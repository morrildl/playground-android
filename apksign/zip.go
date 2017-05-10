package apksign

import (
	"archive/zip"
	"bytes"
	"encoding/binary"
	"errors"
	"strings"

	"playground/android"
	"playground/log"
)

// Zip loads and performs operations on ZIP files required for signing Android APKs. It supports the
// "Android Signing Scheme v2" introduced in Nougat.
//
// See https://source.android.com/security/apksigning/v2.html
//
// As this signing scheme does not rely on any Android-related content in the Zip file itself, it
// can actually be used to sign arbitrary Zip files; they need not be Android APKs.
type Zip struct {
	IsAPK      bool
	IsV1Signed bool
	IsV2Signed bool

	raw        []byte
	size       int64
	eocdOffset uint64
	cdOffset   uint64
	asv2Offset uint64
	rawASv2    []byte
}

// NewZip attempts to parse its input as a Zip file, determining along the way whether the input is
// actually an Android APK, and whether it is signed with either the v1 or v2 signing schemes. A
// non-nil error is returned if the input does not parse as a Zip. The IsAPK, IsV1Signed, and
// IsV2Signed will be populated once this function returns a nil error; until they, their values are
// untrustworthy.
//
// Note that this function does NOT use the Go standard zip library. As the Android v2 signing scheme is
// non-standard and involves injecting a non-Zip data-block into the file before the Zip central
// directory, this code does byte parsing of its input to locate the relevant offsets.
func NewZip(buf []byte) (*Zip, error) {
	z := &Zip{}

	z.size = int64(len(buf))
	z.raw = make([]byte, z.size)
	copy(z.raw, buf)

	// now scan for key offsets: Central Directory (CD) table; End Of Central Directory (EOCD) table;
	// and the Android Signing Scheme v2 block (ASv2). If the file lacks either a CD or EOCD, it
	// cannot be a Zip at all; if it lacks an ASv2 block it just means it isn't signed under that
	// scheme. It could still be v1 signed. Note that we don't do much parsing of either the CD or
	// EOCD tables -- this isn't a general-purpose zip utility.

	if z.size < 22 { // cannot possibly be a ZIP
		return nil, errors.New("input is too small to be a zip")
	}

	var b []byte
	var start int64
	for i := uint32(0); i < 65535; i++ {
		// The "end of central directory" block has 22 bytes of fixed headers, followed by a variable
		// length comment, whose length is stored in the final 16 bits of the EOCD block. This means
		// that we can't just look at EOF - 22 for the EOCD magic identifier, we have to read backward
		// to accommodate a possible zip file comment.

		start = z.size - 22 - int64(i)
		b = z.raw[start : start+22]

		// check for the EOCD magic string, 0x06054b50. note that zip files are little endian
		if binary.LittleEndian.Uint32(b[:4]) == 0x06054b50 {
			// we now have a candidate, but we don't know for sure that this is the EOCD: the comment
			// could technically contain the EOCD magic. so verify that the number of bytes we've read
			// backward matches what the EOCD should say is the comment length. This also covers this
			// verification requirement:
			// Spec: "verify that ... ZIP End of Central Directory is not followed by more data"
			commentLen := binary.LittleEndian.Uint16(b[20:22])
			if uint16(i) != commentLen {
				continue // can't be the EOCD; keep going
			}

			// comment length checks out, but that could be a coincidence, so also check CD offset, which we need anyway
			candidateEOCD := uint64(z.size) - 22 - uint64(i)
			eocdCD := binary.LittleEndian.Uint32(b[16:20])
			eocdCDLen := binary.LittleEndian.Uint32(b[12:16])
			b2 := z.raw[int64(eocdCD):]
			if binary.LittleEndian.Uint32(b2) != 0x02014b50 {
				continue // CD pointed to by "EOCD" is not a valid CD, but there may still be comment bytes to unwind
			}

			// Spec: "verify that ... ZIP Central Directory is immediately followed by ZIP End of Central Directory record"
			if uint64(eocdCD)+uint64(eocdCDLen) != candidateEOCD {
				return nil, errors.New("CD not adjacent to EOCD")
			}

			// now we have an EOCD that checks out and appears to point to a CD, so we are pretty sure this is a zip file
			z.cdOffset = uint64(eocdCD)
			z.eocdOffset = candidateEOCD

			// scan the file using zip library, looking for specific file names
			r, err := zip.NewReader(bytes.NewReader(z.raw), z.size)
			if err != nil {
				return nil, err
			}
			hasClassesDex := false
			hasAndroidManifestXML := false
			hasResourcesARSC := false
			hasManifest := false
			hasSF := false
			hasRSA := false
			for _, f := range r.File {
				switch f.FileHeader.Name {
				case "classes.dex":
					hasClassesDex = true
				case "AndroidManifest.xml":
					hasAndroidManifestXML = true
				case "resources.arsc":
					hasResourcesARSC = true
				case "META-INF/MANIFEST.MF":
					hasManifest = true
				}
				hasSF = hasSF || strings.HasSuffix(f.FileHeader.Name, ".SF")
				hasRSA = hasRSA || strings.HasSuffix(f.FileHeader.Name, ".RSA") || strings.HasSuffix(f.FileHeader.Name, ".DSA")
			}
			z.IsAPK = hasClassesDex && hasAndroidManifestXML && hasResourcesARSC
			z.IsV1Signed = hasManifest && (hasSF || hasRSA) // doesn't mean it validates...

			// now see if there is an Android signing v2 block
			start = int64(z.cdOffset) - 16
			magic := z.raw[start:z.cdOffset]
			if string(magic) != "APK Sig Block 42" {
				return z, nil
			}

			// it has the ASv2 magic in the expected spot, so check size fields: size field is uint64 & is
			// repeated at start & end of block, but pre-size copy does not include itself
			start = int64(z.cdOffset - 16 - 8)
			b64 := z.raw[start : start+8]
			postSize := binary.LittleEndian.Uint64(b64)
			start = int64(z.cdOffset - postSize - 8)
			b64 = z.raw[start : start+8]
			preSize := binary.LittleEndian.Uint64(b64)
			if preSize == postSize { // Spec: "Two size fields of APK Signing Block contain the same value"
				z.asv2Offset = z.cdOffset - postSize - 8
				z.rawASv2 = make([]byte, preSize-24)
				start = int64(z.asv2Offset + 8)
				copy(z.rawASv2, z.raw[start:])
			}

			z.IsV2Signed = z.asv2Offset > 0

			log.Debug("Zip.New", "ASv2, CD, EOCD", z.asv2Offset, z.cdOffset, z.eocdOffset)

			return z, nil
		}
	}

	// if we fall past the end of the loop, means we exhausted all possibility of it being a zip
	return nil, errors.New("input is not a zip")
}

// VerifyV1 returns a non-nil error if the represented Zip file has a v1 (i.e. Java signed JAR)
// signature that does not verify. Note that calling this when z.IsV1Signed == false is always an
// error. VerifyV1 returns nil if the signature validates.
func (z *Zip) VerifyV1() error {
	var r *V1Reader
	var err error

	if !z.IsV1Signed {
		return errors.New("v1 verification attempted on non-v1-signed file")
	}

	if r, err = ParseZip(z.raw, nil); err != nil {
		return err
	}

	return r.Verify()
}

// VerifyV2 returns a non-nil error if the represented Zip file has a v2 (i.e. Android-specific
// whole-file) signature that does not verify. Note that calling this when z.IsV2Signed == false is
// always an error. VerifyV2 returns nil if the signature validates.
func (z *Zip) VerifyV2() error {
	var v2 *V2Block
	var err error

	if !z.IsV2Signed {
		return errors.New("v2 verification attempted on non-v2-signed file")
	}

	v2, err = ParseV2Block(z.rawASv2)
	if err != nil {
		return err
	}

	return v2.Verify(z)
}

// Verify returns a non-nil error if the represented Zip file has a signature (under either v1 or v2
// rubric) that does not validate. Note that calling this when both z.IsV1Signed == false and
// z.IsV2Signed == false is always an error. Verify returns nil if the signature(s) validate(s).
func (z *Zip) Verify() error {
	if z.IsV2Signed {
		return z.VerifyV2()
	}

	if !z.IsV1Signed {
		return errors.New("APK not recognized as signed")
	}

	return z.VerifyV1()
}

// SignV1 signs the zip with the provided keys, using the Java signed-JAR signing rubric, only. This
// was used by Android up to the Nougat release, when it was supplemented by a more secure
// whole-file "v2" scheme.
func (z *Zip) SignV1(keys []*android.SigningCert) (*Zip, error) {
	for _, sk := range keys {
		if err := sk.Resolve(); err != nil {
			return nil, err
		}
	}

	var err error
	var b []byte
	w := NewV1Writer()

	if _, err = ParseZip(z.raw, w); err != nil {
		return nil, err
	}

	if err = w.Sign(keys, false); err != nil {
		return nil, err
	}
	if b, err = w.Marshal(); err != nil {
		return nil, err
	}

	return NewZip(b)
}

// SignV2 signs the zip with the provided keys, using the Android-specific whole-file "v2" signing
// rubric, only.
func (z *Zip) SignV2(keys []*android.SigningCert) (*Zip, error) {
	for _, sk := range keys {
		if err := sk.Resolve(); err != nil {
			return nil, err
		}
	}

	var b []byte
	var err error
	v2 := V2Block{}
	if b, err = v2.Sign(z, keys); err != nil {
		return nil, err
	}

	return NewZip(b)
}

// Sign signs the zip with the provided keys, using BOTH the v1 (JAR signer) and v2
// (Android-specific whole-file) signing rubrics. Note that `Sign()` IS NOT equivalent to
// `SignV1(); SignV2()`. When signed with both schemes, the JAR `.SF` files have an additional
// header, per spec.
func (z *Zip) Sign(keys []*android.SigningCert) (*Zip, error) {
	for _, sk := range keys {
		if err := sk.Resolve(); err != nil {
			return nil, err
		}
	}

	var w *V1Writer
	var v2 *V2Block
	var newZ *Zip
	var b []byte
	var err error

	w = NewV1Writer()
	if _, err = ParseZip(z.raw, w); err != nil {
		return nil, err
	}

	if err = w.Sign(keys, true); err != nil {
		return nil, err
	}
	if b, err = w.Marshal(); err != nil {
		return nil, err
	}
	if newZ, err = NewZip(b); err != nil {
		return nil, err
	}

	v2 = &V2Block{}
	if b, err = v2.Sign(newZ, keys); err != nil {
		return nil, err
	}

	return NewZip(b)
}

// InjectBeforeCD modifies the Zip file bytes represented by this instance by injecting the input
// bytes into the file immediately before the Zip Central Directory block. The End of Central
// Directory block's record of the Central Directory offset is updated accordingly, so that the new
// Zip file is valid. Note that this is the behavior specified by the Android APK signing scheme v2,
// which is what this function is intended to be used for.
//
// The returned slice is backed by a new array. The bytes represented by `z` are not modified, nor
// is any other state of `z`. If the resulting Zip bytes need to be interacted with, they must be
// parsed into a new Zip instance.
func (z *Zip) InjectBeforeCD(data []byte) []byte {
	// compute how much space we'll need for the new bytes
	newSize := int64(len(z.raw))
	endOfFilesSection := z.cdOffset
	if z.asv2Offset > 0 {
		endOfFilesSection = z.asv2Offset
		newSize -= int64(z.cdOffset - z.asv2Offset)
	}
	newSize += int64(len(data))

	newEocd := make([]byte, z.size-int64(z.eocdOffset))
	copy(newEocd, z.raw[z.eocdOffset:])
	binary.LittleEndian.PutUint32(newEocd[16:], uint32(endOfFilesSection+uint64(len(data))))

	// allocate & copy in the data
	ret := make([]byte, newSize)
	copy(ret[:endOfFilesSection], z.raw[:endOfFilesSection])
	copy(ret[endOfFilesSection:endOfFilesSection+uint64(len(data))], data)
	copy(ret[endOfFilesSection+uint64(len(data)):], z.raw[z.cdOffset:z.eocdOffset])
	copy(ret[endOfFilesSection+uint64(len(data))+(z.eocdOffset-z.cdOffset):], newEocd)

	return ret
}

// Bytes returns a slice over a new copy of the bytes underlying `z`.
func (z *Zip) Bytes() []byte {
	ret := make([]byte, len(z.raw))
	copy(ret, z.raw)
	return ret
}
