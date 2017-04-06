package apksign

import (
	"archive/zip"
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"regexp"
	"strings"

	"github.com/fullsailor/pkcs7"

	"playground/log"
)

type sigPair struct {
	sf    *signedFile
	pkcs7 *pkcs7.PKCS7
}

type V1Reader struct {
	observed *manifest
	provided *manifest
	sigs     map[string]*sigPair
	writer   *V1Writer
}

var (
	spaceRE      = regexp.MustCompile(`\s`)
	signedFileRE = regexp.MustCompile(`^META-INF/([a-zA-Z0-9_]+)\.SF$`)
	rsaRE        = regexp.MustCompile(`^META-INF/([a-zA-Z0-9_]+)\.RSA$`)
	dsaRE        = regexp.MustCompile(`^META-INF/([a-zA-Z0-9_]+)\.DSA$`)
	sigRE        = regexp.MustCompile(`^META-INF/SIG-([a-zA-Z0-9_]+)$`)
)

func ParseZip(buf []byte, writer *V1Writer) (*V1Reader, error) {
	var z *zip.Reader
	var err error

	// start a reader on the zip input to feed us individual files
	if z, err = zip.NewReader(bytes.NewReader(buf), int64(len(buf))); err != nil {
		log.Debug("ParseZip", "reader")
		return nil, err
	}

	v1 := &V1Reader{}
	v1.observed = newManifest() // this will track digests of the actual physical bits in the file
	v1.writer = writer
	v1.sigs = make(map[string]*sigPair)

	for _, f := range z.File {
		// send every file we see to the writer on behalf of our caller, if it wants us to
		if writer != nil {
			writer.Add(f)
		}

		// when we see the manifest, parse & store it for future comparison during verification
		if f.FileHeader.Name == "META-INF/MANIFEST.MF" {
			if buf, err = readZipFile(f); err != nil {
				return nil, err
			}
			if v1.provided, err = parseManifest(buf); err != nil {
				return nil, err
			}
		}

		// when we see a <signer>.SF, parse & record it for future verification
		hits := signedFileRE.FindStringSubmatch(f.FileHeader.Name)
		if hits != nil {
			signer := hits[1]
			pair, ok := v1.sigs[signer]
			if !ok {
				pair = &sigPair{}
				v1.sigs[signer] = pair
			}

			if pair.sf != nil {
				return nil, errors.New("duplicate .SF for '" + signer + "'")
			}

			if buf, err = readZipFile(f); err != nil {
				return nil, err
			}
			if pair.sf, err = parseSignedFile(buf); err != nil {
				return nil, err
			}
		}

		// when we see a signature file (PKCS7 struct per spec), parse & record it for future verification
		hits = rsaRE.FindStringSubmatch(f.FileHeader.Name)
		if hits == nil {
			hits = dsaRE.FindStringSubmatch(f.FileHeader.Name)
		}
		if hits == nil {
			hits = sigRE.FindStringSubmatch(f.FileHeader.Name)
		}
		if hits != nil {
			signer := hits[1]
			pair, ok := v1.sigs[signer]
			if !ok {
				pair = &sigPair{}
				v1.sigs[signer] = pair
			}

			if pair.pkcs7 != nil {
				// Technically signers are allowed to have a .RSA & a .DSA for same .SF, but the spec is
				// kind of flaky on this (lots of "shoulds", no clear guidance) so we treat it as an error.
				// In practice this is very uncommon.
				return nil, errors.New("duplicate PKCS7 for '" + signer + "'")
			}

			if buf, err = readZipFile(f); err != nil {
				return nil, err
			}
			if pair.pkcs7, err = pkcs7.Parse(buf); err != nil {
				return nil, err
			}
		}

		// add the file to the manifest; it will filter META-INF files (which must not appear in the
		// manifest list) on its own
		if err := v1.observed.add(f); err != nil {
			return nil, err
		}
	}

	return v1, nil
}

func (v1 *V1Reader) Verify() error {
	if v1.provided == nil || v1.observed == nil {
		return errors.New("nil reported or observed")
	}

	// manifest in the file must match the hashes of the files we actually saw;
	// this will also check that there are no extra or missing files vs. manifest
	if !v1.provided.equals(v1.observed) {
		return errors.New("observed & provided manifests do not match")
	}

	// verify each signature from META-INF/
	for signer, sig := range v1.sigs {
		if sig.sf.version >= APKSignV2 {
			return errors.New("signer specified v2 rubric; v2-aware verifiers must abort v1 verification")
		}

		// .SF file must have hashes that match manifest, and must not have extra or missing files;
		// this will also verify manifest file hash, although that is optional per spec
		if !sig.sf.verify(v1.observed) {
			return errors.New(".SF file for '" + signer + "' does not comport with manifest")
		}

		// verify the actual signature over the original .SF file bytes (not a hash, which seems kind of wrong but...)
		sig.pkcs7.Content = sig.sf.raw // set bytes to be verified
		if err := sig.pkcs7.Verify(); err != nil {
			return err
		}
	}

	// the manifest matches the actual files, and all signatures verify, so we're done
	return nil
}

type V1Writer struct {
	manifest *manifest
	writer   *zip.Writer
	buf      bytes.Buffer
}

func NewV1Writer() *V1Writer {
	v1 := &V1Writer{}
	v1.manifest = newManifest()
	v1.writer = zip.NewWriter(&v1.buf)
	return v1
}

func (v1 *V1Writer) Add(zf *zip.File) error {
	var fr io.ReadCloser
	var contents []byte
	var err error
	var wr io.Writer

	if strings.HasPrefix(zf.FileHeader.Name, "META-INF/") {
		return nil
	}

	if fr, err = zf.Open(); err != nil {
		return err
	}
	defer fr.Close()

	if contents, err = ioutil.ReadAll(fr); err != nil {
		return err
	}

	buf := bytes.NewBuffer(contents)
	if wr, err = v1.writer.Create(zf.FileHeader.Name); err != nil {
		return err
	}
	if _, err = io.Copy(wr, buf); err != nil {
		return err
	}

	if err = v1.manifest.add(zf); err != nil {
		return err
	}

	return nil
}

func (v1 *V1Writer) Sign(keys []*SigningKey, signifyV2 bool) error {
	if v1 == nil || v1.manifest == nil || v1.writer == nil {
		return errors.New("V1Writer.Sign called uninitialized")
	}

	var err error
	var signer string
	var signed []byte
	var out io.Writer
	var sd *pkcs7.SignedData
	var sf *signedFile

	if out, err = v1.writer.Create("META-INF/MANIFEST.MF"); err != nil {
		return err
	}
	v1.manifest.marshal()
	if _, err = io.Copy(out, bytes.NewBuffer(v1.manifest.raw)); err != nil {
		return err
	}

	for i, key := range keys {
		sf = createSignedFileFrom(v1.manifest, !signifyV2)
		sf.setManifest(crypto.SHA256, v1.manifest)
		sf.marshal()

		if sd, err = pkcs7.NewSignedData(sf.raw); err != nil {
			return err
		}

		if err = sd.AddSigner(key.Certificate, key.Key, pkcs7.SignerInfoConfig{}); err != nil {
			return err
		}

		sd.Detach()

		if signed, err = sd.Finish(); err != nil {
			return err
		}

		if _, err = pkcs7.Parse(signed); err != nil {
			log.Debug("V1Writer.Sign", "failed to roundtrip parse generated PKCS7")
			return err
		}

		signer = fmt.Sprintf("CERT%02d", i)

		if out, err = v1.writer.Create(fmt.Sprintf("META-INF/%s.RSA", signer)); err != nil {
			// TODO: handle DSA
			return err
		}
		if _, err = io.Copy(out, bytes.NewBuffer(signed)); err != nil {
			return err
		}

		if out, err = v1.writer.Create(fmt.Sprintf("META-INF/%s.SF", signer)); err != nil {
			return err
		}
		if _, err = io.Copy(out, bytes.NewBuffer(sf.raw)); err != nil {
			return err
		}
	}

	return nil
}

func (v1 *V1Writer) Marshal() ([]byte, error) {
	if v1 == nil || v1.manifest == nil || v1.writer == nil {
		return nil, errors.New("V1Writer.Marshal called uninitialized")
	}

	if err := v1.writer.Close(); err != nil {
		return nil, err
	}

	return v1.buf.Bytes(), nil
}

func readZipFile(zf *zip.File) ([]byte, error) {
	var fr io.ReadCloser
	var err error
	if fr, err = zf.Open(); err != nil {
		return nil, err
	}
	defer fr.Close()

	sfBytes, err := ioutil.ReadAll(fr)
	if err != nil {
		return nil, err
	}

	return sfBytes, nil
}
