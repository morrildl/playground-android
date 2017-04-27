package apksign

import (
	"archive/zip"
	"bytes"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	"playground/log"
)

type manifest struct {
	headers map[string]string
	digests map[string]map[crypto.Hash][]byte
	raw     []byte
}

type signedFile struct {
	headers        map[string]string
	digests        map[string]map[crypto.Hash][]byte
	version        SigningVersion
	manifestDigest []byte
	manifestHash   crypto.Hash
	raw            []byte
}

func newManifest() *manifest {
	mf := &manifest{}
	mf.headers = make(map[string]string)
	mf.digests = make(map[string]map[crypto.Hash][]byte)
	return mf
}

func parseManifest(buf []byte) (*manifest, error) {
	mf := &manifest{}
	mf.digests = make(map[string]map[crypto.Hash][]byte)
	mf.raw = make([]byte, len(buf))
	copy(mf.raw, buf)

	lines := strings.Split(string(buf), "\n")
	var files []map[string]string
	var err error
	mf.headers, files, err = parseManifestLines(lines)
	if err != nil {
		return nil, err
	}

	if mf.headers["Manifest-Version"] != "1.0" {
		return nil, errors.New("unknown manifest version")
	}

	for _, cur := range files {
		name, digests := extractDigests(cur)
		if name == "" {
			continue
		}
		mf.digests[name] = digests
	}

	return mf, nil
}

func (mf *manifest) add(zf *zip.File) error {
	if strings.HasPrefix(zf.Name, "META-INF/") {
		return nil
	}

	var err error
	var r io.ReadCloser
	var contents []byte

	name := zf.FileHeader.Name
	if r, err = zf.Open(); err != nil {
		return err
	}
	defer r.Close()
	if contents, err = ioutil.ReadAll(r); err != nil {
		return err
	}

	if _, ok := mf.digests[name]; ok {
		// this is technically okay since the last duplicate entry in a zip will be the only one that
		// appears in the central directory, but for us this indicates either a programming error or
		// input coming from a broken zip via V1Reader
		return errors.New("duplicate entry for '" + name + "'")
	}
	mf.digests[name] = make(map[crypto.Hash][]byte)
	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA256} {
		potato := hash.New()
		potato.Write(contents)
		mf.digests[name][hash] = potato.Sum(nil)
	}

	return nil
}

func (mf *manifest) setHeader(key, value string) {
	mf.headers[key] = value
}

func (mf *manifest) marshal() []byte {
	var buf bytes.Buffer

	buf.Write(marshalHeaders("Playground Warden", "Playground Warden", mf.headers, false))

	for name, hashes := range mf.digests {
		h, ok := hashes[crypto.SHA256]
		if !ok {
			log.Debug("apksign.manifest.marshal", "missing SHA256 hash for '"+name+"'")
			continue
		}
		attrs := map[string]string{"SHA-256-Digest": base64.StdEncoding.EncodeToString(h)}
		buf.Write(marshalSection(name, attrs))
	}

	mf.raw = buf.Bytes()
	return mf.raw
}

func (left *manifest) equals(right *manifest) bool {
	if left == nil || right == nil {
		// this feels a bit awkward when left & right are both nil, but NaN != NaN too, so...
		log.Debug("manifest.equals", "nil")
		return false
	}

	if len(left.digests) != len(right.digests) {
		log.Debug("manifest.equals", "wrong len", len(left.digests), len(right.digests))
		return false
	}

	for k, lv := range left.digests {
		rv, ok := right.digests[k]
		if !ok {
			log.Debug("manifest.equals", "right missing key '"+k+"'")
			return false
		}
		for h, lb := range lv {
			rb, ok := rv[h]
			if !ok {
				log.Debug("manifest.equals", "right missing subkey", h, lv, rv)
				return false
			}
			if !bytes.Equal(lb, rb) {
				log.Debug("manifest.equals", "hashes differ", h)
				return false
			}
		}
	}

	/* headers are not relevant to the equality of two manifests, in the same way that entries in
	 * META-INF/ are not included in MANIFEST.MF

	if len(left.headers) != len(right.headers) {
		return false
	}

	for k, lv := range left.headers {
		rv, ok := right.headers[k]
		if !ok {
			return false
		}
		if lv != rv {
			return false
		}
	}
	*/

	return true
}

func parseSignedFile(buf []byte) (*signedFile, error) {
	sf := &signedFile{}
	sf.digests = make(map[string]map[crypto.Hash][]byte)
	sf.raw = make([]byte, len(buf))
	copy(sf.raw, buf)

	lines := strings.Split(string(buf), "\n")
	var files []map[string]string
	var err error
	sf.headers, files, err = parseManifestLines(lines)
	if err != nil {
		return nil, err
	}

	if sf.headers["Signature-Version"] != "1.0" {
		return nil, errors.New("unknown signature version")
	}
	if ver, ok := sf.headers["X-Android-APK-Signed"]; ok {
		chunks := strings.Split(ver, ",")
		maxVer := APKSignUnknown
		for _, c := range chunks {
			c = strings.TrimSpace(c)
			if c == "2" {
				// unrecognized or missing versions will default to 1, below
				maxVer = APKSignV2
			}
		}
		if maxVer == APKSignUnknown {
			maxVer = APKSignV1
		}
		sf.version = maxVer
	} else {
		sf.version = APKSignV1
	}
	if b64, ok := sf.headers["SHA-256-Digest-Manifest"]; ok {
		sf.manifestHash = crypto.SHA256
		sf.manifestDigest, err = base64.StdEncoding.DecodeString(b64)
	} else if b64, ok := sf.headers["SHA1-Digest-Manifest"]; ok {
		sf.manifestHash = crypto.SHA1
		sf.manifestDigest, err = base64.StdEncoding.DecodeString(b64)
	} else {
		return nil, errors.New("missing or unsupported manifest digest header")
	}

	for _, cur := range files {
		name, digests := extractDigests(cur)
		if name == "" {
			continue
		}
		sf.digests[name] = digests
	}

	return sf, nil
}

func createSignedFileFrom(mf *manifest, v1Only bool) *signedFile {
	version := APKSignV2
	if v1Only {
		version = APKSignV1
	}
	sf := &signedFile{headers: make(map[string]string), digests: make(map[string]map[crypto.Hash][]byte), version: version}

	for k, mfd := range mf.digests {
		sf.digests[k] = make(map[crypto.Hash][]byte)
		for h, b := range mfd {
			sf.digests[k][h] = make([]byte, len(b))
			copy(sf.digests[k][h], b)
		}
	}

	for k, v := range mf.headers {
		sf.headers[k] = v
	}

	return sf
}

func (sf *signedFile) marshal() []byte {
	var buf bytes.Buffer

	headers := make(map[string]string)
	for k, v := range sf.headers {
		headers[k] = v
	}
	if sf.version > APKSignV1 {
		headers["X-Android-APK-Signed"] = sf.version.String()
	}
	headers["SHA-256-Digest-Manifest"] = base64.StdEncoding.EncodeToString(sf.manifestDigest)
	buf.Write(marshalHeaders("Playground Warden", "Playground Warden", headers, true))

	for name, hashes := range sf.digests {
		h, ok := hashes[crypto.SHA256]
		if !ok {
			log.Debug("apksign.signedFile.marshal", "missing SHA256 hash for '"+name+"'")
			continue
		}
		attrs := map[string]string{"SHA-256-Digest": base64.StdEncoding.EncodeToString(h)}
		buf.Write(marshalSection(name, attrs))
	}

	sf.raw = buf.Bytes()
	return sf.raw
}

func (sf *signedFile) setManifest(hash crypto.Hash, mf *manifest) {
	potato := hash.New()
	potato.Write(mf.raw)
	sf.manifestDigest = potato.Sum(nil)
}

func (sf *signedFile) verify(mf *manifest) bool {
	if sf == nil || mf == nil {
		// this feels a bit awkward when left & right are both nil, but NaN != NaN too, so...
		log.Debug("signedFile.verify", "nil input")
		return false
	}

	if len(mf.digests) != len(sf.digests) {
		log.Debug("signedFile.verify", "differing lengths")
		return false
	}

	for k, lv := range sf.digests {
		rv, ok := mf.digests[k]
		if !ok {
			log.Debug("signedFile.verify", "manifest missing key '"+k+"'")
			return false
		}

		/* the manifest can serve multiple signers via .SF files. Since each could use a different hash
		 * algorith, it's not necessarily an error for manifest to have extra hash entries, so we can't
		 * just compare lengths.

		if len(rv) != len(lv) {
			log.Debug("signedFile.verify", "hash lengths differ'" + k + "'", len(lv), len(rv))
			return false
		}
		*/

		for h, lb := range lv {
			rb, ok := rv[h]
			if !ok {
				return false
			}
			if !bytes.Equal(lb, rb) {
				return false
			}
		}
	}

	return true
}

func marshalHeader(k, v string) []byte {
	var buf bytes.Buffer
	k = strings.TrimSpace(k)
	k = spaceRE.ReplaceAllString(k, "-")
	v = strings.TrimSpace(v)
	line := fmt.Sprintf("%s: %s", k, v)
	if len(line) > 72 {
		line = line[:72] // truncate per spec
	}
	buf.WriteString(line)
	buf.WriteString("\n")
	return buf.Bytes()
}

func marshalHeaders(createdBy, builtBy string, headers map[string]string, isSignedFile bool) []byte {
	if createdBy == "" {
		createdBy = "Playground Warden"
	}
	if builtBy == "" {
		builtBy = "Playground Warden"
	}

	var buf bytes.Buffer

	if isSignedFile {
		buf.Write(marshalHeader("Signature-Version", "1.0"))
	} else {
		buf.Write(marshalHeader("Manifest-Version", "1.0"))
	}
	buf.Write(marshalHeader("Created-By", createdBy))
	buf.Write(marshalHeader("Built-By", builtBy))
	for k, v := range headers {
		buf.Write(marshalHeader(k, v))
	}
	buf.WriteString("\n")

	return buf.Bytes()
}

func marshalSection(name string, attrs map[string]string) []byte {
	var buf bytes.Buffer

	if name == "" {
		return buf.Bytes()
	}

	lines := manifestSplitLine("Name: " + name)
	for _, line := range lines {
		buf.WriteString(line)
		buf.WriteString("\n")
	}

	for k, v := range attrs {
		lines = manifestSplitLine(fmt.Sprintf("%s: %s", k, v))
		for _, line := range lines {
			buf.WriteString(line)
			buf.WriteString("\n")
		}
	}

	buf.WriteString("\n")

	return buf.Bytes()
}

func manifestSplitLine(s string) []string {
	lines := make([]string, 0)
	if len(s) > 72 {
		lines = append(lines, s[:72])
		s = s[72:]
		for len(s) > 0 {
			num := len(s)
			if num > 71 {
				num = 71
			}
			lines = append(lines, " "+s[:num])
			s = s[num:]
		}
	} else {
		lines = append(lines, s)
	}
	return lines
}

func parseSection(lines []string) (map[string]string, error) {
	var lastk string
	cur := make(map[string]string)

	for _, line := range lines {
		if line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if strings.HasPrefix(line, " ") {
			if lastk == "" {
				return nil, errors.New("malformed manifest: spurious continuation line")
			}
			cur[lastk] = cur[lastk] + line[1:]
			continue
		}

		chunks := strings.SplitN(line, ": ", 2)
		if len(chunks) != 2 {
			return nil, errors.New("malformed attribute")
		}
		k := strings.TrimSpace(chunks[0])
		v := chunks[1]
		if _, ok := cur[k]; ok {
			return nil, errors.New("duplicate value for attribute '" + k + "'")
		}
		lastk = k
		cur[k] = v
	}

	return cur, nil
}

func parseManifestLines(lines []string) (headers map[string]string, sections []map[string]string, err error) {
	var curLines []string
	var s map[string]string
	var i int
	var line string
	for i, line = range lines {
		if line != "\r" && line != "" {
			curLines = append(curLines, line)
		} else {
			break
		}
	}

	if lines[len(lines)-1] == "" {
		// lines is generated via strings.Split(), which will insert "" after the split target if it is
		// the last character in the input. Since these files typically end with a "\n", we will
		// basically always get an empty string as the final entry in the list
		lines = lines[:len(lines)-1]
	}

	if headers, err = parseSection(curLines); err != nil {
		return nil, nil, err
	}
	lines = lines[i+1:]

	sections = make([]map[string]string, 0)
	curLines = make([]string, 0)
	for _, line := range lines {
		if line == "\r" || line == "" {
			if s, err = parseSection(curLines); err != nil {
				return nil, nil, err
			}
			sections = append(sections, s)
			curLines = make([]string, 0)
		} else {
			curLines = append(curLines, line)
		}
	}
	if len(curLines) > 0 { // in case last line isn't blank line
		if s, err = parseSection(curLines); err != nil {
			return nil, nil, err
		}
		if len(s) > 0 {
			sections = append(sections, s)
		}
	}

	return
}

func extractDigests(attrs map[string]string) (string, map[crypto.Hash][]byte) {
	var name string
	var ok bool
	if name, ok = attrs["Name"]; !ok {
		log.Debug("apksign.extractDigests", "digest attr set missing Name", attrs)
		return "", nil
	}

	out := make(map[crypto.Hash][]byte)
	for k, v := range attrs {
		if k == "Name" {
			continue
		}

		var potato crypto.Hash
		switch k {
		case "SHA-256-Digest":
			potato = crypto.SHA256
		case "SHA1-Digest":
			potato = crypto.SHA1
		}
		if potato < crypto.SHA1 {
			log.Debug("apksign.extractDigests", "unsupported hash algorithm in file")
			return "", nil
		} else {
			if b, err := base64.StdEncoding.DecodeString(v); err == nil {
				out[potato] = b[:]
			} else {
				log.Debug("apksign.extractDigests", "hash value failed to base64-decode")
			}
		}
	}

	return name, out
}
