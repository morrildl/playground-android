package android

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"playground/log"
)

type SigningKey struct {
	KeyPath     string
	Type        KeyAlgorithm
	Hash        HashAlgorithm
	Key         *rsa.PrivateKey
}

func (sk *SigningKey) Resolve() error {
	if sk.Type != RSA {
		// TODO: support EC
		return errors.New("elliptic curve support not currently implemented")
	}

	switch sk.Hash {
	case SHA256:
	case SHA512:
	default:
		return errors.New("unsupported hash algorithm was specified")
	}

	// parse private key
	someBytes, err := safeLoad(sk.KeyPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(someBytes) // require cert to be in first block in file; ignore rest
	if block == nil {
		return errors.New("key does not decode as PEM")
	}
	switch sk.Type {
	case RSA:
		if block.Type != "RSA PRIVATE KEY" {
			return errors.New("type set as RSA but PEM block is not 'RSA PRIVATE KEY'")
		}
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes) // assumes ASN1 DER representation of a PKCS1 key
		if err != nil {
			return err
		}
		sk.Key = key
		return nil

	case EC:
		// TODO: support EC
		return errors.New("EC not currently supported")

	default:
		return errors.New("unknown signing key type")
	}
}

func (sk *SigningKey) Sign(data []byte, hash crypto.Hash) ([]byte, error) {
	h := hash.New()
	h.Write(data)
	sum := h.Sum(nil)
	return sk.SignPrehashed(sum, hash)
}

func (sk *SigningKey) SignPrehashed(data []byte, hash crypto.Hash) ([]byte, error) {
	res, err := rsa.SignPKCS1v15(rand.Reader, sk.Key, hash, data)
	if err != nil {
		log.Debug("SigningKey.Sign", "error during sign", err)
	}
	return res, err
}


type SigningCert struct {
	SigningKey
	CertPath string
	Certificate *x509.Certificate
	CertHash    string
}

func (sc *SigningCert) Resolve() error {
	err := sc.SigningKey.Resolve()
	if err != nil {
		return err
	}

	// parse Certificate
	someBytes, err := safeLoad(sc.CertPath)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(someBytes) // require cert to be in first block in file; ignore rest
	if block == nil {
		return errors.New("certificate does not decode as PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes) // assumes ASN1 DER
	if err != nil {
		return err
	}
	b := sha256.Sum256(cert.Raw)
	certHash := hex.EncodeToString(b[:]) // cert.Raw == block.Bytes

	switch sc.Type {
	case RSA:
		switch cert.PublicKey.(type) {
		case *rsa.PublicKey:
		default:
			return errors.New("type set as RSA but certificate doesn't contain RSA public key")
		}
		certPubKey := cert.PublicKey.(*rsa.PublicKey)
		if sc.Key.N.Cmp(certPubKey.N) != 0 || sc.Key.E != certPubKey.E {
			log.Debug("SigningCert.Resolve", "certificate public key does not match private key's copy", sc.Key.N, certPubKey.N, sc.Key.E, certPubKey.E)
			return errors.New("certificate public key does not match private key's copy")
		}
		sc.Certificate, sc.CertHash = cert, certHash
		return nil

	case EC:
		// TODO: support EC
		return errors.New("EC not currently supported")

	default:
		return errors.New("unknown signing key type")
	}
}

func safeLoad(path string) ([]byte, error) {
	var err error
	myPath := ""
	if myPath, err = filepath.Abs(filepath.Dir(os.Args[0])); err != nil {
		log.Error("android.safeLoad", "could not locate executable directory", err)
		return nil, err
	}
	if path, err = filepath.Abs(path); err != nil {
		log.Error("android.safeLoad", "file '"+path+"' does not resolve")
		return nil, err
	}
	if !strings.HasPrefix(path, myPath) {
		log.Warn("android.safeLoad", "path '"+path+"' is not under executable pwd '" + myPath + "'")
	}
	if stat, err := os.Stat(path); err != nil || (stat != nil && stat.IsDir()) {
		log.Error("android.safeLoad", "file '"+path+"' does not stat or is a directory", err)
		return nil, err
	}
	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("android.safeLoad", "file '"+path+"' failed to load", err)
		return nil, err
	}
	return fileBytes, nil
}
