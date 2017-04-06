package apksign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"hash"
	"io/ioutil"
	"os"
	"path/filepath"

	"playground/log"
)

type SigningKey struct {
	CertPath    string
	KeyPath     string
	Type        KeyAlgorithm
	Hash        HashAlgorithm
	Certificate *x509.Certificate
	certHash    string
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

	// parse Certificate
	someBytes, err := safeLoad(sk.CertPath)
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

	// parse private key
	someBytes, err = safeLoad(sk.KeyPath)
	if err != nil {
		return err
	}
	block, _ = pem.Decode(someBytes) // require cert to be in first block in file; ignore rest
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
		switch cert.PublicKey.(type) {
		case *rsa.PublicKey:
		default:
			return errors.New("type set as RSA but certificate doesn't contain RSA public key")
		}
		certPubKey := cert.PublicKey.(*rsa.PublicKey)
		if key.N.Cmp(certPubKey.N) != 0 || key.E != certPubKey.E {
			log.Debug("SigningKey.Resolve", "certificate public key does not match private key's copy", key.N, certPubKey.N, key.E, certPubKey.E)
			return errors.New("certificate public key does not match private key's copy")
		}
		sk.Certificate, sk.Key, sk.certHash = cert, key, certHash
		return nil

	case EC:
		// TODO: support EC
		return errors.New("EC not currently supported")

	default:
		return errors.New("unknown signing key type")
	}
}

func (sk *SigningKey) Sign(data []byte, hash crypto.Hash) ([]byte, error) {
	rng := rand.Reader
	h := hash.New()
	h.Write(data)
	sum := h.Sum(nil)
	res, err := rsa.SignPKCS1v15(rng, sk.Key, hash, sum)
	if err != nil {
		log.Debug("SigningKey.Sign", "error during sign", err)
	}
	return res, err
}

func (sk *SigningKey) GetHasher() hash.Hash {
	switch sk.Hash {
	case SHA256:
		return sha256.New()
	case SHA512:
		return sha512.New()
	default:
		return nil
	}
}

func safeLoad(path string) ([]byte, error) {
	var err error
	origPath := path
	if path, err = filepath.Abs(path); err != nil {
		log.Error("apksign.safeLoad", "file '"+path+"' does not resolve")
		return nil, err
	}
	if origPath != path {
		log.Warn("apksign.safeLoad", "path '"+path+"' is a symlink")
	}
	if stat, err := os.Stat(path); err != nil || (stat != nil && stat.IsDir()) {
		log.Error("apksign.safeLoad", "file '"+path+"' does not stat or is a directory", err)
		return nil, err
	}
	fileBytes, err := ioutil.ReadFile(path)
	if err != nil {
		log.Error("apksign.safeLoad", "file '"+path+"' failed to load", err)
		return nil, err
	}
	return fileBytes, nil
}
