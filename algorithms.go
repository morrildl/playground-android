package android

import (
	"crypto"
)

type KeyAlgorithm string

const (
	RSA    KeyAlgorithm = "RSA"
	RSAPSS              = "RSAPSS"
	EC                  = "EC"
	DSA                 = "DSA"
)

// this is partially redundant with crypto.Hash, but its purpose is to be able to basically map a string
// from a config file into a crypto.Hash elsewhere in code
type HashAlgorithm string

const (
	SHA256 HashAlgorithm = "SHA256"
	SHA512               = "SHA512"
)

func (h HashAlgorithm) AsHash() crypto.Hash {
	switch h {
	case SHA256:
		return crypto.SHA256
	case SHA512:
		return crypto.SHA512
	default:
		// panic is a smidge aggressive here, but we can't return nil and caller shouldn't have called
		// us on a string not listed above. in normal operation this is pretty bad.
		panic("unknown hash algorithm requested")
	}
}

type AlgorithmID uint32

const (
	RSAPSS_SHA256   AlgorithmID = 0x0101
	RSAPSS_SHA512               = 0x0102
	RSA_PKCS_SHA256             = 0x0103
	RSA_PKCS_SHA512             = 0x0104
	ECDSA_SHA256                = 0x0201
	ECDSA_SHA512                = 0x0202
	DSA_SHA256                  = 0x0301
)

func IDtoString(id uint32) string {
	switch id {
	case 0x0101:
		return "RSASSA-PSS with SHA2-256 digest, SHA2-256 MGF1, 32 bytes of salt, trailer: 0xbc"
	case 0x0102:
		return "RSASSA-PSS with SHA2-512 digest, SHA2-512 MGF1, 64 bytes of salt, trailer: 0xbc"
	case 0x0103:
		return "RSASSA-PKCS1-v1_5 with SHA2-256 digest."
	case 0x0104:
		return "RSASSA-PKCS1-v1_5 with SHA2-512 digest."
	case 0x0201:
		return "ECDSA with SHA2-256 digest"
	case 0x0202:
		return "ECDSA with SHA2-512 digest"
	case 0x0301:
		return "DSA with SHA2-256 digest"
	default:
		return "unknown algorithm"
	}
}

func IDFor(key KeyAlgorithm, hash HashAlgorithm) uint32 {
	var algID uint32
	switch key {
	case RSA:
		algID = 0x0100
	case RSAPSS:
		algID = 0x0102
	case EC:
		algID = 0x0200
	case DSA:
		algID = 0x0300
	default:
		return 0x00
	}

	switch hash {
	case SHA256:
		algID += 1
	case SHA512:
		algID += 2
	}

	if algID > DSA_SHA256 {
		return 0x00
	}

	return algID
}
