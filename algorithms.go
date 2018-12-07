// Copyright © 2018 Playground Global, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package android is a parent package of Android-related code-signing implementations for APKs,
// system images, and OTA images.
package android

import (
	"crypto"
)

// KeyAlgorithm is used to map strings used in e.g. config files to implementations.
type KeyAlgorithm string

const (
	RSA    KeyAlgorithm = "RSA"
	RSAPSS              = "RSAPSS"
	EC                  = "EC"
	DSA                 = "DSA"
)

// HashAlgorithm is used to map strings used in e.g. config files to implementations. This is
// partially redundant with crypto.Hash, but its purpose is to be able to basically map a string
// from a config file into a crypto.Hash elsewhere in code
type HashAlgorithm string

const (
	SHA256 HashAlgorithm = "SHA256"
	SHA512               = "SHA512"
)

// AsHash turns our string-based enum type into a Go crypto.Hash value.
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

// AlgorithmID labels the Android APK signing scheme v2 magic constants. Note that these constants
// serve the same function as the usual ASN.1 object ID registered constants, but in an integer
// format.
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

// IDtoString returns a string representation of an Android APK signing scheme v2 magic constant.
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

// Returns the appropriate Android APK v2 signing scheme magic constant for the given cryptosystem.
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
