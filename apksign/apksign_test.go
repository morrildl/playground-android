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

package apksign

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"playground/android"
)

const (
	keyPath    = "testdata/signing.key"
	certPath   = "testdata/signing.crt"
	sdkapkPath = "testdata/app.1.apk"
	unsapkPath = "testdata/app.2.apk"
	rawzipPath = "testdata/just.a.zip"
)

func loadFile(name string) ([]byte, error) {
	var err error
	var b []byte
	if b, err = os.ReadFile(name); err != nil {
		return nil, err
	}
	return b, err
}

func saveFile(name string, b []byte) error {
	var f *os.File
	var err error
	if f, err = os.Create(name); err != nil {
		return err
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			panic(err)
		}
	}(f)
	if _, err = f.Write(b); err != nil {
		return err
	}
	return nil
}

var sdkapk, unsapk, rawzip []byte

var keys = []*android.SigningCert{
	{SigningKey: android.SigningKey{
		KeyPath: keyPath,
		Type:    android.RSA,
		Hash:    android.SHA256,
	},
		CertPath: certPath,
	},
}

var keysStream []*android.SigningCert

func InitKeyFromStream() {
	// Check Private Key File
	if _, err := filepath.Abs(keyPath); err != nil {
		fmt.Printf("File '%s' does not resolve", keyPath)
		return
	}

	if stat, err := os.Stat(keyPath); err != nil || (stat != nil && stat.IsDir()) {
		fmt.Printf("File '%v' does not stat or is a directory", err)
		return
	}

	fileBytes, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Printf("File '%s' failed to load", keyPath)
		return
	}

	block, _ := pem.Decode(fileBytes)
	if block == nil {
		fmt.Printf("Unable to decode PEM bytes")
	}
	if block.Type != "RSA PRIVATE KEY" && block.Type != "PRIVATE KEY" {
		fmt.Printf("type set as RSA but PEM block does not look like a 'PRIVATE KEY'")
		return
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		fmt.Printf("Cannot decode RSA Private key: %v", err)
	}

	// Check Certificate File
	if _, err := filepath.Abs(certPath); err != nil {
		fmt.Printf("File '%s' does not resolve", certPath)
		return
	}

	if stat, err := os.Stat(certPath); err != nil || (stat != nil && stat.IsDir()) {
		fmt.Printf("File '%v' does not stat or is a directory", err)
		return
	}

	certBytes, err := os.ReadFile(certPath)
	if err != nil {
		fmt.Printf("File '%s' failed to load", certPath)
		return
	}

	keysStream = []*android.SigningCert{
		{SigningKey: android.SigningKey{
			Type: android.RSA,
			Hash: android.SHA256,
			Key:  key,
		},
			CertBytes: certBytes,
		},
	}
}

func TestMain(m *testing.M) {
	var err error

	InitKeyFromStream()

	if sdkapk, err = loadFile(sdkapkPath); err != nil {
		os.Exit(1)
	}
	if unsapk, err = loadFile(unsapkPath); err != nil {
		os.Exit(1)
	}
	if rawzip, err = loadFile(rawzipPath); err != nil {
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func TestSDKAPK(t *testing.T) {
	var z *Zip
	var err error

	if z, err = NewZip(sdkapk); err != nil {
		t.Log("error parsing Zip", err)
		t.FailNow()
	}
	if !z.IsAPK {
		t.Errorf("zip is not an APK")
	}
	if !z.IsV1Signed {
		t.Errorf("zip is not V1 (JAR) signed")
	}
	if !z.IsV2Signed {
		t.Errorf("zip is not V2 signed")
	}
}

func TestUnsignedAPK(t *testing.T) {
	var z *Zip
	var err error
	if z, err = NewZip(unsapk); err != nil {
		t.Log("error parsing Zip", err)
		t.FailNow()
	}
	if !z.IsAPK {
		t.Errorf("zip is not an APK")
	}
	if z.IsV1Signed {
		t.Errorf("unsigned zip is reporting as V1 (JAR) signed")
	}
	if z.IsV2Signed {
		t.Errorf("unsigned zip is reporting as V2 signed")
	}
}

func TestRawZip(t *testing.T) {
	var z *Zip
	var err error
	if z, err = NewZip(rawzip); err != nil {
		t.Log("error parsing Zip", err)
		t.FailNow()
	}
	if z.IsAPK {
		t.Errorf("zip is reporting as an APK")
	}
	if z.IsV1Signed {
		t.Errorf("unsigned zip is reporting as V1 (JAR) signed")
	}
	if z.IsV2Signed {
		t.Errorf("unsigned zip is reporting as V2 signed")
	}
}

func TestVerifySDKAPK(t *testing.T) {
	var z *Zip
	var err error
	if z, err = NewZip(sdkapk); err != nil {
		t.Log("error parsing Zip", err)
		t.FailNow()
	}
	if err = z.VerifyV1(); err == nil {
		t.Errorf("v2-signed zip passes v1-only verify")
	}
	if err = z.VerifyV2(); err != nil {
		t.Errorf("v2-signed zip fails v2-only verify")
	}
	if err = z.Verify(); err != nil {
		t.Errorf("v2-signed zip fails generic verify")
	}
}

func TestSignUnsignedAPK(t *testing.T) {
	var z *Zip
	var err error
	if z, err = NewZip(unsapk); err != nil {
		t.Log("error parsing Zip", err)
		t.FailNow()
	}
	if z, err = z.Sign(keys); err != nil {
		t.Log("error signing apk", err)
		t.FailNow()
	}
	if err = z.VerifyV1(); err == nil {
		t.Errorf("v2-signed apk passes v1 verify")
	}
	if err = z.VerifyV2(); err != nil {
		t.Errorf("v2-signed apk fails v2 verify: %v", err)
	}
	if err = z.Verify(); err != nil {
		t.Errorf("v2-signed apk fails verify: %v", err)
	}
}

func TestSignUnsignedAPKWithKeyStream(t *testing.T) {
	var z *Zip
	var err error
	if z, err = NewZip(unsapk); err != nil {
		t.Log("error parsing Zip", err)
		t.FailNow()
	}
	if z, err = z.Sign(keysStream); err != nil {
		t.Log("error signing apk", err)
		t.FailNow()
	}
	if err = z.VerifyV1(); err == nil {
		t.Errorf("v2-signed apk passes v1 verify")
	}
	if err = z.VerifyV2(); err != nil {
		t.Errorf("v2-signed apk fails v2 verify: %v", err)
	}
	if err = z.Verify(); err != nil {
		t.Errorf("v2-signed apk fails verify: %v", err)
	}
}

func TestSignUnsignedZip(t *testing.T) {
	var z *Zip
	var err error
	if z, err = NewZip(rawzip); err != nil {
		t.Log("error parsing Zip", err)
		t.FailNow()
	}
	if z, err = z.Sign(keys); err != nil {
		t.Errorf("error signing zip: %v", err)
	}
	if err = z.VerifyV1(); err == nil {
		t.Errorf("v2-signed zip passes v1 verify")
	}
	if err = z.VerifyV2(); err != nil {
		t.Errorf("v2-signed zip fails v2 verify: %v", err)
	}
	if err = z.Verify(); err != nil {
		t.Errorf("v2-signed zip fails verify: %v", err)
	}
}

func TestResignAPK(t *testing.T) {
	var z *Zip
	var err error
	if z, err = NewZip(sdkapk); err != nil {
		t.Log("error parsing Zip", err)
		t.FailNow()
	}
	if z, err = z.Sign(keys); err != nil {
		t.Log("error signing zip", err)
		t.FailNow()
	}
	if err = z.VerifyV1(); err == nil {
		t.Errorf("v2-signed zip passes v1 verify")
	}
	if err = z.VerifyV2(); err != nil {
		t.Errorf("v2-signed zip fails v2 verify: %v", err)
	}
	if err = z.Verify(); err != nil {
		t.Errorf("v2-signed zip fails verify: %v", err)
	}
}

func TestV1Verify(t *testing.T) {
	var z *Zip
	var err error
	var b []byte

	if b, err = loadFile("testdata/app.v1.apk"); err != nil {
		t.Log("error loading file", err)
		t.FailNow()
	}
	if z, err = NewZip(b); err != nil {
		t.Log("error parsing zip", err)
		t.FailNow()
	}
	if err = z.VerifyV1(); err != nil {
		t.Errorf("v1-signed zip fails v1 verify")
	}
	if err = z.VerifyV2(); err == nil {
		t.Errorf("v1-signed zip passes v2 verify")
	}
	if err = z.Verify(); err != nil {
		t.Errorf("v1-signed zip fails general verify: %v", err)
	}
}

func TestV2Verify(t *testing.T) {
	var z *Zip
	var err error
	var b []byte

	if b, err = loadFile("testdata/app.v2.apk"); err != nil {
		t.Log("error loading file", err)
		t.FailNow()
	}
	if z, err = NewZip(b); err != nil {
		t.Log("error parsing zip", err)
		t.FailNow()
	}
	if err = z.VerifyV1(); err == nil {
		t.Errorf("v2-signed zip passes v1 verify")
	}
	if err = z.VerifyV2(); err != nil {
		t.Errorf("v2-signed zip fails v2 verify")
	}
	if err = z.Verify(); err != nil {
		t.Errorf("v2-signed zip fails general verify: %v", err)
	}
}

func TestV2Stripped(t *testing.T) {
	var z *Zip
	var err error
	var b []byte

	if b, err = loadFile("testdata/app.v2.stripped.apk"); err != nil {
		t.Log("error loading file", err)
		t.FailNow()
	}
	if z, err = NewZip(b); err != nil {
		t.Log("error parsing zip", err)
		t.FailNow()
	}
	if err = z.VerifyV1(); err == nil {
		t.Errorf("v2-stripped zip passes v1 verify ")
	}
	if err = z.VerifyV2(); err == nil {
		t.Errorf("v2-stripped zip passes v2 verify")
	}
	if err = z.Verify(); err == nil {
		t.Errorf("v2-stripped zip passes general verify: %v", err)
	}
}

func TestGenerateSignedFile(t *testing.T) {
	var z *Zip
	var err error
	var b []byte

	if b, err = loadFile("testdata/app.2.apk"); err != nil {
		t.Log("error loading file", err)
		t.FailNow()
	}
	if z, err = NewZip(b); err != nil {
		t.Log("error parsing zip", err)
		t.FailNow()
	}
	if z, err = z.Sign(keys); err != nil {
		t.Log("error signing zip", err)
		t.FailNow()
	}
	if err = saveFile("testdata/signed-app.2.apk", z.Bytes()); err != nil {
		t.Error("error signing zip", err)
	}
}
