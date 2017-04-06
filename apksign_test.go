package apksign

import (
	"io/ioutil"
	"os"
	"testing"
)

func loadFile(name string) ([]byte, error) {
	var f *os.File
	var err error
	var b []byte
	if f, err = os.Open(name); err != nil {
		return nil, err
	}
	defer f.Close()
	if b, err = ioutil.ReadAll(f); err != nil {
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
	defer f.Close()
	if _, err = f.Write(b); err != nil {
		return err
	}
	return nil
}

var sdkapk, unsapk, rawzip []byte

var keys []*SigningKey = []*SigningKey{
	{
		CertPath: "testdata/signing.crt",
		KeyPath:  "testdata/signing.key",
		Type:     RSA,
		Hash:     SHA256,
	},
}

func TestMain(m *testing.M) {
	var err error

	if sdkapk, err = loadFile("testdata/app.1.apk"); err != nil {
		os.Exit(1)
	}
	if unsapk, err = loadFile("testdata/app.2.apk"); err != nil {
		os.Exit(1)
	}
	if rawzip, err = loadFile("testdata/just.a.zip"); err != nil {
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
		t.Errorf("v2-signed apk fails v2 verify", err)
	}
	if err = z.Verify(); err != nil {
		t.Errorf("v2-signed apk fails verify", err)
	}
	if !z.IsAPK || !z.IsV1Signed || !z.IsV2Signed {
		t.Errorf("v2-signed apk incorrectly characterized", z.IsAPK, z.IsV1Signed, z.IsV2Signed)
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
		t.Errorf("error signing zip", err)
	}
	if err = z.VerifyV1(); err == nil {
		t.Errorf("v2-signed zip passes v1 verify")
	}
	if err = z.VerifyV2(); err != nil {
		t.Errorf("v2-signed zip fails v2 verify", err)
	}
	if err = z.Verify(); err != nil {
		t.Errorf("v2-signed zip fails verify", err)
	}
	if z.IsAPK || !z.IsV1Signed || !z.IsV2Signed {
		t.Errorf("v2-signed apk incorrectly characterized", z.IsAPK, z.IsV1Signed, z.IsV2Signed)
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
		t.Errorf("v2-signed zip fails v2 verify", err)
	}
	if err = z.Verify(); err != nil {
		t.Errorf("v2-signed zip fails verify", err)
	}
	if !z.IsAPK || !z.IsV1Signed || !z.IsV2Signed {
		t.Errorf("v2-signed apk incorrectly characterized", z.IsAPK, z.IsV1Signed, z.IsV2Signed)
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
	if !z.IsAPK || !z.IsV1Signed || z.IsV2Signed {
		t.Errorf("v1-signed apk incorrectly characterized", z.IsAPK, z.IsV1Signed, z.IsV2Signed)
	}
	if err = z.VerifyV1(); err != nil {
		t.Errorf("v1-signed zip fails v1 verify")
	}
	if err = z.VerifyV2(); err == nil {
		t.Errorf("v1-signed zip passes v2 verify")
	}
	if err = z.Verify(); err != nil {
		t.Errorf("v1-signed zip fails general verify", err)
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
	if !z.IsAPK || z.IsV1Signed || !z.IsV2Signed {
		t.Errorf("v2-signed apk incorrectly characterized", z.IsAPK, z.IsV1Signed, z.IsV2Signed)
	}
	if err = z.VerifyV1(); err == nil {
		t.Errorf("v2-signed zip passes v1 verify")
	}
	if err = z.VerifyV2(); err != nil {
		t.Errorf("v2-signed zip fails v2 verify")
	}
	if err = z.Verify(); err != nil {
		t.Errorf("v2-signed zip fails general verify", err)
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
	if !z.IsAPK || !z.IsV1Signed || z.IsV2Signed {
		t.Errorf("v2-stripped apk incorrectly characterized", z.IsAPK, z.IsV1Signed, z.IsV2Signed)
	}
	if err = z.VerifyV1(); err == nil {
		t.Errorf("v2-stripped zip passes v1 verify ")
	}
	if err = z.VerifyV2(); err == nil {
		t.Errorf("v2-stripped zip passes v2 verify")
	}
	if err = z.Verify(); err == nil {
		t.Errorf("v2-stripped zip passes general verify", err)
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
