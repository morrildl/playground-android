// Copyright © 2019 Playground Global, LLC
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

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"playground/android"
	"playground/android/apksign"
)

// extremely basic wrapper for signing an APK
func main() {
	var z *apksign.Zip
	var err error
	var b []byte

	if len(os.Args) != 5 {
		panic(fmt.Errorf("%s: <unsigned.apk> <signing.crt> <signing.key> <signed.apk>", os.Args[0]))
	}

	sc := &android.SigningCert{
		SigningKey: android.SigningKey{
			Type:    android.RSA,
			Hash:    android.SHA256,
			KeyPath: os.Args[3],
		},
		CertPath: os.Args[2],
	}
	if err = sc.Resolve(); err != nil {
		panic(err)
	}

	if b, err = ioutil.ReadFile(os.Args[1]); err != nil {
		panic(err)
	}
	if z, err = apksign.NewZip(b); err != nil {
		panic(err)
	}
	if z, err = z.Sign([]*android.SigningCert{sc}); err != nil {
		panic(err)
	}
	if err = z.Verify(); err != nil {
		panic(err)
	}
	if err = ioutil.WriteFile(os.Args[4], z.Bytes(), 0660); err != nil {
		panic(err)
	}
}
