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

// SigningVersion is an enum of all supported Android APK signing scheme versions. Currently these
// are v1 and v2.
type SigningVersion int

const (
	APKSignUnknown SigningVersion = iota
	APKSignV1
	APKSignV2
)

func (sv SigningVersion) String() string {
	switch sv {
	case APKSignV1:
		return "1"
	case APKSignV2:
		return "2"
	default:
		return ""
	}
}
