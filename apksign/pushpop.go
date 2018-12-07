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
	"encoding/binary"
)

/* This idiom is very common in the v2 Android signing scheme:
   val := binary.LittleEndian.Uint32(buf) // parse 4 bytes into a uint32
	 buf = buf[4:]													// advance the buffer past the "consumed" bytes

	 ...and same for uint64 values.

	 It's not a lot of code but when it appears many times in succession it detracts from readability
	 and is prone to typos and copy/paste bugs. So we wrap this in a few convenience functions to
	 improve this. The compiler generally seems to inline calls to these.
*/

// pop32 returns the first 4 bytes of the input decoded into a uint32, and a new slice over the same
// backing array, shifted past the 4 bytes. That is, it pops the first 4 bytes off the slice into a
// uint32, and returns both.
func pop32(in []byte) (uint32, []byte) {
	return binary.LittleEndian.Uint32(in[:4]), in[4:]
}

// pop64 returns the first 8 bytes of the input decoded into a uint32, and a new slice over the same
// backing array, shifted past the 8 bytes. That is, it pops the first 8 bytes off the slice into a
// uint64, and returns both.
func pop64(in []byte) (uint64, []byte) {
	return binary.LittleEndian.Uint64(in[:8]), in[8:]
}

// popN pops the first `count` bytes of `in` into a new slice, and then returns it along with the
// remainder.
func popN(in []byte, count int) ([]byte, []byte) {
	return in[:count], in[count:]
}

// push32 returns a new slice with new backing array that is identical to the input except with 4
// additional bytes at its head. These 4 new bytes are populated with the uint32-encoded length of
// the input array. That is, push32 returns a new slice (and array) prepended with a 4-byte length
// of the original slice, followed by the original slice's data.
func push32(in []byte) []byte {
	l := uint32(len(in))
	out := make([]byte, l+4)
	binary.LittleEndian.PutUint32(out, l)
	copy(out[4:], in)
	return out
}

// push64 returns a new slice with new backing array that is identical to the input except with 8
// additional bytes at its head. These 8 new bytes are populated with the uint64-encoded length of
// the input array. That is, push64 returns a new slice (and array) prepended with an 8-byte length
// of the original slice, followed by the original slice's data.
func push64(in []byte) []byte {
	l := uint64(len(in))
	out := make([]byte, l+8)
	binary.LittleEndian.PutUint64(out, l)
	copy(out[8:], in)
	return out
}

// concat returns a new slice over a new backing array, consisting of all the input slices
// concatenated back to back. The length of the output is, naturally, the sum of the lengths of the
// input.
func concat(blocks ...[]byte) []byte {
	totes := 0
	for _, b := range blocks {
		totes += len(b)
	}
	out := make([]byte, totes)
	cur := out
	for _, b := range blocks {
		copy(cur, b)
		cur = cur[len(b):]
	}
	return out
}
