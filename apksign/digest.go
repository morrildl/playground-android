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
	"bytes"
	"crypto"
	"encoding/binary"
	"encoding/hex"
	"hash"
	"io"

	"playground/log"
)

// Digester is a crypto.Hash implementation that implements the Merkel-tree-flavored hash scheme
// defined in the Android APK v2 signing scheme.
type Digester struct {
	Hash   crypto.Hash
	chunks []chan []byte
}

// NewDigester returns a new instance using the provided crypto.Hash algorithm for its underlying
// hash scheme.
func NewDigester(h crypto.Hash) *Digester {
	return &Digester{h, make([]chan []byte, 0)}
}

// Write starts a parallelized chunk-based hash computation of the input. Note that this differs
// slightly from a typical crypto.Hash in that the input is, per Android spec, computed in 1k chunks
// of its input. This means that `d.Write(a); d.Write(b)` != `d.Write(append(a, b...))` unless `a`
// happens to be an exact multiple of 1k.
//
// This function starts `len(p) / 1k` goroutines.
func (d *Digester) Write(p []byte) (n int, err error) {
	d.chunks = append(d.chunks, parallelBufferHash(p, d.Hash.New)...)
	return len(p), nil
}

// Sum waits winds up the parallel chunk hashes into the accumulated top-level hash, per Android
// spec.
func (d *Digester) Sum(b []byte) []byte {
	numChunks := make([]byte, 4)
	binary.LittleEndian.PutUint32(numChunks, uint32(len(d.chunks)))
	accumHash := d.Hash.New()
	accumHash.Write([]byte{0x5a})
	accumHash.Write(numChunks)
	for _, c := range d.chunks {
		buf := <-c
		log.Debug("Digester.Sum", "chunk hash", hex.EncodeToString(buf))
		_, err := io.Copy(accumHash, bytes.NewReader(buf))
		if err != nil {
			// this is highly unlikely to happen, but given return type, nothing we can do
			log.Debug("Digester.Sum", "error copying RAM buffers", err)
			break
		}
	}
	return accumHash.Sum(b)
}

// Reset clears this Digester, preparing it for a new usage.
func (d *Digester) Reset() {
	d.chunks = make([]chan []byte, 0)
}

// Size() returns the size of the Digester, which is the same as the size of its current underlying
// crypto.Hash.
func (d *Digester) Size() int {
	return d.Hash.New().Size()
}

// BlockSize() returns the block size of the Digester, which is the same as the block size of its current underlying
// crypto.Hash.
func (d *Digester) BlockSize() int {
	return d.Hash.New().BlockSize()
}

func parallelBufferHash(inbuf []byte, newHash func() hash.Hash) []chan []byte {
	hasher := func(d []byte, h hash.Hash, c chan []byte) {
		h.Write(d)
		c <- h.Sum(nil)
	}
	var ret []chan []byte
	count := len(inbuf)
	for count > 0 {
		c := make(chan []byte)
		var buf []byte
		var l uint32
		if count < 1048576 {
			buf = make([]byte, count+5)
			copy(buf[5:], inbuf[:count])
			l = uint32(count)
			count = 0
		} else {
			buf = make([]byte, 1048576+5)
			copy(buf[5:], inbuf[:1048576])
			l = 1048576
			count -= 1048576
			inbuf = inbuf[1048576:]
		}
		buf[0] = 0xa5
		binary.LittleEndian.PutUint32(buf[1:5], l)
		go hasher(buf, newHash(), c)
		ret = append(ret, c)
	}

	return ret
}

/* obsolete, but let's keep this for reference

func parallelFileHash(f *os.File, start, count uint64, newHash func() hash.Hash) ([]chan []byte, error) {
	hasher := func(d []byte, h hash.Hash, c chan []byte) {
		h.Write(d)
		c <- h.Sum(nil)
	}
	var ret []chan []byte
	f.Seek(int64(start), 0)
	for count > 0 {
		c := make(chan []byte)
		var buf []byte
		var l uint32
		if count < 1048576 {
			buf = make([]byte, count+5)
			l = uint32(count)
		} else {
			buf = make([]byte, 1048576+5)
			l = 1048576
		}
		buf[0] = 0xa5
		binary.LittleEndian.PutUint32(buf[1:5], l)
		n, err := io.ReadFull(f, buf[5:])
		if err != nil {
			return nil, err
		}
		count -= uint64(n)
		go hasher(buf, newHash(), c)
		ret = append(ret, c)
	}

	return ret, nil
}
*/
