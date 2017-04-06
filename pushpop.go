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

func pop32(in []byte) (uint32, []byte) {
	return binary.LittleEndian.Uint32(in[:4]), in[4:]
}

func pop64(in []byte) (uint64, []byte) {
	return binary.LittleEndian.Uint64(in[:8]), in[8:]
}

func popN(in []byte, count int) ([]byte, []byte) {
	return in[:count], in[count:]
}

func push32(in []byte) []byte {
	l := uint32(len(in))
	out := make([]byte, l+4)
	binary.LittleEndian.PutUint32(out, l)
	copy(out[4:], in)
	return out
}

func push64(in []byte) []byte {
	l := uint64(len(in))
	out := make([]byte, l+8)
	binary.LittleEndian.PutUint64(out, l)
	copy(out[8:], in)
	return out
}

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
