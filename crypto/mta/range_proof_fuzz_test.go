// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"encoding/binary"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
)

// capRangeProofAliceFuzz bounds the fuzz framing before it is unpacked into
// slice allocations, so CI fuzzing cannot amplify a blob into oversized
// big.Int arrays (each part length is a uint16 in the framing).
const capRangeProofAliceFuzz = 2048

// capFramedParts bounds the section count the framing parser will honour
// before it allocates the element slice, so a small blob declaring a huge
// uint16 count cannot amplify into a large allocation.
const capFramedParts = 1024

// ----- //
// framing codec: one fuzz input drives the six-arity decoder
//
// Layout (big-endian): uint16 count, then per part: uint16 len, bytes.

type rfWriter struct{ b []byte }

func (w *rfWriter) u16(v uint16) {
	w.b = binary.BigEndian.AppendUint16(w.b, v)
}

func (w *rfWriter) parts(x [][]byte) {
	w.u16(uint16(len(x)))
	for i := range x {
		w.u16(uint16(len(x[i])))
		w.b = append(w.b, x[i]...)
	}
}

// frameRangeProofParts encodes the six decoder parts into one byte stream.
func frameRangeProofParts(parts ...[]byte) []byte {
	w := &rfWriter{}
	w.parts(parts)
	return w.b
}

type fuzzU16Reader struct {
	buf []byte
	off int
}

func (r *fuzzU16Reader) u16() (uint16, bool) {
	b, ok := r.take(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(b), true
}

func (r *fuzzU16Reader) take(n int) ([]byte, bool) {
	if n < 0 || len(r.buf)-r.off < n {
		return nil, false
	}
	v := r.buf[r.off : r.off+n]
	r.off += n
	return v, true
}

// parseRangeProofParts unpacks the framing. ok is false when the blob is
// truncated; callers must return early in that case.
func parseRangeProofParts(buf []byte) ([][]byte, bool) {
	r := &fuzzU16Reader{buf: buf}
	count, ok := r.u16()
	if !ok {
		return nil, false
	}
	if count > capFramedParts {
		return nil, false
	}
	s := make([][]byte, count)
	for i := range s {
		l, ok := r.u16()
		if !ok {
			return nil, false
		}
		v, ok := r.take(int(l))
		if !ok {
			return nil, false
		}
		s[i] = v
	}
	return s, true
}

// ----- //
// seed: deterministic, no key generation or expensive crypto

// validRangeProofSeed builds a deterministic six-part, all-parts-non-empty
// seed so the fuzzer starts in the success region.
func validRangeProofSeed() [][]byte {
	parts := make([][]byte, RangeProofAliceBytesParts)
	for i := range parts {
		// Distinct deterministic 1..6-byte payloads, none empty.
		parts[i] = make([]byte, i+1)
		for j := range parts[i] {
			parts[i][j] = byte(1 + i*7 + j)
		}
	}
	return parts
}

// ----- //
// fuzz target

// FuzzRangeProofAliceFromBytes exercises mta.RangeProofAliceFromBytes on
// untrusted framed input, classifying each generated shape against the
// decoder's contract.
//
//   - exactly RangeProofAliceBytesParts non-empty parts must decode to a
//     non-nil proof that passes ValidateBasic;
//   - a wrong part count or any empty part must be rejected — category
//     pinned, wording not.
//
// The target is cheap (slice framing, no key generation) and deterministic,
// safe under parallel fuzz workers.
func FuzzRangeProofAliceFromBytes(f *testing.F) {
	seed := validRangeProofSeed()
	f.Add(frameRangeProofParts(seed...))
	f.Add(frameRangeProofParts(seed[:5]...)) // one part short
	// One part extra: a 7-part slice built explicitly; slicing the
	// 6-part seed to [:7] would panic.
	extra := append(append([][]byte{}, seed...), []byte{9})
	f.Add(frameRangeProofParts(extra...))
	empty := validRangeProofSeed()
	empty[2] = nil
	f.Add(frameRangeProofParts(empty...)) // interior empty part

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > capRangeProofAliceFuzz {
			return
		}
		parts, ok := parseRangeProofParts(data)
		if !ok {
			return // truncated framing
		}
		pf, err := RangeProofAliceFromBytes(parts)
		if common.NonEmptyMultiBytes(parts, RangeProofAliceBytesParts) {
			if err != nil {
				t.Fatalf("RangeProofAliceFromBytes rejected %d non-empty parts: %v", len(parts), err)
			}
			if !pf.ValidateBasic() {
				t.Fatal("decoded proof must have all six fields set")
			}
			return
		}
		if err == nil {
			t.Fatalf("RangeProofAliceFromBytes accepted %d-part input with empty parts, expected rejection", len(parts))
		}
	})
}
