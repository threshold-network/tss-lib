// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

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

// ----- //
// seeds: deterministic, no key generation or expensive crypto

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

// rangeProofArityOK mirrors the decoder guard: exactly
// RangeProofAliceBytesParts non-empty parts.
func rangeProofArityOK(parts [][]byte) bool {
	return common.NonEmptyMultiBytes(parts, RangeProofAliceBytesParts)
}

// ----- //
// fuzz target

// FuzzRangeProofAliceFromBytes exercises mta.RangeProofAliceFromBytes on
// untrusted framed input.
//
// Contract asserted:
//   - rejection: wrong part count or any empty part is rejected (category
//     pinned, wording not);
//   - success invariants: the decoded proof passes ValidateBasic and every
//     field is the big-endian SetBytes of the matching input part, so the
//     six-part arity is preserved exactly through the decode.
//
// The target is cheap (SetBytes + struct construction only, no key
// generation) and deterministic, safe under parallel fuzz workers.
func FuzzRangeProofAliceFromBytes(f *testing.F) {
	f.Add(frameRangeProofParts(validRangeProofSeed()...))
	f.Add(frameRangeProofParts(validRangeProofSeed()[:5]...)) // one part short
	// One part extra: a 7-part slice built explicitly; slicing the
	// 6-part seed to [:7] would panic.
	extra := append(append([][]byte{}, validRangeProofSeed()...), []byte{9})
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
		if !rangeProofArityOK(parts) {
			if _, err := RangeProofAliceFromBytes(parts); err == nil {
				t.Fatalf("RangeProofAliceFromBytes accepted %d-part input with empty parts, expected rejection", len(parts))
			}
			return
		}
		pf, err := RangeProofAliceFromBytes(parts)
		if err != nil {
			t.Fatalf("RangeProofAliceFromBytes failed on arity-valid input: %v", err)
		}
		assert.True(t, pf.ValidateBasic(), "decoded proof must have all six fields set")
		fields := []*big.Int{pf.Z, pf.U, pf.W, pf.S, pf.S1, pf.S2}
		for i := range parts {
			// Value equality on the decoded fields: the proof must be the
			// big-endian SetBytes of each input part.
			if fields[i].Cmp(new(big.Int).SetBytes(parts[i])) != 0 {
				t.Fatalf("part %d must decode as the big-endian SetBytes of the input", i)
			}
		}
	})
}

// TestRangeProofAliceFromBytesSemantics pins the success invariant and the
// rejection categories on deterministic seeds (no fuzz corpus needed).
func TestRangeProofAliceFromBytesSemantics(t *testing.T) {
	parts := validRangeProofSeed()
	pf, err := RangeProofAliceFromBytes(parts)
	assert.NoError(t, err, "six non-empty parts must decode")
	if err != nil {
		return
	}
	assert.True(t, pf.ValidateBasic(), "all six fields must be set")
	if pf.S1.Cmp(new(big.Int).SetBytes(parts[4])) != 0 {
		t.Fatal("S1 must be the big-endian SetBytes of part 4")
	}
	if pf.S2.Cmp(new(big.Int).SetBytes(parts[5])) != 0 {
		t.Fatal("S2 must be the big-endian SetBytes of part 5")
	}

	// Rejection: one part short.
	short := parts[:5]
	if _, err := RangeProofAliceFromBytes(short); err == nil {
		t.Fatal("expected 5-part input to be rejected")
	}

	// Rejection: one extra part.
	long := append(append([][]byte{}, parts...), []byte{9})
	if _, err := RangeProofAliceFromBytes(long); err == nil {
		t.Fatal("expected 7-part input to be rejected")
	}

	// Rejection: interior empty part.
	empty := parts
	empty[3] = nil
	if _, err := RangeProofAliceFromBytes(empty); err == nil {
		t.Fatal("expected empty interior part to be rejected")
	}
}
