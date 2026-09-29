// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package dlnproof

import (
	"encoding/binary"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

// capDLNProofFuzz bounds the fuzz framing before it is unpacked into slice
// allocations, so CI fuzzing cannot amplify a blob into oversized big.Int
// arrays (each part length is a uint16 in the framing).
const capDLNProofFuzz = 2048

// capFramedParts bounds the section count the framing parser will honour
// before it allocates the element slice, so a small blob declaring a huge
// uint16 count cannot amplify into a large allocation.
const capFramedParts = 1024

// ----- //
// framing codec: one fuzz input drives the two-argument decoder
//
// Layout (big-endian): two sections, each
//
//	uint16 count, then per part: uint16 len, bytes

type dlnWriter struct{ b []byte }

func (w *dlnWriter) u16(v uint16) {
	w.b = binary.BigEndian.AppendUint16(w.b, v)
}

func (w *dlnWriter) section(x [][]byte) {
	w.u16(uint16(len(x)))
	for i := range x {
		w.u16(uint16(len(x[i])))
		w.b = append(w.b, x[i]...)
	}
}

// frameDLNParts encodes (alphas, ts) into one byte stream.
func frameDLNParts(alphas, ts [][]byte) []byte {
	w := &dlnWriter{}
	w.section(alphas)
	w.section(ts)
	return w.b
}

// parseDLNParts unpacks the framing. ok is false when the blob is truncated;
// callers must return early in that case.
func parseDLNParts(buf []byte) (alphas, ts [][]byte, ok bool) {
	r := &dlnFuzzReader{buf: buf}
	alphas, ok = r.section()
	if !ok {
		return
	}

	ts, ok = r.section()
	return alphas, ts, ok
}

type dlnFuzzReader struct {
	buf []byte
	off int
}

func (r *dlnFuzzReader) u16() (uint16, bool) {
	b, ok := r.take(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(b), true
}

func (r *dlnFuzzReader) take(n int) ([]byte, bool) {
	if n < 0 || len(r.buf)-r.off < n {
		return nil, false
	}
	v := r.buf[r.off : r.off+n]
	r.off += n
	return v, true
}

func (r *dlnFuzzReader) section() ([][]byte, bool) {
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
// seeds: deterministic, no key generation or expensive crypto

// validDLNSeed builds a deterministic pair of exactly-Iterations part lists.
func validDLNSeed() (alphas, ts [][]byte) {
	alphas = make([][]byte, Iterations)
	ts = make([][]byte, Iterations)
	for i := range alphas {
		alphas[i] = []byte{byte(1 + i%251)}
		ts[i] = []byte{byte(127 + i%124)}
	}
	return
}

// ----- //
// fuzz target

// FuzzUnmarshalDLNProof exercises dlnproof.UnmarshalDLNProof on untrusted
// framed input.
//
// Contract asserted:
//   - rejection: when either section does not carry exactly Iterations
//     parts, UnmarshalDLNProof must return an error (category pinned,
//     wording not);
//   - success invariants: when both sections carry exactly Iterations parts,
//     every Alpha[i] and T[i] is the big-endian SetBytes of the matching
//     input part, so the fixed arity is preserved exactly through the
//     decode.
//
// The target is cheap (SetBytes + struct construction only, no key
// generation) and deterministic, safe under parallel fuzz workers.
func FuzzUnmarshalDLNProof(f *testing.F) {
	va, vt := validDLNSeed()
	f.Add(frameDLNParts(va, vt))
	f.Add(frameDLNParts(va[:Iterations-1], vt)) // alphas one short

	// vt has Iterations parts; append one more to make Iterations+1.
	plus := append(append([][]byte{}, vt...), []byte{9})
	f.Add(frameDLNParts(va, plus))

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > capDLNProofFuzz {
			return
		}
		alphas, ts, ok := parseDLNParts(data)
		if !ok {
			return // truncated framing
		}
		if len(alphas) != Iterations || len(ts) != Iterations {
			if _, err := UnmarshalDLNProof(alphas, ts); err == nil {
				t.Fatalf("UnmarshalDLNProof accepted %d alphas / %d ts parts, expected Iterations=%d each",
					len(alphas), len(ts), Iterations)
			}
			return
		}
		pf, err := UnmarshalDLNProof(alphas, ts)
		if err != nil {
			t.Fatalf("UnmarshalDLNProof failed on exact-arity input: %v", err)
		}
		for i := range pf.Alpha {
			// Value equality on the decoded fields: the proof parts must be
			// the big-endian SetBytes of each input part.
			if pf.Alpha[i].Cmp(new(big.Int).SetBytes(alphas[i])) != 0 {
				t.Fatalf("Alpha[%d] must be the big-endian SetBytes of the input part", i)
			}
			if pf.T[i].Cmp(new(big.Int).SetBytes(ts[i])) != 0 {
				t.Fatalf("T[%d] must be the big-endian SetBytes of the input part", i)
			}
		}
	})
}

// TestUnmarshalDLNProofSemantics pins the success invariant and the two
// rejection categories on deterministic seeds (no fuzz corpus needed).
func TestUnmarshalDLNProofSemantics(t *testing.T) {
	a, tv := validDLNSeed()
	pf, err := UnmarshalDLNProof(a, tv)
	assert.NoError(t, err, "exact-arity input must decode")
	if err != nil {
		return
	}
	if pf.Alpha[0].Cmp(new(big.Int).SetBytes(a[0])) != 0 {
		t.Fatal("Alpha[0] must be the big-endian SetBytes of input part 0")
	}
	if pf.T[0].Cmp(new(big.Int).SetBytes(tv[0])) != 0 {
		t.Fatal("T[0] must be the big-endian SetBytes of input part 0")
	}

	// Rejection: one alpha part short.
	short := a[:Iterations-1]
	if _, err := UnmarshalDLNProof(short, tv); err == nil {
		t.Fatal("expected short alpha arity to be rejected")
	}

	// Rejection: one ts part extra.
	long := append(append([][]byte{}, tv...), []byte{9})
	if _, err := UnmarshalDLNProof(a, long); err == nil {
		t.Fatal("expected surplus ts arity to be rejected")
	}
}
