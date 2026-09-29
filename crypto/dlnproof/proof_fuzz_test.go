// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package dlnproof

import (
	"encoding/binary"
	"testing"
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

type dlnFuzzReader struct {
	buf []byte
	off int
}

func (r *dlnFuzzReader) u16() (uint16, bool) {
	if len(r.buf)-r.off < 2 {
		return 0, false
	}
	v := binary.BigEndian.Uint16(r.buf[r.off:])
	r.off += 2
	return v, true
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

// parseDLNParts unpacks the framing. ok is false when the blob is truncated;
// callers must return early in that case.
func parseDLNParts(buf []byte) (alphas, ts [][]byte, ok bool) {
	r := &dlnFuzzReader{buf: buf}
	alphas, ok = r.section()
	if !ok {
		return nil, nil, false
	}
	ts, ok = r.section()
	return alphas, ts, ok
}

// ----- //
// seed: deterministic, no key generation or expensive crypto

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
// framed input, classifying each generated shape against the decoder's
// contract.
//
//   - exactly Iterations alphas and Iterations ts parts must decode to a
//     non-nil proof;
//   - any other arity on either side must be rejected — category pinned,
//     wording not.
//
// The target is cheap (slice framing, no key generation) and deterministic,
// safe under parallel fuzz workers.
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
		pf, err := UnmarshalDLNProof(alphas, ts)
		if len(alphas) == Iterations && len(ts) == Iterations {
			if err != nil {
				t.Fatalf("UnmarshalDLNProof rejected exact-arity input: %v", err)
			}
			if pf == nil {
				t.Fatal("UnmarshalDLNProof must return a populated proof on valid input")
			}
			return
		}
		if err == nil {
			t.Fatalf("UnmarshalDLNProof accepted %d alphas / %d ts parts, expected Iterations=%d each",
				len(alphas), len(ts), Iterations)
		}
	})
}
