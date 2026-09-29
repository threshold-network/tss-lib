// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package paillier

import (
	"encoding/binary"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
)

// capModProofFuzz bounds the fuzz framing before it is unpacked into slice
// allocations, so CI fuzzing cannot amplify a blob into oversized element
// arrays (each element length is a uint16 in the framing).
const capModProofFuzz = 2048

// capFramedParts bounds the section counts the framing parser will honour
// before it allocates the element slice, so a small blob declaring a huge
// uint16 count cannot amplify into a large allocation.
const capFramedParts = 1024

// ----- //
// framing codec: one fuzz input drives the five-argument decoder
//
// Layout (big-endian, sequential):
//
//	ws:  uint32 len, bytes
//	xs:  uint16 count, then per element: uint16 len, bytes
//	as:  uint16 count, then per element: 1 byte
//	bs:  uint16 count, then per element: 1 byte
//	zs:  uint16 len, bytes

type framedWriter struct{ b []byte }

func (w *framedWriter) u16(v uint16) {
	w.b = binary.BigEndian.AppendUint16(w.b, v)
}

func (w *framedWriter) u32(v uint32) {
	w.b = binary.BigEndian.AppendUint32(w.b, v)
}

func (w *framedWriter) u32LenBytes(x []byte) {
	w.u32(uint32(len(x)))
	w.b = append(w.b, x...)
}

func (w *framedWriter) byteSliceList(x [][]byte) {
	w.u16(uint16(len(x)))
	for i := range x {
		w.u16(uint16(len(x[i])))
		w.b = append(w.b, x[i]...)
	}
}

func (w *framedWriter) boolList(x []bool) {
	w.u16(uint16(len(x)))
	for i := range x {
		if x[i] {
			w.b = append(w.b, 1)
		} else {
			w.b = append(w.b, 0)
		}
	}
}

// frameModProofSections encodes (ws, xs, as, bs, zs) into a single
// self-describing byte stream.
func frameModProofSections(ws []byte, xs [][]byte, as, bs []bool, zs [][]byte) []byte {
	w := &framedWriter{}
	w.u32LenBytes(ws)
	w.byteSliceList(xs)
	w.boolList(as)
	w.boolList(bs)
	w.byteSliceList(zs)
	return w.b
}

type fuzzReader struct {
	buf []byte
	off int
}

func (r *fuzzReader) remain() int { return len(r.buf) - r.off }

func (r *fuzzReader) take(n int) ([]byte, bool) {
	if n < 0 || r.remain() < n {
		return nil, false
	}
	v := r.buf[r.off : r.off+n]
	r.off += n
	return v, true
}

func (r *fuzzReader) u16() (uint16, bool) {
	b, ok := r.take(2)
	if !ok {
		return 0, false
	}
	return binary.BigEndian.Uint16(b), true
}

func (r *fuzzReader) u32LenBytes(out *[]byte) bool {
	b, ok := r.take(4)
	if !ok {
		return false
	}
	n := int(binary.BigEndian.Uint32(b))
	v, ok := r.take(n)
	if !ok {
		return false
	}
	*out = v
	return true
}

func (r *fuzzReader) byteSliceList(out *[][]byte) bool {
	count, ok := r.u16()
	if !ok {
		return false
	}
	if count > capFramedParts {
		return false
	}
	s := make([][]byte, count)
	for i := range s {
		l, ok := r.u16()
		if !ok {
			return false
		}
		v, ok := r.take(int(l))
		if !ok {
			return false
		}
		s[i] = v
	}
	*out = s
	return true
}

func (r *fuzzReader) boolList(out *[]bool) bool {
	count, ok := r.u16()
	if !ok {
		return false
	}
	if count > capFramedParts {
		return false
	}
	s := make([]bool, count)
	for i := range s {
		v, ok := r.take(1)
		if !ok {
			return false
		}
		s[i] = v[0] != 0
	}
	*out = s
	return true
}

// parseModProofFrame unpacks the framing back into the five decoder
// arguments. ok is false when the blob is truncated; callers must return
// early in that case.
func parseModProofFrame(buf []byte) (ws []byte, xs [][]byte, as, bs []bool, zs [][]byte, ok bool) {
	r := &fuzzReader{buf: buf}
	if !r.u32LenBytes(&ws) {
		return
	}
	if !r.byteSliceList(&xs) {
		return
	}
	if !r.boolList(&as) {
		return
	}
	if !r.boolList(&bs) {
		return
	}
	if !r.byteSliceList(&zs) {
		return
	}
	ok = true
	return
}

// ----- //
// seeds: deterministic, no key generation

type modProofSeed struct {
	ws []byte
	xs [][]byte
	as []bool
	bs []bool
	zs [][]byte
}

// validModProofSeed builds a deterministic, arity-valid seed: non-empty W
// and exactly PARAM_M of each of X, A, B, Z.
func validModProofSeed() modProofSeed {
	return modProofSeedWithArity(PARAM_M, PARAM_M, PARAM_M, PARAM_M)
}

// modProofSeedWithArity builds a seed with controlled per-section counts so
// the fuzzer can seed the rejection shapes directly.
func modProofSeedWithArity(nx, na, nb, nz int) modProofSeed {
	s := modProofSeed{ws: []byte{1}}
	s.xs = make([][]byte, nx)
	s.as = make([]bool, na)
	s.bs = make([]bool, nb)
	s.zs = make([][]byte, nz)
	for i := range s.xs {
		s.xs[i] = []byte{byte(i % 251)}
	}
	for i := range s.zs {
		s.zs[i] = []byte{byte((i + 127) % 251)}
	}
	for i := range s.as {
		s.as[i] = i%2 == 0
	}
	for i := range s.bs {
		s.bs[i] = i%3 != 0
	}
	return s
}

// emptyWSModProofSeed builds an arity-valid seed with a nil W: the decoder
// must reject empty W even when every count guard passes.
func emptyWSModProofSeed() modProofSeed {
	s := modProofSeedWithArity(PARAM_M, PARAM_M, PARAM_M, PARAM_M)
	s.ws = nil
	return s
}

func (s modProofSeed) frame() []byte {
	return frameModProofSections(s.ws, s.xs, s.as, s.bs, s.zs)
}

// modProofArityOK reports whether the unpacked arguments satisfy the decoder
// contract: non-empty W and exact PARAM_M arity for each of X, A, B, Z.
func modProofArityOK(ws []byte, xs [][]byte, as, bs []bool, zs [][]byte) bool {
	return common.NonEmptyBytes(ws) &&
		len(xs) == PARAM_M && len(as) == PARAM_M &&
		len(bs) == PARAM_M && len(zs) == PARAM_M
}

// ----- //
// fuzz target

// FuzzUnmarshalModProof exercises paillier.UnmarshalModProof on untrusted
// framed input, classifying each generated shape against the decoder's
// contract.
//
//   - contract-satisfying shapes (non-empty W, exact PARAM_M arity for X/A/B/Z)
//     must decode to a non-nil proof with W populated;
//   - contract-violating shapes (empty W or any wrong arity) must be
//     rejected — category pinned, wording not.
//
// The target is cheap (slice framing, no key generation) and deterministic,
// safe under parallel fuzz workers.
func FuzzUnmarshalModProof(f *testing.F) {
	f.Add(validModProofSeed().frame())
	f.Add(modProofSeedWithArity(PARAM_M-1, PARAM_M, PARAM_M, PARAM_M).frame())
	f.Add(modProofSeedWithArity(PARAM_M, PARAM_M, PARAM_M, PARAM_M+1).frame())
	f.Add(emptyWSModProofSeed().frame())

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > capModProofFuzz {
			return
		}
		ws, xs, as, bs, zs, ok := parseModProofFrame(data)
		if !ok {
			return // truncated framing; decoder arguments not constructed
		}
		proof, err := UnmarshalModProof(ws, xs, as, bs, zs)
		if modProofArityOK(ws, xs, as, bs, zs) {
			if err != nil {
				t.Fatalf("UnmarshalModProof rejected a contract-satisfying shape: %v", err)
			}
			if proof == nil || proof.W == nil {
				t.Fatal("UnmarshalModProof must return a populated proof on valid input")
			}
			return
		}
		if err == nil {
			t.Fatalf("UnmarshalModProof accepted a contract-violating shape: |ws|=%d |xs|=%d |as|=%d |bs|=%d |zs|=%d",
				len(ws), len(xs), len(as), len(bs), len(zs))
		}
	})
}
