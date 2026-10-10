// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package paillier

import "testing"

// capFramedParts bounds the slice counts the fuzzer constructs from its
// uint16 arguments, so a tiny fuzz value cannot amplify into an oversized
// allocation before the decoder runs.
const capFramedParts = 1024

// FuzzUnmarshalModProof exercises paillier.UnmarshalModProof on untrusted
// argument shapes derived from native fuzz primitives.
//
// The fuzz args are section counts (nx, na, nb, nz), a fill byte for the
// part payloads, and an emptyWS flag (non-zero -> nil W). Each generated
// shape is classified against the decoder's guards: exact PARAM_M arity for
// X/A/B/Z plus non-empty W must decode to a non-nil, populated proof; any
// other shape must be rejected (category pinned, wording not). The target
// is cheap (small slices only, no key generation) and deterministic, safe
// under parallel fuzz workers.
func FuzzUnmarshalModProof(f *testing.F) {
	// Exact arity on all four sections.
	f.Add(uint16(PARAM_M), uint16(PARAM_M), uint16(PARAM_M), uint16(PARAM_M), byte(1), byte(0))
	// X section one part short.
	f.Add(uint16(PARAM_M-1), uint16(PARAM_M), uint16(PARAM_M), uint16(PARAM_M), byte(1), byte(0))
	// Z section one part long.
	f.Add(uint16(PARAM_M), uint16(PARAM_M), uint16(PARAM_M), uint16(PARAM_M+1), byte(1), byte(0))
	// Empty W with every arity guard passing.
	f.Add(uint16(PARAM_M), uint16(PARAM_M), uint16(PARAM_M), uint16(PARAM_M), byte(1), byte(1))

	f.Fuzz(func(t *testing.T, nx, na, nb, nz uint16, fill, emptyWS byte) {
		nx = min(nx, capFramedParts)
		na = min(na, capFramedParts)
		nb = min(nb, capFramedParts)
		nz = min(nz, capFramedParts)
		ws := []byte{fill}
		if emptyWS != 0 {
			ws = nil
		}
		xs := make([][]byte, nx)
		for i := range xs {
			xs[i] = []byte{fill}
		}
		as := make([]bool, na)
		for i := range as {
			as[i] = i&1 == 0
		}
		bs := make([]bool, nb)
		for i := range bs {
			bs[i] = i&1 != 0
		}
		zs := make([][]byte, nz)
		for i := range zs {
			zs[i] = []byte{fill}
		}
		proof, err := UnmarshalModProof(ws, xs, as, bs, zs)
		if emptyWS == 0 && len(xs) == PARAM_M && len(as) == PARAM_M &&
			len(bs) == PARAM_M && len(zs) == PARAM_M {
			if err != nil {
				t.Fatalf("UnmarshalModProof rejected a guard-passing shape: %v", err)
			}
			if proof == nil || proof.W == nil {
				t.Fatal("UnmarshalModProof must return a populated proof on valid input")
			}
			return
		}
		if err == nil {
			t.Fatalf("UnmarshalModProof accepted a guard-violating shape: wsEmpty=%v xs=%d as=%d bs=%d zs=%d",
				emptyWS != 0, len(xs), len(as), len(bs), len(zs))
		}
	})
}
