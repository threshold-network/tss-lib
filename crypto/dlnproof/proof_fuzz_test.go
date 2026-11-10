// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package dlnproof

import "testing"

// capFramedParts bounds the slice counts the fuzzer constructs from its
// uint16 arguments, so a tiny fuzz value cannot amplify into an oversized
// allocation before the decoder runs.
const capFramedParts = 1024

// FuzzUnmarshalDLNProof exercises dlnproof.UnmarshalDLNProof on untrusted
// argument shapes derived from native fuzz primitives.
//
// The fuzz args are the two section counts na and nt, and a fill byte for
// the part payloads. Each generated shape is classified against the
// decoder's guards: exactly Iterations alphas and Iterations ts parts must
// decode to a non-nil proof; any other arity on either side must be
// rejected (category pinned, wording not). The target is cheap (small
// slices only, no key generation) and deterministic, safe under parallel
// fuzz workers.
func FuzzUnmarshalDLNProof(f *testing.F) {
	// Exact arity on both sections.
	f.Add(uint16(Iterations), uint16(Iterations), byte(1))
	// Alphas one part short.
	f.Add(uint16(Iterations-1), uint16(Iterations), byte(1))
	// Ts one part long.
	f.Add(uint16(Iterations), uint16(Iterations+1), byte(1))

	f.Fuzz(func(t *testing.T, na, nt uint16, fill byte) {
		na = min(na, capFramedParts)
		nt = min(nt, capFramedParts)
		alphas := make([][]byte, na)
		for i := range alphas {
			alphas[i] = []byte{fill}
		}
		ts := make([][]byte, nt)
		for i := range ts {
			ts[i] = []byte{fill}
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
