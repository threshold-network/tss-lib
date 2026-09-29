// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import "testing"

// capFramedParts bounds the slice count the fuzzer constructs from its
// uint16 argument, so a tiny fuzz value cannot amplify into an oversized
// allocation before the decoder runs.
const capFramedParts = 1024

// FuzzRangeProofAliceFromBytes exercises mta.RangeProofAliceFromBytes on
// untrusted argument shapes derived from native fuzz primitives.
//
// The fuzz args are the part count n, a fill byte for the part payloads,
// and an emptyAt index (non-zero -> parts[emptyAt-1] is empty). Each
// generated shape is classified against the decoder's guard: exactly
// RangeProofAliceBytesParts non-empty parts must decode to a non-nil proof
// that passes ValidateBasic; any other shape must be rejected (category
// pinned, wording not). The target is cheap (small slices only, no key
// generation) and deterministic, safe under parallel fuzz workers.
func FuzzRangeProofAliceFromBytes(f *testing.F) {
	seed := uint16(RangeProofAliceBytesParts)
	// Exact arity, all parts non-empty.
	f.Add(seed, byte(1), byte(0))
	// One part short.
	f.Add(seed-1, byte(1), byte(0))
	// One part extra.
	f.Add(seed+1, byte(1), byte(0))
	// Interior part emptied.
	f.Add(seed, byte(1), byte(3))

	f.Fuzz(func(t *testing.T, n uint16, fill, emptyAt byte) {
		n = min(n, capFramedParts)
		parts := make([][]byte, n)
		for i := range parts {
			parts[i] = []byte{fill}
		}
		emptyPart := emptyAt != 0 && uint16(emptyAt) <= n
		if emptyPart {
			parts[emptyAt-1] = nil
		}
		pf, err := RangeProofAliceFromBytes(parts)
		if len(parts) == RangeProofAliceBytesParts && !emptyPart {
			if err != nil {
				t.Fatalf("RangeProofAliceFromBytes rejected %d non-empty parts: %v", len(parts), err)
			}
			if !pf.ValidateBasic() {
				t.Fatal("decoded proof must have all six fields set")
			}
			return
		}
		if err == nil {
			t.Fatalf("RangeProofAliceFromBytes accepted %d-part shape: emptyPart=%v, expected rejection", len(parts), emptyPart)
		}
	})
}
