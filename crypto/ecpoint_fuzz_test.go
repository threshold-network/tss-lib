// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto_test

import (
	"math/big"
	"testing"

	. "github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/tss"
)

// capECPointGobFuzz bounds the fuzz input before the decoder reserves any
// coordinate buffers, so CI fuzzing cannot amplify arbitrary input into
// oversized big.Int allocations.
const capECPointGobFuzz = 1024

// canonicalGobSeed encodes the deterministic secp256k1 point k*G so the
// fuzzer starts in the success region. No key generation or randomness.
func canonicalGobSeed(f *testing.F, k int64) []byte {
	p := ScalarBaseMult(tss.EC(), big.NewInt(k))
	if p == nil {
		f.Fatalf("k*G must be non-nil for k >= 1")
	}
	bz, err := p.GobEncode()
	if err != nil {
		f.Fatalf("gob encode of canonical seed failed: %v", err)
	}
	return bz
}

// offCurveGobSeed builds a structurally valid encode of coordinates that are
// off the curve: both coordinates equal the prime P and fail the x,y < P
// range check before any curve arithmetic. Deterministic rejection seed.
func offCurveGobSeed(f *testing.F) []byte {
	p := NewECPointNoCurveCheck(tss.EC(), tss.EC().Params().P, tss.EC().Params().P)
	bz, err := p.GobEncode()
	if err != nil {
		f.Fatalf("gob encode of off-curve seed failed: %v", err)
	}
	return bz
}

// FuzzECPointGobDecode fuzzes crypto.ECPoint.GobDecode on untrusted bytes.
//
// A failed decode must leave no trusted state: the receiver must not
// validate as an on-curve point after an error. A successful decode must
// satisfy ValidateBasic, keep curve identity (GobDecode pins tss.EC()),
// and a canonical re-encode + re-decode must reproduce the equal point on
// the same curve. The target is deterministic (only registry reads and
// fresh allocations) and safe under parallel fuzz workers.
func FuzzECPointGobDecode(f *testing.F) {
	valid := canonicalGobSeed(f, 1)
	f.Add(valid)
	f.Add(canonicalGobSeed(f, 7))
	// Truncated coordinate stream.
	f.Add(valid[:len(valid)/2])
	// Structurally valid encode of off-curve coordinates.
	f.Add(offCurveGobSeed(f))
	// Empty input.
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > capECPointGobFuzz {
			return
		}
		pt := &ECPoint{}
		err := pt.GobDecode(data)
		if err != nil {
			if pt.ValidateBasic() {
				t.Fatal("GobDecode errored but left a point that validates as on-curve")
			}
			return
		}
		if !pt.ValidateBasic() {
			t.Fatal("decoded point failed ValidateBasic")
		}
		if !SameCurve(pt.Curve(), tss.EC()) {
			t.Fatal("decoded point lost curve identity")
		}
		// Round-trip: re-encode the decoded point, decode again, and the
		// point must survive (catches swapped, mis-ordered, or sign-flipped
		// coordinate decoding).
		bz, err := pt.GobEncode()
		if err != nil {
			t.Fatalf("re-encode of decoded point failed: %v", err)
		}
		rt := &ECPoint{}
		if err := rt.GobDecode(bz); err != nil {
			t.Fatalf("re-decode of re-encoded point failed: %v", err)
		}
		if !pt.Equals(rt) || !SameCurve(rt.Curve(), tss.EC()) {
			t.Fatal("gob round-trip changed coordinates or curve")
		}
	})
}
