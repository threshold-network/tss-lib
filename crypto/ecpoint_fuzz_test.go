// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	. "github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/tss"
)

// capECPointGobFuzz bounds the fuzz input before the decoder reserves any
// coordinate buffers, so CI fuzzing cannot amplify arbitrary input into
// oversized big.Int allocations.
const capECPointGobFuzz = 1024

// fataler is the minimal Fatalf interface satisfied by both *testing.T and
// *testing.F, so seed helpers can be shared between the fuzz target and the
// plain tests without panics on a seed failure.
type fataler interface {
	Fatalf(format string, args ...any)
}

// canonicalGobSeed encodes the deterministic secp256k1 point k*G so the
// fuzzer starts in the success region. No key generation or randomness.
func canonicalGobSeed(f fataler, k int64) []byte {
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
func offCurveGobSeed(f fataler) []byte {
	p := NewECPointNoCurveCheck(tss.EC(), tss.EC().Params().P, tss.EC().Params().P)
	bz, err := p.GobEncode()
	if err != nil {
		f.Fatalf("gob encode of off-curve seed failed: %v", err)
	}
	return bz
}

// FuzzECPointGobDecode fuzzes crypto.ECPoint.GobDecode on untrusted bytes.
//
// Contract asserted:
//   - rejection: a failed decode leaves no trusted state — the receiver must
//     not validate as an on-curve, non-identity point after an error;
//   - success invariants: the decoded point satisfies ValidateBasic (on
//     curve, not identity), keeps curve identity (GobDecode pins tss.EC()),
//     and canonical re-encoding + re-decoding reproduces the equal point.
//
// The target is deterministic (only registry reads and fresh allocations)
// and safe under parallel fuzz workers.
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
	// Declared coordinate length beyond the remaining bytes.
	f.Add([]byte{0, 0, 0, 1, 5, 5, 5, 5, 5})

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
		// coordinates must survive (catches swapped, mis-ordered, or
		// sign-flipped coordinate decoding).
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

// TestECPointGobDecodeRejectsMalformedShapes pins the concrete rejection
// categories (truncated stream, off-curve coordinates, empty input) without
// pinning error wording.
func TestECPointGobDecodeRejectsMalformedShapes(t *testing.T) {
	valid := canonicalGobSeed(t, 3)

	if err := (&ECPoint{}).GobDecode(valid[:len(valid)/2]); err == nil {
		t.Fatal("expected truncated coordinate stream to be rejected")
	}
	if err := (&ECPoint{}).GobDecode(offCurveGobSeed(t)); err == nil {
		t.Fatal("expected off-curve coordinates to be rejected")
	}
	if err := (&ECPoint{}).GobDecode(nil); err == nil {
		t.Fatal("expected empty input to be rejected")
	}
	// A successful decode must be semantically valid.
	seed := canonicalGobSeed(t, 5)
	pt := &ECPoint{}
	if err := pt.GobDecode(seed); err != nil {
		t.Fatalf("gob decode of canonical seed failed: %v", err)
	}
	assert.True(t, pt.ValidateBasic(), "decoded point must be on curve and non-identity")
}

// TestECPointGobDecodeRoundtrip pins the success invariant on a
// deterministic canonical seed: encode -> decode -> re-encode -> decode must
// reproduce the equal point on the same curve.
func TestECPointGobDecodeRoundtrip(t *testing.T) {
	seed := canonicalGobSeed(t, 11)
	orig := &ECPoint{}
	require.NoError(t, orig.GobDecode(seed))
	require.True(t, orig.ValidateBasic())

	rebz, err := orig.GobEncode()
	require.NoError(t, err)
	re := &ECPoint{}
	require.NoError(t, re.GobDecode(rebz))
	assert.True(t, orig.Equals(re))
	assert.True(t, SameCurve(re.Curve(), tss.EC()))
}
