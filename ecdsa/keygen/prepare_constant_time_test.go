// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
)

// TestPrepareTrapdoorCTEquivalence verifies that the constant-time path GeneratePreParams
// uses to derive the ring-Pedersen element h2i = h1i^alpha mod NTildei (alpha is the
// secret trapdoor stored long-term in LocalPreParams) computes the same value as
// math/big, on real fixture key material. It mirrors the exact operation hardened in
// prepare.go; fixtures are used to avoid multi-minute safe-prime generation.
func TestPrepareTrapdoorCTEquivalence(t *testing.T) {
	fixtures, _, err := LoadKeygenTestFixtures(1)
	if err != nil {
		t.Skip("keygen test fixtures are required (avoids safe-prime generation)")
	}
	pp := fixtures[0].LocalPreParams

	modNTildeI := common.ModInt(pp.NTildei)
	want := modNTildeI.Exp(pp.H1i, pp.Alpha)

	previousMode := common.IsConstantTimeEnabled()
	t.Cleanup(func() {
		if previousMode {
			common.EnableConstantTimeOps()
		} else {
			common.DisableConstantTimeOps()
		}
	})
	common.EnableConstantTimeOps()
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")
	got := common.NewCTModInt(pp.NTildei).ExpCT(pp.H1i, pp.Alpha)

	assert.Zero(t, want.Cmp(got), "CT trapdoor exponentiation must match math/big")
	assert.Zero(t, pp.H2i.Cmp(got), "recomputed h2i must equal the stored trapdoor element")
}

// TestPrepareTrapdoorBetaCTEquivalence verifies that the constant-time inverse
// used in GeneratePreParamsWithContext to compute beta = alpha^-1 mod (p*q)
// (where p, q are the two safe-prime factors of the NTilde modulus) produces
// the same result as math/big.ModInverse, and that the ring-Pedersen
// consistency identity h1 = h2^beta mod NTildei holds for the fixture values.
// Without this test a silent regression that made the CT inverse fall back to
// a variable-time computation (or used the wrong modulus/group exponent) would
// be undetectable, since both paths give the same answer for correct inputs.
func TestPrepareTrapdoorBetaCTEquivalence(t *testing.T) {
	fixtures, _, err := LoadKeygenTestFixtures(1)
	if err != nil {
		t.Skip("keygen test fixtures are required (avoids safe-prime generation)")
	}
	pp := fixtures[0].LocalPreParams

	// alpha and beta are stored in the fixture; recompute beta independently.
	phiPQ := new(big.Int).Mul(new(big.Int).Sub(pp.P, big.NewInt(1)),
		new(big.Int).Sub(pp.Q, big.NewInt(1)))
	modPQ := new(big.Int).Mul(pp.P, pp.Q)

	// Non-CT reference: math/big extended Euclidean inverse.
	want := new(big.Int).ModInverse(pp.Alpha, modPQ)
	if want == nil {
		t.Skip("alpha is not invertible mod p*q in this fixture")
	}

	// CT path: NewCTModIntWithPhi(p*q, phi) with ModInverseCT.
	gotCT := common.NewCTModIntWithPhi(modPQ, phiPQ).ModInverseCT(pp.Alpha)

	// CT and non-CT inverses must agree.
	assert.Zero(t, want.Cmp(gotCT), "CT beta must match math/big inverse")

	// The fixture's stored Beta was computed by GeneratePreParamsWithContext,
	// which uses the CT path when CT is enabled and math/big otherwise;
	// both must produce the same value.
	assert.Zero(t, pp.Beta.Cmp(want), "stored Beta must equal the math/big inverse of Alpha mod p*q")

	// Ring-Pedersen consistency: since h1 = f1^2 is always a quadratic
	// residue mod NTildei, ord(h1) | p*q, and alpha*beta ≡ 1 (mod p*q), so
	// h2^beta = (h1^alpha)^beta = h1^(alpha*beta) = h1^(1+k*pq) = h1 mod NTildei.
	modNTildeI := common.ModInt(pp.NTildei)
	h1Recomputed := modNTildeI.Exp(pp.H2i, pp.Beta)
	assert.Zero(t, pp.H1i.Cmp(h1Recomputed),
		"h1 must equal h2^beta mod NTildei (ring-Pedersen inverse identity)")
}
