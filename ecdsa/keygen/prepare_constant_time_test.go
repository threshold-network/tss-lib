// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"fmt"
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

// TestRingPedersenBeta checks the beta = alpha^-1 mod (p*q) helper that
// GeneratePreParams uses, in both timing modes, against math/big ModInverse.
// The fixture row also checks the stored Beta and the ring-Pedersen
// identity h1 = h2^beta mod NTildei.
func TestRingPedersenBeta(t *testing.T) {
	fixtures, _, err := LoadKeygenTestFixtures(1)
	if err != nil {
		t.Skip("keygen test fixtures are required (avoids safe-prime generation)")
	}
	pp := fixtures[0].LocalPreParams

	// 11 and 23 are Germain primes (23 = 2*11+1, 47 = 2*23+1), so the
	// small rows use the same shape of modulus as the fixture.
	small := struct{ p, q *big.Int }{big.NewInt(11), big.NewInt(23)}
	cases := []struct {
		name         string
		alpha, p, q  *big.Int
		checkFixture bool
	}{
		{"fixture", pp.Alpha, pp.P, pp.Q, true},
		{"alpha = 1", big.NewInt(1), small.p, small.q, false},
		{"alpha = 2", big.NewInt(2), small.p, small.q, false},
		{"alpha = p*q - 1", big.NewInt(11*23 - 1), small.p, small.q, false},
	}

	previousMode := common.IsConstantTimeEnabled()
	t.Cleanup(func() {
		if previousMode {
			common.EnableConstantTimeOps()
		} else {
			common.DisableConstantTimeOps()
		}
	})
	for _, ct := range []bool{false, true} {
		if ct {
			common.EnableConstantTimeOps()
		} else {
			common.DisableConstantTimeOps()
		}
		for _, tc := range cases {
			t.Run(fmt.Sprintf("CT=%t/%s", ct, tc.name), func(t *testing.T) {
				want := new(big.Int).ModInverse(tc.alpha, new(big.Int).Mul(tc.p, tc.q))
				got := ringPedersenBeta(tc.alpha, tc.p, tc.q)
				assert.Zero(t, want.Cmp(got), "beta must match math/big ModInverse")
				if !tc.checkFixture {
					return
				}
				assert.Zero(t, pp.Beta.Cmp(got), "beta must equal the stored fixture Beta")
				// h1 is a square mod NTildei, so ord(h1) divides p*q and
				// h2^beta = h1^(alpha*beta) = h1.
				h1 := common.ModInt(pp.NTildei).Exp(pp.H2i, got)
				assert.Zero(t, pp.H1i.Cmp(h1), "h1 must equal h2^beta mod NTildei")
			})
		}
	}
}
