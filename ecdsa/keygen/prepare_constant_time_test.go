// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
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

	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")
	got := common.NewCTModInt(pp.NTildei).ExpCT(pp.H1i, pp.Alpha)

	assert.Zero(t, want.Cmp(got), "CT trapdoor exponentiation must match math/big")
	assert.Zero(t, pp.H2i.Cmp(got), "recomputed h2i must equal the stored trapdoor element")
}
