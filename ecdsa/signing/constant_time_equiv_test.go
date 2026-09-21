// Copyright © 2019-2026 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code and distribution tree.

package signing

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/tss"
)

// TestRound3TheltaSigmaCTEquivalence verifies that the constant-time
// multiplications in round 3 (thelta = k*gamma, sigma = k*w) produce
// results identical to plain math/big multiplication.
func TestRound3TheltaSigmaCTEquivalence(t *testing.T) {
	N := tss.EC().Params().N
	ctModN := common.NewCTModInt(N)

	k := common.GetRandomPositiveInt(N)
	gamma := common.GetRandomPositiveInt(N)
	w := common.GetRandomPositiveInt(N)

	// thelta = k * gamma mod N
	ctThelta := ctModN.MulCT(k, gamma)
	expectedThelta := new(big.Int).Mod(new(big.Int).Mul(k, gamma), N)
	assert.True(t, ctThelta.Cmp(expectedThelta) == 0,
		"MulCT(k, gamma) should equal k*gamma mod N")

	// sigma = k * w mod N
	ctSigma := ctModN.MulCT(k, w)
	expectedSigma := new(big.Int).Mod(new(big.Int).Mul(k, w), N)
	assert.True(t, ctSigma.Cmp(expectedSigma) == 0,
		"MulCT(k, w) should equal k*w mod N")
}

// TestRound4ThetaInverseCTEquivalence verifies that the constant-time modular
// inverse in round 4 (thetaInverse = theta^-1 mod N) produces results
// identical to math/big.ModInverse for randomly coprime inputs, and that
// both implementations return nil consistently for non-coprime inputs.
func TestRound4ThetaInverseCTEquivalence(t *testing.T) {
	N := tss.EC().Params().N
	ctModN := common.NewCTModInt(N)

	theta := common.GetRandomPositiveInt(N)
	ctInv := ctModN.ModInverseCT(theta)
	stdInv := new(big.Int).ModInverse(theta, N)

	assert.NotNil(t, ctInv, "ModInverseCT should return non-nil for random theta against prime N")
	assert.NotNil(t, stdInv, "ModInverse should return non-nil for random theta against prime N")
	assert.True(t, ctInv.Cmp(stdInv) == 0,
		"MulCT(theta, thetaInverse) should equal theta*theta^-1 mod N")

	// Degenerate case: theta = N is not coprime to N (gcd(N, N) = N ≠ 1),
	// so both implementations must return nil consistently.
	thetaN := new(big.Int).Set(N)
	ctInvN := ctModN.ModInverseCT(thetaN)
	stdInvN := new(big.Int).ModInverse(thetaN, N)
	assert.Nil(t, ctInvN, "ModInverseCT(N) should return nil (N and N are not coprime)")
	assert.Nil(t, stdInvN, "ModInverse(N, N) should return nil (N and N are not coprime)")
}

// TestRound5SiCTEquivalence verifies that the constant-time multiplications
// in round 5 (si = m*k + rx*sigma mod N) produce results identical to plain
// math/big multiplication.
func TestRound5SiCTEquivalence(t *testing.T) {
	N := tss.EC().Params().N
	ctModN := common.NewCTModInt(N)

	m := common.GetRandomPositiveInt(N)
	k := common.GetRandomPositiveInt(N)
	rx := common.GetRandomPositiveInt(N)
	sigma := common.GetRandomPositiveInt(N)

	// m * k mod N
	ctMk := ctModN.MulCT(m, k)
	expectedMk := new(big.Int).Mod(new(big.Int).Mul(m, k), N)
	assert.True(t, ctMk.Cmp(expectedMk) == 0,
		"MulCT(m, k) should equal m*k mod N")

	// rx * sigma mod N
	ctRxSigma := ctModN.MulCT(rx, sigma)
	expectedRxSigma := new(big.Int).Mod(new(big.Int).Mul(rx, sigma), N)
	assert.True(t, ctRxSigma.Cmp(expectedRxSigma) == 0,
		"MulCT(rx, sigma) should equal rx*sigma mod N")
}
