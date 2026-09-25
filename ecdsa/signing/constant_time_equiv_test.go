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

	// Reachable production case: round_4 accumulates theta mod N via modN.Add, so the
	// value actually passed to ModInverseCT is already in [0, N); the only reachable
	// non-coprime value is 0 (a multiple of N), not N itself.
	ctInv0 := ctModN.ModInverseCT(new(big.Int))
	stdInv0 := new(big.Int).ModInverse(new(big.Int), N)
	assert.Nil(t, ctInv0, "ModInverseCT(0) should return nil (0 is not invertible)")
	assert.Nil(t, stdInv0, "ModInverse(0) should return nil (0 is not invertible)")
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

	// rx >= N case: production rx = R.X() is a field coordinate in [0, p-1] where
	// p (the field prime) can exceed the curve order N, so rx may be out of range
	// mod N. Both the CT and non-CT paths reduce rx mod N before multiplying; pin
	// that equivalence for an out-of-range rx so a future asymmetric change to the
	// reduction cannot silently break CT/non-CT agreement.
	p := tss.EC().Params().P
	// rxOver >= N; clamp to p if N+rx would reach p (still an out-of-range value).
	rxOver := new(big.Int).Add(N, rx)
	if rxOver.Cmp(p) >= 0 {
		rxOver = new(big.Int).Set(p)
	}
	ctRxOver := ctModN.MulCT(rxOver, sigma)
	expectedRxOver := new(big.Int).Mod(new(big.Int).Mul(rxOver, sigma), N)
	assert.True(t, ctRxOver.Cmp(expectedRxOver) == 0,
		"MulCT(rx, sigma) must equal rx*sigma mod N even when rx >= N")
}
