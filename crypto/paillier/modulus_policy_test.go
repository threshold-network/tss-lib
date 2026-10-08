// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package paillier

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/tss"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oddCompositeAtBits deterministically builds an odd composite of exactly
// bitLen bits: 3*2^(bitLen-2)+3 is odd and divisible by 3, so the
// ProbablyPrime rounds inside common.IsUsableUnknownOrderModulus reject it
// via small-prime trial division — no safe-prime or Paillier key
// generation is needed.
func oddCompositeAtBits(bitLen int) *big.Int {
	n := new(big.Int).Lsh(big.NewInt(3), uint(bitLen-2))
	n.Add(n, big.NewInt(3))
	return n
}

// evenAtBits returns an even value of exactly bitLen bits: 2^(bitLen-1).
func evenAtBits(bitLen int) *big.Int {
	return new(big.Int).Lsh(big.NewInt(1), uint(bitLen-1))
}

// hasWidthPolicyError reports whether err is one of the shared
// width-policy rejections FactorVerify returns: the usability
// floor/ceiling/parity/composite check ("invalid Paillier modulus" /
// "invalid auxiliary modulus"). A width-
// valid 2048-bit odd composite is rejected downstream (generators,
// equations), so a negative assert against this helper proves the width
// policy itself did not fire.
func hasWidthPolicyError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "invalid Paillier modulus") ||
		strings.Contains(msg, "invalid auxiliary modulus")
}

// TestFactorVerifyModulusPolicySwaps pins the shared width policy on
// FactorVerify: on a valid fixture proof, only one modulus argument — the
// Paillier pkN or the auxiliary N, separately — is swapped. The fixture
// moduli are the positive control. A 2048-bit odd composite is
// width-valid: its rejection must come from a downstream generator or
// equation check, not the width policy. A 2047-bit odd composite is below
// the width floor, a 65537-bit odd composite is one past the shared
// ceiling, and even values fail parity. Removing a width call changes which
// error text is returned (or drops the error entirely), failing the
// matching assertion.
func TestFactorVerifyModulusPolicySwaps(t *testing.T) {
	facSetUp(t)

	// errSubstr pins the rejection to the exact policy call that must fire.
	// Empty errSubstr means the swapped modulus is width-valid, so
	// FactorVerify must let it through the width policy and reject it at a
	// downstream check instead.
	cases := []struct {
		name      string
		pkN, N    *big.Int
		accepted  bool
		errSubstr string
	}{
		{
			name:     "fixture_modulus_accepted",
			pkN:      publicKey.N,
			N:        auxPrime.N,
			accepted: true,
		},
		{
			name:      "paillier_2047bit_odd_composite_rejected",
			pkN:       oddCompositeAtBits(common.MinUnknownOrderModulusBitLen - 1),
			N:         auxPrime.N,
			errSubstr: "invalid Paillier modulus",
		},
		{
			name: "paillier_2048bit_odd_composite_width_valid",
			pkN:  oddCompositeAtBits(common.MinUnknownOrderModulusBitLen),
			N:    auxPrime.N,
		},
		{
			name:      "paillier_65537bit_odd_composite_rejected",
			pkN:       oddCompositeAtBits(common.MaxUnknownOrderModulusBitLen + 1),
			N:         auxPrime.N,
			errSubstr: "invalid Paillier modulus",
		},
		{
			name:      "paillier_even_rejected",
			pkN:       evenAtBits(common.MinUnknownOrderModulusBitLen),
			N:         auxPrime.N,
			errSubstr: "invalid Paillier modulus",
		},
		{
			name:      "aux_2047bit_odd_composite_rejected",
			pkN:       publicKey.N,
			N:         oddCompositeAtBits(common.MinUnknownOrderModulusBitLen - 1),
			errSubstr: "invalid auxiliary modulus",
		},
		{
			name: "aux_2048bit_odd_composite_width_valid",
			pkN:  publicKey.N,
			N:    oddCompositeAtBits(common.MinUnknownOrderModulusBitLen),
		},
		{
			name:      "aux_65537bit_odd_composite_rejected",
			pkN:       publicKey.N,
			N:         oddCompositeAtBits(common.MaxUnknownOrderModulusBitLen + 1),
			errSubstr: "invalid auxiliary modulus",
		},
		{
			name:      "aux_even_rejected",
			pkN:       publicKey.N,
			N:         evenAtBits(common.MinUnknownOrderModulusBitLen),
			errSubstr: "invalid auxiliary modulus",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proof := privateKey.FactorProof(auxPrime.N, s, tt)
			res, err := proof.FactorVerify(tc.pkN, tc.N, s, tt)

			if tc.accepted {
				assert.NoError(t, err)
				assert.True(t, res, "fixture proof must verify under the fixture moduli")
				return
			}

			assert.Error(t, err, "swapped modulus must be rejected")
			assert.False(t, res, "swapped modulus must not verify")
			if tc.errSubstr != "" {
				assert.Contains(t, err.Error(), tc.errSubstr,
					"rejection must come from the expected width-policy call")
				return
			}
			assert.False(t, hasWidthPolicyError(err),
				"2048-bit odd composite is width-valid; rejection must not be a width-policy error: %v", err)
		})
	}
}

// TestProofVerifyModulusPolicySwaps pins the shared width policy on
// Proof.Verify: on a valid fixture proof, only pkN is swapped.
// Proof.Verify signals every rejection — width policy included — as a
// plain `false` with a nil error (its error return is reserved for a
// malformed xs generation), so rejected swaps are asserted on `false`
// alone and the fixture modulus is the positive control.
func TestProofVerifyModulusPolicySwaps(t *testing.T) {
	setUp(t)
	require.NotNil(t, privateKey)
	require.NotNil(t, publicKey)

	ki := common.MustGetRandomInt(256) // index
	ui := common.GetRandomPositiveInt(tss.EC().Params().N)
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())
	ecdsaPub := crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY)

	cases := []struct {
		name     string
		pkN      *big.Int
		accepted bool
	}{
		{
			name:     "fixture_modulus_accepted",
			pkN:      publicKey.N,
			accepted: true,
		},
		{
			name: "2047bit_odd_composite_rejected",
			pkN:  oddCompositeAtBits(common.MinUnknownOrderModulusBitLen - 1),
		},
		{
			// Width-valid composite: the width policy does not reject it;
			// a proof built under the fixture modulus simply cannot
			// verify under a different modulus.
			name: "2048bit_odd_composite_rejected_by_equation",
			pkN:  oddCompositeAtBits(common.MinUnknownOrderModulusBitLen),
		},
		{
			name: "65537bit_odd_composite_rejected",
			pkN:  oddCompositeAtBits(common.MaxUnknownOrderModulusBitLen + 1),
		},
		{
			name: "even_rejected",
			pkN:  evenAtBits(common.MinUnknownOrderModulusBitLen),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proof := privateKey.Proof(ki, ecdsaPub)
			res, err := proof.Verify(tc.pkN, ki, ecdsaPub)
			assert.NoError(t, err)
			assert.Equal(t, tc.accepted, res,
				"swapped modulus %s: verify result mismatch", tc.name)
		})
	}
}

// factorVerifyBounds recomputes the verifier-side absolute-value limits
// FactorVerify enforces on the responses Z1/Z2/W1/W2/Sigma/V — the same
// expressions as FactorVerify's body — for the fixture key pairs.
func factorVerifyBounds() map[string]*big.Int {
	one := big.NewInt(1)

	zLimit := new(big.Int).Lsh(one, PARAM_L+PARAM_E)
	zLimit.Mul(zLimit, new(big.Int).Sqrt(publicKey.N))

	q := new(big.Int).Lsh(one, PARAM_L)
	q3 := new(big.Int).Mul(q, q)
	q3.Mul(q3, q)
	qN := new(big.Int).Mul(q, auxPrime.N)
	qPkNN := new(big.Int).Mul(qN, publicKey.N)
	q3N := new(big.Int).Mul(q3, auxPrime.N)
	q3PkNN := new(big.Int).Mul(q3N, publicKey.N)
	limitW := new(big.Int).Lsh(q3N, 1)
	limitV := new(big.Int).Lsh(q3PkNN, 2)

	return map[string]*big.Int{
		"Z1":    zLimit,
		"Z2":    zLimit,
		"W1":    limitW,
		"W2":    limitW,
		"Sigma": qPkNN,
		"V":     limitV,
	}
}

// setFactorProofField copies the proof struct and replaces exactly one
// response field, leaving every other field unchanged.
func setFactorProofField(proof *FactorProof, name string, value *big.Int) FactorProof {
	p := *proof
	switch name {
	case "Z1":
		p.Z1 = value
	case "Z2":
		p.Z2 = value
	case "W1":
		p.W1 = value
	case "W2":
		p.W2 = value
	case "Sigma":
		p.Sigma = value
	case "V":
		p.V = value
	}
	return p
}

// TestFactorVerifyRejectsResponsesOnePastBound pins the cheap response DoS
// bounds in FactorVerify: a valid fixture proof with exactly one response
// replaced by its verifier bound plus one is rejected by that bound check
// itself — before any modular exponentiation — with the specific
// "exceeds limit" error naming that bound, while the unmutated proof still
// verifies. Removing the bound call or off-by-one-ing the CmpAbs
// comparison makes the matching case fail.
func TestFactorVerifyRejectsResponsesOnePastBound(t *testing.T) {
	facSetUp(t)

	bounds := factorVerifyBounds()
	over := make(map[string]*big.Int, len(bounds))
	for name, bound := range bounds {
		over[name] = new(big.Int).Add(bound, big.NewInt(1))
	}

	for _, name := range []string{"Z1", "Z2", "W1", "W2", "Sigma", "V"} {
		t.Run(name, func(t *testing.T) {
			proof := privateKey.FactorProof(auxPrime.N, s, tt)

			// Control: the unmutated proof verifies.
			res, err := proof.FactorVerify(publicKey.N, auxPrime.N, s, tt)
			assert.NoError(t, err)
			assert.True(t, res, "unmutated fixture proof must still verify")

			mutated := setFactorProofField(proof, name, over[name])
			res, err = mutated.FactorVerify(publicKey.N, auxPrime.N, s, tt)
			assert.Error(t, err)
			assert.False(t, res)
			assert.Contains(t, err.Error(), "exceeds limit",
				"rejection must come from the response bound check")
			assert.Contains(t, err.Error(), fmt.Sprintf("%x", bounds[name]),
				"the reported bound must be the one enforced for "+name)
		})
	}
}

// TestFactorVerifyResponseAtLimitNotRejectedByBound pins the inclusive
// bound semantics: a response exactly at the limit must pass the bound
// check (CmpAbs > 0, not >= 0) and fail at a later verification equation
// instead. This catches an off-by-one regression of the bound comparison
// that the one-past-bound test would miss.
func TestFactorVerifyResponseAtLimitNotRejectedByBound(t *testing.T) {
	facSetUp(t)

	bounds := factorVerifyBounds()

	proof := privateKey.FactorProof(auxPrime.N, s, tt)
	mutated := setFactorProofField(proof, "Z1", bounds["Z1"])

	res, err := mutated.FactorVerify(publicKey.N, auxPrime.N, s, tt)
	assert.Error(t, err)
	assert.False(t, res)
	assert.NotContains(t, err.Error(), "exceeds limit",
		"a response exactly at the inclusive limit must not trip the bound check")
}
