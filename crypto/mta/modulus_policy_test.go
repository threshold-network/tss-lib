// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// TestMtaModulusPolicy pins the shared unknown-order modulus policy of
// validateVerifierParams (common.IsUsableUnknownOrderModulus: odd, between
// 2048 and MaxUnknownOrderModulusBitLen bits, composite) on all
// three MtA verifier entry points: ProofBob.Verify, ProofBobWC.Verify and
// RangeProofAlice.Verify.
//
// A valid fixture proof is built with the committed keygen fixture, then
// exactly one modulus is swapped at a time. For pk.N the table covers:
//
//   - the fixture value: accepted (positive control);
//   - a 2047-bit odd composite: rejected by the width floor
//     (2047 < MinUnknownOrderModulusBitLen);
//   - a 65537-bit odd composite: rejected by the width ceiling
//     (65537 > MaxUnknownOrderModulusBitLen);
//   - an even 2048-bit value: rejected by the parity check.
//
// For NTilde the same shape is repeated: a 2047-bit odd composite above
// every fixture generator (so the rejection is pinned to the width floor,
// not the canonical-generator width guard), a 65537-bit odd composite,
// and an even 2048-bit value.
//
// The positive control and the swapped rows run in the default timing mode
// only: the shared preamble does not depend on it.
//
// The swapped rows can also be rejected by later checks or equation
// failures, so this table alone does not prove that each Verify calls
// validateVerifierParams. The direct validateVerifierParams assertions
// below pin what the gate checks; TestMtaVerifiersCallSharedGate pins that
// each verifier calls it.
func TestMtaModulusPolicy(t *testing.T) {
	key := mtaFixtureKey(t)
	fixturePk := &key.PublicKey
	NTilde, h1, h2, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	require.NoError(t, err)
	ec := tss.EC()

	// Fixture sanity: the verifiers are exercised on a known-usable pair
	// of unknown-order moduli, so a swapped-modulus rejection is
	// attributable to the swap, not to the fixture.
	require.Equal(t, common.MinUnknownOrderModulusBitLen, fixturePk.N.BitLen(),
		"fixture Paillier modulus must sit at the 2048-bit width floor")
	require.True(t, common.IsUsableUnknownOrderModulus(fixturePk.N, common.MinUnknownOrderModulusBitLen),
		"fixture pk.N must be a usable unknown-order modulus")
	require.True(t, common.IsUsableUnknownOrderModulus(NTilde, common.MinUnknownOrderModulusBitLen),
		"fixture NTilde must be a usable unknown-order modulus")

	// Constructed swap moduli, all deterministic:
	//  - belowFloorN = 3*2^2045+3: 2047 bits, odd, divisible by 3. Only
	//    the width floor rejects it; the canonical-generator and
	//    ciphertext checks still hold for every fixture value against a
	//    2047-bit modulus, so the gate assertion on it pins the floor.
	//  - pastCeiling = 3*2^65535+5: 65537 bits, odd, composite, and
	//    coprime to every fixture generator and ciphertext, so the gate
	//    assertions on it pin the width ceiling.
	//  - evenAtFloor: fixture N-1 (and NTilde-1): even, 2048 bits, so
	//    the parity check rejects them.
	//  - belowFloorTilde = 3*2^2045+1: 2047 bits, odd, composite (2^5+1
	//    divides 2^2045+1), and above every fixture generator and
	//    ciphertext, so the 2047-bit NTilde row is pinned to the width
	//    floor instead of the generator width guard.
	belowFloorN := oddCompositeAt(common.MinUnknownOrderModulusBitLen-1, 3)
	pastCeiling := oddCompositeAt(common.MaxUnknownOrderModulusBitLen+1, 5)
	evenN := new(big.Int).Sub(fixturePk.N, one)
	evenTilde := new(big.Int).Sub(NTilde, one)
	belowFloorTilde := oddCompositeAt(common.MinUnknownOrderModulusBitLen-1, 1)

	require.Equal(t, common.MinUnknownOrderModulusBitLen-1, belowFloorN.BitLen())
	require.Equal(t, common.MaxUnknownOrderModulusBitLen+1, pastCeiling.BitLen())
	require.Equal(t, common.MinUnknownOrderModulusBitLen-1, belowFloorTilde.BitLen())
	require.Equal(t, uint(1), pastCeiling.Bit(0), "past-ceiling swap value must be odd")
	require.Equal(t, uint(1), belowFloorN.Bit(0), "below-floor pk.N swap value must be odd")
	require.Equal(t, uint(1), belowFloorTilde.Bit(0), "below-floor NTilde swap value must be odd")
	require.Equal(t, common.MinUnknownOrderModulusBitLen, evenN.BitLen())
	require.Equal(t, common.MinUnknownOrderModulusBitLen, evenTilde.BitLen())
	require.Zero(t, evenN.Bit(0), "even pk.N swap value must be even")
	require.Zero(t, evenTilde.Bit(0), "even NTilde swap value must be even")

	// The 2047-bit NTilde swap must exceed every value the
	// canonical-generator and ciphertext checks compare against, so
	// those checks pass and the rejection is pinned to the width floor.
	for _, v := range []*big.Int{h1, h2} {
		require.True(t, v.Cmp(belowFloorTilde) < 0, "fixture generator must be narrower than the 2047-bit NTilde swap")
	}

	// The 65537-bit swap must be coprime to every fixture value so the
	// ceiling row cannot be explained by a coincidental shared factor.
	for _, v := range []*big.Int{h1, h2, NTilde} {
		require.Zero(t, new(big.Int).GCD(nil, nil, v, pastCeiling).Cmp(one),
			"fixture value must be coprime to the 65537-bit swap value")
	}

	// Build the valid fixture proofs. x and y are small in-domain
	// witnesses; c2 is the MtA-shaped ciphertext c1^x * G^y * r^N mod N^2.
	// The session-less (legacy) verifier bounds admit these proofs.
	x, y, r := big.NewInt(7), big.NewInt(11), firstSmallUnit(fixturePk.N, 2)
	c1 := fixedPaillierEncryption(fixturePk, big.NewInt(5), firstSmallUnit(fixturePk.N, 3))
	c2 := c2ForWitness(t, ec, fixturePk, c1, x, y, r)
	X := crypto.ScalarBaseMult(ec, x)
	proofBob, err := ProveBob(ec, fixturePk, NTilde, h1, h2, c1, c2, x, y, r)
	require.NoError(t, err)
	proofBobWC, err := ProveBobWC(ec, fixturePk, NTilde, h1, h2, c1, c2, x, y, r, X)
	require.NoError(t, err)
	m, rMsg := big.NewInt(424242), big.NewInt(2)
	cMsg := fixedPaillierEncryption(fixturePk, m, rMsg)
	proofRange, err := ProveRangeAlice(ec, fixturePk, cMsg, NTilde, h1, h2, m, rMsg)
	require.NoError(t, err)

	// Gate pinning on the shared preamble itself, on the same constructed
	// values. The positive control must pass the gate; every swapped row
	// must fail it, so a mutation that removes a gate check from
	// validateVerifierParams turns at least one assertion below red.
	require.True(t, validateVerifierParams(fixturePk, NTilde, h1, h2, c1, c2, cMsg),
		"fixture moduli, generators, and ciphertexts must pass the shared gate")
	require.False(t, validateVerifierParams(&paillier.PublicKey{N: belowFloorN}, NTilde, h1, h2, c1, c2, cMsg),
		"2047-bit pk.N must fail the gate's width floor")
	require.False(t, validateVerifierParams(fixturePk, belowFloorTilde, h1, h2, c1, c2, cMsg),
		"2047-bit NTilde must fail the gate's width floor")
	require.False(t, validateVerifierParams(&paillier.PublicKey{N: pastCeiling}, NTilde, h1, h2, c1, c2, cMsg),
		"65537-bit pk.N must fail the gate's width ceiling")
	require.False(t, validateVerifierParams(fixturePk, pastCeiling, h1, h2, c1, c2, cMsg),
		"65537-bit NTilde must fail the gate's width ceiling")
	require.False(t, validateVerifierParams(&paillier.PublicKey{N: evenN}, NTilde, h1, h2, c1, c2, cMsg),
		"even 2048-bit pk.N must fail the gate's parity check")
	require.False(t, validateVerifierParams(fixturePk, evenTilde, h1, h2, c1, c2, cMsg),
		"even 2048-bit NTilde must fail the gate's parity check")

	type mtaModulusCase struct {
		name   string
		N      *big.Int
		NTilde *big.Int
		want   bool
	}
	// Swap pk.N first, then NTilde. The positive control row (fixture
	// values) must verify on all three verifiers; every swapped value
	// must be rejected.
	cases := []mtaModulusCase{
		{"N_fixture_accepted", fixturePk.N, NTilde, true},
		{"N_odd_composite_2047bit_rejected", belowFloorN, NTilde, false},
		{"N_odd_composite_65537bit_rejected", pastCeiling, NTilde, false},
		{"N_even_2048bit_rejected", evenN, NTilde, false},
		{"NTilde_odd_composite_2047bit_rejected", fixturePk.N, belowFloorTilde, false},
		{"NTilde_odd_composite_65537bit_rejected", fixturePk.N, pastCeiling, false},
		{"NTilde_even_2048bit_rejected", fixturePk.N, evenTilde, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			swpk := &paillier.PublicKey{N: tc.N}
			gotBob := proofBob.Verify(ec, swpk, tc.NTilde, h1, h2, c1, c2)
			assert.Equal(t, tc.want, gotBob, "ProofBob.Verify")
			gotWC := proofBobWC.Verify(ec, swpk, tc.NTilde, h1, h2, c1, c2, X)
			assert.Equal(t, tc.want, gotWC, "ProofBobWC.Verify")
			gotRange := proofRange.Verify(ec, swpk, tc.NTilde, h1, h2, cMsg)
			assert.Equal(t, tc.want, gotRange, "RangeProofAlice.Verify")
		})
	}
}

// oddCompositeAt returns 3*2^(bits-2)+extra: an odd value of exactly bits
// bits. extra = 3 keeps divisibility by 3 (ProbablyPrime rejects it in
// the first round); extra = 5 avoids 3 where coprimality to the fixture
// ciphertexts is needed. No keygen or primality generation is involved.
func oddCompositeAt(bits int, extra int64) *big.Int {
	v := new(big.Int).Lsh(big.NewInt(3), uint(bits-2))
	return new(big.Int).Add(v, big.NewInt(extra))
}

// TestMtaVerifiersCallSharedGate pins that every MtA verifier calls
// validateVerifierParams. The proofs are honest proofs for the generator
// pair (h1, h1), so every response bound and verification equation holds.
// Of all the verifier checks, only the gate rejects equal generators, so a
// verifier that does not call the gate accepts these proofs.
func TestMtaVerifiersCallSharedGate(t *testing.T) {
	key := mtaFixtureKey(t)
	pk := &key.PublicKey
	NTilde, h1, _, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	require.NoError(t, err)
	ec := tss.EC()

	x, y, r := big.NewInt(7), big.NewInt(11), firstSmallUnit(pk.N, 2)
	c1 := fixedPaillierEncryption(pk, big.NewInt(5), firstSmallUnit(pk.N, 3))
	c2 := c2ForWitness(t, ec, pk, c1, x, y, r)
	X := crypto.ScalarBaseMult(ec, x)
	proofBob, err := ProveBob(ec, pk, NTilde, h1, h1, c1, c2, x, y, r)
	require.NoError(t, err)
	proofBobWC, err := ProveBobWC(ec, pk, NTilde, h1, h1, c1, c2, x, y, r, X)
	require.NoError(t, err)
	m, rMsg := big.NewInt(424242), big.NewInt(2)
	cMsg := fixedPaillierEncryption(pk, m, rMsg)
	proofRange, err := ProveRangeAlice(ec, pk, cMsg, NTilde, h1, h1, m, rMsg)
	require.NoError(t, err)

	require.False(t, validateVerifierParams(pk, NTilde, h1, h1, c1, c2, cMsg), "the gate must reject h1 == h2")
	assert.False(t, proofBob.Verify(ec, pk, NTilde, h1, h1, c1, c2), "ProofBob.Verify")
	assert.False(t, proofBob.VerifyLegacy(ec, pk, NTilde, h1, h1, c1, c2, true), "ProofBob.VerifyLegacy")
	assert.False(t, proofBobWC.Verify(ec, pk, NTilde, h1, h1, c1, c2, X), "ProofBobWC.Verify")
	assert.False(t, proofRange.Verify(ec, pk, NTilde, h1, h1, cMsg), "RangeProofAlice.Verify")
}
