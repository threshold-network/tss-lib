// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// TestProveBobRejectsOutOfDomainWitnesses pins the exported Bob prover guard:
// x must sit in the curve-order domain and y in the Paillier plaintext
// domain; negative or over-wide witnesses must return an error (no panic)
// under both CT settings, through both the with-check and without-check
// constructors. The historical y < N path stays valid, so the boundary
// witness y = N-1 keeps proving.
func TestProveBobRejectsOutOfDomainWitnesses(t *testing.T) {
	key := mtaFixtureKey(t)
	pk := &key.PublicKey
	NTilde, h1, h2, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	require.NoError(t, err)
	ec := tss.EC()

	x := big.NewInt(7)
	r := firstSmallUnit(pk.N, 2)
	c1 := fixedPaillierEncryption(pk, big.NewInt(5), firstSmallUnit(pk.N, 3))
	// A real with-check point, used for the historical positive control below.
	X := crypto.ScalarBaseMult(ec, x)

	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("CT=%t", enabled), func(t *testing.T) {
			setMTAProofTestMode(t, enabled)
			q := ec.Params().N
			// Invalid x (negative or ≥ q) must error, not panic, in both
			// the without-check and with-check constructors.
			for _, wx := range []*big.Int{big.NewInt(-1), q, new(big.Int).Set(pk.N)} {
				assert.NotPanics(t, func() {
					p, e := ProveBob(ec, pk, NTilde, h1, h2, c1, c1, wx, big.NewInt(3), r)
					assert.Error(t, e)
					assert.Nil(t, p)
				})
				assert.NotPanics(t, func() {
					p, e := ProveBobWC(ec, pk, NTilde, h1, h2, c1, c1, wx, big.NewInt(3), r, X)
					assert.Error(t, e)
					assert.Nil(t, p)
				})
			}
			// Invalid y (negative or ≥ N) must error, not panic, in both
			// the without-check and with-check constructors.
			for _, wy := range []*big.Int{big.NewInt(-1), new(big.Int).Set(pk.N), new(big.Int).Add(pk.N, one)} {
				assert.NotPanics(t, func() {
					p, e := ProveBob(ec, pk, NTilde, h1, h2, c1, c1, big.NewInt(3), wy, r)
					assert.Error(t, e)
					assert.Nil(t, p)
				})
				assert.NotPanics(t, func() {
					p, e := ProveBobWC(ec, pk, NTilde, h1, h2, c1, c1, big.NewInt(3), wy, r, X)
					assert.Error(t, e)
					assert.Nil(t, p)
				})
			}
			// The top of the Paillier domain is a valid historical witness: a
			// with-check proof at y = N-1 must verify under the widened
			// historical bound selected by the compatibility entry point.
			histY := new(big.Int).Sub(pk.N, one)
			histC2 := c2ForWitness(t, ec, pk, c1, x, histY, r)
			pf, e := ProveBobWC(ec, pk, NTilde, h1, h2, c1, histC2, x, histY, r, X)
			require.NoError(t, e)
			require.NotNil(t, pf)
			assert.True(t, pf.VerifyLegacy(ec, pk, NTilde, h1, h2, c1, histC2, X, true), "historical y=N-1 WC proof must verify under the widened bound")
		})
	}
}

// TestProveRangeAliceRejectsOutOfDomainWitness pins the exported Alice prover
// guard: a negative or over-wide m must return an error (no panic) under both
// CT settings. The boundary m = N-1 is not a valid range-proof witness, so
// the positive control instead proves a curve-domain message and verifies the
// returned proof with the production verifier.
func TestProveRangeAliceRejectsOutOfDomainWitness(t *testing.T) {
	key := mtaFixtureKey(t)
	pk := &key.PublicKey
	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	require.NoError(t, err)
	ec := tss.EC()

	// Tiny auxiliary modulus used only for the invalid-witness rejection
	// subtests; its ciphertext is independent of the Paillier plaintext domain.
	NTilde, h1, h2 := big.NewInt(11*23), big.NewInt(4), big.NewInt(9)
	r := big.NewInt(2)
	modN2 := common.ModInt(pk.NSquare())
	c := modN2.Mul(modN2.Exp(pk.Gamma(), big.NewInt(5)), modN2.Exp(r, pk.N))

	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("CT=%t", enabled), func(t *testing.T) {
			setMTAProofTestMode(t, enabled)
			q := ec.Params().N
			// Negative or curve-external m must error, not panic.
			for _, m := range []*big.Int{big.NewInt(-1), q, new(big.Int).Set(pk.N), new(big.Int).Add(pk.N, one)} {
				assert.NotPanics(t, func() {
					p, e := ProveRangeAlice(ec, pk, c, NTilde, h1, h2, m, r)
					assert.Error(t, e)
					assert.Nil(t, p)
				})
			}
			// A curve-domain message is an honest range-proof witness: the
			// generated proof must verify against the production auxiliary
			// modulus under the Paillier key.
			m := common.GetRandomPositiveInt(ec.Params().N)
			require.True(t, m.Cmp(pk.N) < 0, "curve-order message must fit the Paillier plaintext domain")
			cMsg, rMsg, e := key.EncryptAndReturnRandomness(m)
			require.NoError(t, e)
			pf, e := ProveRangeAlice(ec, pk, cMsg, NTildei, h1i, h2i, m, rMsg)
			require.NoError(t, e)
			require.NotNil(t, pf)
			assert.True(t, pf.Verify(ec, pk, NTildei, h1i, h2i, cMsg), "honest Alice range proof must verify")
		})
	}
}

// TestBobVerifiersRejectNilInputs pins the malformed-input guard of the shared
// Bob/BobWC verifier: a nil curve, key, or modulus must return false (no
// panic), even when historicalBobCompat=true would otherwise derive the
// widened bound from those same inputs. Each nil field is exercised in
// isolation against an otherwise-valid surrounding context.
func TestBobVerifiersRejectNilInputs(t *testing.T) {
	key := mtaFixtureKey(t)
	pk := &key.PublicKey
	NTilde, h1, h2, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	require.NoError(t, err)
	ec := tss.EC()

	r := firstSmallUnit(pk.N, 2)
	c1 := fixedPaillierEncryption(pk, big.NewInt(5), firstSmallUnit(pk.N, 3))
	c2 := c2ForWitness(t, ec, pk, c1, big.NewInt(3), big.NewInt(7), r)
	// A valid with-check proof provides the surrounding context.
	X := crypto.ScalarBaseMult(ec, big.NewInt(3))
	pf, e := ProveBobWC(ec, pk, NTilde, h1, h2, c1, c2, big.NewInt(3), big.NewInt(7), r, X)
	require.NoError(t, e)
	require.NotNil(t, pf)
	assert.True(t, pf.Verify(ec, pk, NTilde, h1, h2, c1, c2, X), "control: valid proof must verify before nilning inputs")

	// Nil each input individually, keeping the others valid.
	assert.NotPanics(t, func() {
		assert.False(t, pf.VerifyLegacy(nil, pk, NTilde, h1, h2, c1, c2, X, true))
	})
	assert.NotPanics(t, func() {
		assert.False(t, pf.VerifyLegacy(ec, nil, NTilde, h1, h2, c1, c2, X, true))
	})
	assert.NotPanics(t, func() {
		assert.False(t, pf.VerifyLegacy(ec, pk, nil, h1, h2, c1, c2, X, true))
	})
	assert.NotPanics(t, func() {
		assert.False(t, pf.Verify(ec, pk, nil, h1, h2, c1, c2, X))
	})
}
