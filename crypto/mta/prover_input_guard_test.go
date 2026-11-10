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

	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/tss"
)

// TestProversRejectSamplerWideNTilde pins that a caller-supplied NTilde
// narrower than the 5000-bit sampler cap, but wide enough that q^3*NTilde
// exceeds it, makes the provers return an error. The sampler gives nil for
// that limit; before it did, the sampler panicked out of the exported API.
func TestProversRejectSamplerWideNTilde(t *testing.T) {
	ec := tss.EC()
	one := big.NewInt(1)
	NTilde := new(big.Int).Add(new(big.Int).Lsh(one, 4500), one) // odd, 4501 bits
	pk := &paillier.PublicKey{N: new(big.Int).Add(new(big.Int).Lsh(one, 2047), one)}
	h1, h2 := big.NewInt(4), big.NewInt(9)
	c1, c2 := big.NewInt(2), big.NewInt(3)
	x, y, r := big.NewInt(5), big.NewInt(6), big.NewInt(7)
	X := crypto.ScalarBaseMult(ec, x)

	for name, session := range map[string][][]byte{
		"legacy":  nil,
		"session": {[]byte("prover-input-guard")},
	} {
		t.Run(name, func(t *testing.T) {
			require.NotPanics(t, func() {
				pf, err := ProveBob(ec, pk, NTilde, h1, h2, c1, c2, x, y, r, session...)
				assert.Error(t, err, "ProveBob")
				assert.Nil(t, pf)
			})
			require.NotPanics(t, func() {
				pf, err := ProveBobWC(ec, pk, NTilde, h1, h2, c1, c2, x, y, r, X, session...)
				assert.Error(t, err, "ProveBobWC")
				assert.Nil(t, pf)
			})
			require.NotPanics(t, func() {
				pf, err := ProveRangeAlice(ec, pk, c1, NTilde, h1, h2, x, r, session...)
				assert.Error(t, err, "ProveRangeAlice")
				assert.Nil(t, pf)
			})
		})
	}
}
