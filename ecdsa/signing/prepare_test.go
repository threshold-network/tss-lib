// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/tss"
)

func TestPrepareForSigningPointResults(t *testing.T) {
	ec := tss.S256()
	points := []*crypto.ECPoint{
		crypto.ScalarBaseMult(ec, big.NewInt(1)),
		crypto.ScalarBaseMult(ec, big.NewInt(2)),
	}
	wi, ws, err := PrepareForSigning(ec, 0, 2, big.NewInt(1), []*big.Int{big.NewInt(1), big.NewInt(2)}, points)
	if assert.NoError(t, err) {
		assert.Equal(t, big.NewInt(2), wi)
		assert.True(t, ws[0].Equals(crypto.ScalarBaseMult(ec, big.NewInt(2))))
		minusTwo := new(big.Int).Sub(ec.Params().N, big.NewInt(2))
		assert.True(t, ws[1].Equals(crypto.ScalarBaseMult(ec, minusTwo)))
	}

	wi, ws, err = PrepareForSigning(ec, 0, 2, big.NewInt(1), []*big.Int{big.NewInt(1), big.NewInt(0)}, points)
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), "scalar mult produced a nil point at index 0")
	}
	assert.Nil(t, wi)
	assert.Nil(t, ws)
}
