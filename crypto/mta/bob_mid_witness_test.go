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
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// TestBobMidRejectsOutOfRangeWitness pins that Bob's MtA scalar b must be a
// curve-order scalar. b = q and b = -1 must return an error, not a share:
// the constant-time exponent is padded to q's width, so a b outside [0, q)
// must never reach it, and a result for such b would not be a valid share.
func TestBobMidRejectsOutOfRangeWitness(t *testing.T) {
	ec := tss.EC()
	q := ec.Params().N
	_, pk, err := loadPaillierKeyFixture(0)
	require.NoError(t, err)
	NTildeA, h1A, h2A, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	require.NoError(t, err)
	NTildeB, h1B, h2B, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	require.NoError(t, err)
	session := []byte("bob-mid-witness")

	cA, pfA, err := AliceInit(ec, pk, common.GetRandomPositiveInt(q), NTildeB, h1B, h2B, session)
	require.NoError(t, err)
	B := crypto.ScalarBaseMult(ec, big.NewInt(1))

	for name, b := range map[string]*big.Int{
		"b=q":  new(big.Int).Set(q),
		"b=-1": big.NewInt(-1),
	} {
		t.Run(name, func(t *testing.T) {
			_, cB, _, piB, err := BobMid(ec, pk, pfA, b, cA, NTildeA, h1A, h2A, NTildeB, h1B, h2B, session)
			assert.Error(t, err, "BobMid")
			assert.NotErrorIs(t, err, ErrRangeProofVerify, "a local witness error is not a peer proof failure")
			assert.Nil(t, cB)
			assert.Nil(t, piB)

			_, cB, _, piBWC, err := BobMidWC(ec, pk, pfA, b, cA, NTildeA, h1A, h2A, NTildeB, h1B, h2B, B, session)
			assert.Error(t, err, "BobMidWC")
			assert.NotErrorIs(t, err, ErrRangeProofVerify, "a local witness error is not a peer proof failure")
			assert.Nil(t, cB)
			assert.Nil(t, piBWC)
		})
	}
}
