// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
)

func TestSetSessionNonceCopiesInput(t *testing.T) {
	pIDs := GenerateTestPartyIDs(1)
	params := NewParameters(S256(), NewPeerContext(pIDs), pIDs[0], 1, 0)
	nonce := big.NewInt(42)

	params.SetSessionNonce(nonce)
	nonce.SetInt64(7)

	assert.Equal(t, big.NewInt(42), params.SessionNonce())
}

func TestSetSessionNonceBytesHashesSessionID(t *testing.T) {
	pIDs := GenerateTestPartyIDs(1)
	params := NewParameters(S256(), NewPeerContext(pIDs), pIDs[0], 1, 0)
	sessionID := []byte("session-1")

	params.SetSessionNonceBytes(sessionID)

	expected := new(big.Int).SetBytes(common.SHA512_256(sessionID))
	assert.Equal(t, expected, params.SessionNonce())
}

func TestSetSessionNonceBytesRejectsEmptySessionID(t *testing.T) {
	pIDs := GenerateTestPartyIDs(1)
	params := NewParameters(S256(), NewPeerContext(pIDs), pIDs[0], 1, 0)

	assert.Panics(t, func() {
		params.SetSessionNonceBytes(nil)
	})
	assert.Panics(t, func() {
		params.SetSessionNonceBytes([]byte{})
	})
}
