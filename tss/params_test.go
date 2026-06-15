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
	pIDs := GenerateTestPartyIDs(2)
	params := NewParameters(S256(), NewPeerContext(pIDs), pIDs[0], len(pIDs), 1)
	nonce := big.NewInt(42)

	params.SetSessionNonce(nonce)
	nonce.SetInt64(7)

	assert.Equal(t, big.NewInt(42), params.SessionNonce())
}

func TestSetSessionNonceBytesHashesSessionID(t *testing.T) {
	pIDs := GenerateTestPartyIDs(2)
	params := NewParameters(S256(), NewPeerContext(pIDs), pIDs[0], len(pIDs), 1)
	sessionID := []byte("session-1-with-128-bits")

	params.SetSessionNonceBytes(sessionID)

	expected := new(big.Int).SetBytes(common.SHA512_256(sessionID))
	assert.Equal(t, expected, params.SessionNonce())
}

func TestSetSessionNonceBytesRejectsShortSessionID(t *testing.T) {
	pIDs := GenerateTestPartyIDs(2)
	params := NewParameters(S256(), NewPeerContext(pIDs), pIDs[0], len(pIDs), 1)

	assert.Panics(t, func() {
		params.SetSessionNonceBytes(nil)
	})
	assert.Panics(t, func() {
		params.SetSessionNonceBytes([]byte{})
	})
	assert.Panics(t, func() {
		params.SetSessionNonceBytes([]byte("short-session"))
	})
}

func TestSetSessionNonceRejectsNonPositiveNonce(t *testing.T) {
	pIDs := GenerateTestPartyIDs(2)
	params := NewParameters(S256(), NewPeerContext(pIDs), pIDs[0], len(pIDs), 1)

	assert.Panics(t, func() {
		params.SetSessionNonce(nil)
	})
	assert.Panics(t, func() {
		params.SetSessionNonce(big.NewInt(0))
	})
	assert.Panics(t, func() {
		params.SetSessionNonce(big.NewInt(-1))
	})
}

func TestNewParametersRejectsInvalidThresholdBounds(t *testing.T) {
	pIDs := GenerateTestPartyIDs(2)
	ctx := NewPeerContext(pIDs)

	assert.Panics(t, func() {
		NewParameters(S256(), ctx, pIDs[0], 1, 1)
	})
	assert.Panics(t, func() {
		NewParameters(S256(), ctx, pIDs[0], len(pIDs), 0)
	})
	assert.Panics(t, func() {
		NewParameters(S256(), ctx, pIDs[0], len(pIDs), len(pIDs))
	})
}

func TestNewParametersRejectsPartyIDCollisionsModQ(t *testing.T) {
	q := S256().Params().N
	pIDs := SortPartyIDs(UnSortedPartyIDs{
		NewPartyID("p0", "p0", big.NewInt(1)),
		NewPartyID("p1", "p1", new(big.Int).Add(q, big.NewInt(1))),
	})

	assert.Panics(t, func() {
		NewParameters(S256(), NewPeerContext(pIDs), pIDs[0], len(pIDs), 1)
	})
}

func TestNewParametersRejectsZeroResiduePartyID(t *testing.T) {
	q := S256().Params().N
	pIDs := SortPartyIDs(UnSortedPartyIDs{
		NewPartyID("p0", "p0", q),
		NewPartyID("p1", "p1", big.NewInt(1)),
	})

	assert.Panics(t, func() {
		NewParameters(S256(), NewPeerContext(pIDs), pIDs[0], len(pIDs), 1)
	})
}

func TestSortPartyIDsRejectsDuplicateKeys(t *testing.T) {
	assert.Panics(t, func() {
		SortPartyIDs(UnSortedPartyIDs{
			NewPartyID("p0", "p0", big.NewInt(1)),
			NewPartyID("p1", "p1", big.NewInt(1)),
		})
	})
}
