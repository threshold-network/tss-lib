// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss_test

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
)

func expectNamedPanic(t *testing.T, name string, fn func()) {
	t.Helper()
	defer func() {
		value := recover()
		if assert.NotNil(t, value) {
			assert.Contains(t, fmt.Sprint(value), name)
		}
	}()
	fn()
}

func TestPartyIDInputGuards(t *testing.T) {
	var missingContent tss.PartyID
	if err := json.Unmarshal([]byte(`{"index":0}`), &missingContent); err != nil {
		t.Fatal(err)
	}
	for _, id := range []*tss.PartyID{nil, &missingContent} {
		assert.False(t, id.ValidateBasic())
		expectNamedPanic(t, "SortPartyIDs:", func() {
			tss.SortPartyIDs(tss.UnSortedPartyIDs{id})
		})
		expectNamedPanic(t, "SortedPartyIDs.Keys:", func() {
			tss.SortedPartyIDs{id}.Keys()
		})
	}
	assert.Equal(t, "{0,<no PartyID content>}", missingContent.String())

	ids := tss.SortPartyIDs(tss.UnSortedPartyIDs{
		tss.NewPartyID("b", "bob", big.NewInt(2)),
		tss.NewPartyID("a", "alice", big.NewInt(1)),
	})
	assert.True(t, ids[0].ValidateBasic())
	assert.Equal(t, "{0,P[alice]}", ids[0].String())
	assert.Equal(t, []*big.Int{big.NewInt(1), big.NewInt(2)}, ids.Keys())

	// A present wrapper with a nil key retains its existing integer-zero
	// representation in key access and is skipped by parameter validation.
	nilKey := &tss.PartyID{MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{}, Index: 0}
	assert.False(t, nilKey.ValidateBasic())
	assert.Equal(t, []*big.Int{big.NewInt(0)}, tss.SortPartyIDs(tss.UnSortedPartyIDs{nilKey}).Keys())
	ctx := tss.NewPeerContext(tss.SortedPartyIDs{nil, &missingContent, nilKey, ids[0], ids[1]})
	assert.NotPanics(t, func() { tss.NewParameters(tss.S256(), ctx, ids[0], 2, 1) })

	nilKey.Key = []byte{}
	assert.True(t, nilKey.ValidateBasic(), "a non-nil empty key retains its validation behavior")
}

func TestPeerContextIDs(t *testing.T) {
	var absent *tss.PeerContext
	assert.Nil(t, absent.IDs())
	ids := tss.SortPartyIDs(tss.UnSortedPartyIDs{tss.NewPartyID("a", "alice", big.NewInt(1))})
	assert.Equal(t, ids, tss.NewPeerContext(ids).IDs())
}

func TestMessageRoutingInputGuards(t *testing.T) {
	ids := tss.SortPartyIDs(tss.UnSortedPartyIDs{
		tss.NewPartyID("a", "alice", big.NewInt(1)),
		tss.NewPartyID("b", "bob", big.NewInt(2)),
	})
	content := &signing.SignRound3Message{Theta: []byte{1}}
	for _, id := range []*tss.PartyID{nil, {Index: 0}} {
		parsed, err := tss.ParseWireMessage(nil, id, true)
		assert.Nil(t, parsed)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "missing sender PartyID content")
		}
		expectNamedPanic(t, "routing.From", func() {
			tss.NewMessageWrapper(tss.MessageRouting{From: id}, content)
		})
		expectNamedPanic(t, "routing.To[0]", func() {
			tss.NewMessageWrapper(tss.MessageRouting{From: ids[0], To: []*tss.PartyID{id}}, content)
		})
	}

	routing := tss.MessageRouting{From: ids[0], To: []*tss.PartyID{ids[1]}}
	wrapper := tss.NewMessageWrapper(routing, content)
	assert.Equal(t, ids[0].MessageWrapper_PartyID, wrapper.From)
	assert.Equal(t, []*tss.MessageWrapper_PartyID{ids[1].MessageWrapper_PartyID}, wrapper.To)
	message := signing.NewSignRound3Message(ids[0], big.NewInt(1))
	wire, _, err := message.WireBytes()
	if !assert.NoError(t, err) {
		return
	}
	parsed, err := tss.ParseWireMessage(wire, ids[0], true)
	if assert.NoError(t, err) {
		assert.True(t, parsed.ValidateBasic())
		assert.True(t, tss.IsSameMessage(message, parsed))
	}
	_, err = tss.ParseWireMessage(wire, &tss.PartyID{MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{}}, true)
	assert.NoError(t, err, "parsing does not otherwise tighten sender validation")
}
