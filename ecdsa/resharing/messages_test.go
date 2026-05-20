// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"math/big"
	"strings"
	"testing"

	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// TestDGRound1Message_ValidateBasic_RequiresSsid pins the wire-format
// invariant that the SSID field must be present on every DGRound1Message.
// Without this, an attacker could strip the SSID from a broadcast and the
// new-committee cross-verification check in round 1 would silently never
// fire (the message would be rejected for other reasons or accepted with an
// empty SSID, both of which mask the disagreement-detection mechanism the
// SSID-on-the-wire was added for).
func TestDGRound1Message_ValidateBasic_RequiresSsid(t *testing.T) {
	withSsid := &DGRound1Message{
		EcdsaPubX:   []byte{0x01},
		EcdsaPubY:   []byte{0x02},
		VCommitment: []byte{0x03},
		Ssid:        make([]byte, 32),
	}
	if !withSsid.ValidateBasic() {
		t.Fatal("ValidateBasic must accept a complete DGRound1Message")
	}

	missingSsid := &DGRound1Message{
		EcdsaPubX:   []byte{0x01},
		EcdsaPubY:   []byte{0x02},
		VCommitment: []byte{0x03},
		// Ssid intentionally omitted
	}
	if missingSsid.ValidateBasic() {
		t.Fatal("ValidateBasic must reject a DGRound1Message with empty Ssid")
	}

	emptySsid := &DGRound1Message{
		EcdsaPubX:   []byte{0x01},
		EcdsaPubY:   []byte{0x02},
		VCommitment: []byte{0x03},
		Ssid:        []byte{},
	}
	if emptySsid.ValidateBasic() {
		t.Fatal("ValidateBasic must reject a DGRound1Message with zero-length Ssid")
	}

	shortSsid := &DGRound1Message{
		EcdsaPubX:   []byte{0x01},
		EcdsaPubY:   []byte{0x02},
		VCommitment: []byte{0x03},
		Ssid:        []byte("short-ssid"),
	}
	if shortSsid.ValidateBasic() {
		t.Fatal("ValidateBasic must reject a DGRound1Message with short Ssid")
	}
}

// TestRound1Update_RejectsMismatchedSsidBeforePartyZero pins that every old
// committee broadcast is SSID-checked before being marked accepted. In
// particular, old party j>0 may arrive before old party 0; that ordering must
// not bypass the SSID mismatch check.
func TestRound1Update_RejectsMismatchedSsidBeforePartyZero(t *testing.T) {
	oldPIDs := tss.GenerateTestPartyIDs(2)
	newPIDs := tss.GenerateTestPartyIDs(2)
	oldCtx := tss.NewPeerContext(oldPIDs)
	newCtx := tss.NewPeerContext(newPIDs)

	params := tss.NewReSharingParameters(tss.S256(), oldCtx, newCtx, newPIDs[0], len(oldPIDs), 1, len(newPIDs), 1)
	params.SetSessionNonce(big.NewInt(7))

	round := &round1{
		base: &base{
			ReSharingParameters: params,
			temp: &localTempData{
				localMessageStore: localMessageStore{
					dgRound1Messages: make([]tss.ParsedMessage, len(oldPIDs)),
				},
				ssidNonce: params.SessionNonce(),
			},
			oldOK:   make([]bool, len(oldPIDs)),
			newOK:   make([]bool, len(newPIDs)),
			started: true,
			number:  1,
		},
	}
	round.allNewOK()
	round.temp.ssid = round.getSSID()

	content := &DGRound1Message{
		EcdsaPubX:   []byte{0x01},
		EcdsaPubY:   []byte{0x02},
		VCommitment: []byte{0x03},
		Ssid:        []byte("wrong-ssid"),
	}
	routing := tss.MessageRouting{
		From:        oldPIDs[1],
		To:          newPIDs,
		IsBroadcast: true,
	}
	round.temp.dgRound1Messages[1] = tss.NewMessage(routing, content, tss.NewMessageWrapper(routing, content))

	_, tssErr := round.Update()
	if tssErr == nil {
		t.Fatal("expected mismatched SSID to be rejected even when old party 0 has not arrived")
	}
	if !strings.Contains(tssErr.Error(), "ssid does not match") {
		t.Fatalf("unexpected error: %v", tssErr)
	}
	if round.oldOK[1] {
		t.Fatal("old party 1 must not be marked accepted after SSID mismatch")
	}
}

// TestRound1Update_RejectsMismatchedECDSAPubBeforePartyZero pins that
// DGRound1Message ECDSAPub is checked per sender. A non-zero old party may
// arrive before old party 0, and its public key copy must not be silently
// skipped by waiting for party 0 as a canonical source.
func TestRound1Update_RejectsMismatchedECDSAPubBeforePartyZero(t *testing.T) {
	oldPIDs := tss.GenerateTestPartyIDs(2)
	newPIDs := tss.GenerateTestPartyIDs(2)
	oldCtx := tss.NewPeerContext(oldPIDs)
	newCtx := tss.NewPeerContext(newPIDs)

	params := tss.NewReSharingParameters(tss.S256(), oldCtx, newCtx, newPIDs[0], len(oldPIDs), 1, len(newPIDs), 1)
	params.SetSessionNonce(big.NewInt(7))
	save := keygen.NewLocalPartySaveData(len(newPIDs))

	round := &round1{
		base: &base{
			ReSharingParameters: params,
			temp: &localTempData{
				localMessageStore: localMessageStore{
					dgRound1Messages: make([]tss.ParsedMessage, len(oldPIDs)),
				},
				ssidNonce: params.SessionNonce(),
			},
			save:    &save,
			oldOK:   make([]bool, len(oldPIDs)),
			newOK:   make([]bool, len(newPIDs)),
			started: true,
			number:  1,
		},
	}
	round.allNewOK()
	round.temp.ssid = round.getSSID()
	round.save.ECDSAPub = crypto.ScalarBaseMult(tss.S256(), big.NewInt(1))

	differentECDSAPub := crypto.ScalarBaseMult(tss.S256(), big.NewInt(2))
	content := &DGRound1Message{
		EcdsaPubX:   differentECDSAPub.X().Bytes(),
		EcdsaPubY:   differentECDSAPub.Y().Bytes(),
		VCommitment: []byte{0x03},
		Ssid:        round.temp.ssid,
	}
	routing := tss.MessageRouting{
		From:        oldPIDs[1],
		To:          newPIDs,
		IsBroadcast: true,
	}
	round.temp.dgRound1Messages[1] = tss.NewMessage(routing, content, tss.NewMessageWrapper(routing, content))

	_, tssErr := round.Update()
	if tssErr == nil {
		t.Fatal("expected mismatched ECDSA public key to be rejected even when old party 0 has not arrived")
	}
	if !strings.Contains(tssErr.Error(), "ecdsa pub key did not match") {
		t.Fatalf("unexpected error: %v", tssErr)
	}
	if round.oldOK[1] {
		t.Fatal("old party 1 must not be marked accepted after ECDSA public key mismatch")
	}
}
