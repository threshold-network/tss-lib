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
		Ssid:        []byte{0x04},
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
