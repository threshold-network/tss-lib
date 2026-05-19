// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"testing"
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
