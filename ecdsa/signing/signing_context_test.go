// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

func newSigningContextTestParty(t *testing.T, index int, mode tss.ProtocolMode, message, nonce *big.Int, width int) *LocalParty {
	t.Helper()
	keys, partyIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1)
	if err != nil {
		t.Fatal(err)
	}
	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(partyIDs), partyIDs[index], len(partyIDs), testThreshold)
	params.SetProtocolMode(mode)
	if nonce != nil {
		params.SetSessionNonce(nonce)
	}
	out := make(chan tss.Message, len(partyIDs))
	end := make(chan common.SignatureData, 1)
	return NewLocalParty(message, params, keys[index], out, end, width).(*LocalParty)
}

func signingContextTestSSID(t *testing.T, message, nonce int64, width int) []byte {
	t.Helper()
	party := newSigningContextTestParty(t, 0, tss.ProtocolModeSecurityV2, big.NewInt(message), big.NewInt(nonce), width)
	round := party.FirstRound().(*round1)
	round.temp.ssidNonce = round.Params().SessionNonce()
	ssid, err := round.getSSID()
	if err != nil {
		t.Fatal(err)
	}
	return ssid
}

func TestSecurityV2SSIDBindsSigningContext(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		message, otherMessage int64
		nonce, otherNonce     int64
		width, otherWidth     int
	}{
		{"message", 42, 43, 1, 1, 32, 32},
		{"message_width", 42, 42, 1, 1, 32, 31},
		{"zero_message_width", 0, 0, 1, 1, 1, 2},
		{"session_nonce", 42, 42, 1, 2, 32, 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ssid := signingContextTestSSID(t, tc.message, tc.nonce, tc.width)
			other := signingContextTestSSID(t, tc.otherMessage, tc.otherNonce, tc.otherWidth)
			if bytes.Equal(ssid, other) {
				t.Fatal("distinct signing contexts must derive distinct SSIDs")
			}
		})
	}
}

func TestSecurityV2SSIDMatchesPeersAndPreservesWidth(t *testing.T) {
	// This deterministic fixture digest starts with zero, so the vector also
	// pins the existing 32-byte SSID encoding rather than big.Int.Bytes().
	want, err := hex.DecodeString("009d8f7ec28d68a6bb3fbf1581b1b989200e4e996f8d389d4207cd385967e294")
	if err != nil {
		t.Fatal(err)
	}
	for _, index := range []int{0, 1} {
		party := newSigningContextTestParty(t, index, tss.ProtocolModeSecurityV2, big.NewInt(42), big.NewInt(346), 32)
		if err := party.Start(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, party.temp.ssid) {
			t.Fatalf("party %d: SSID = %x, want %x", index, party.temp.ssid, want)
		}
	}
	if got := signingContextTestSSID(t, 42, 346, 32); !bytes.Equal(got, want) {
		t.Fatalf("repeated context: SSID = %x, want %x", got, want)
	}
}

func TestSecurityV2SSIDRejectsNilMessage(t *testing.T) {
	party := newSigningContextTestParty(t, 0, tss.ProtocolModeSecurityV2, nil, big.NewInt(1), 32)
	round := party.FirstRound().(*round1)
	round.temp.ssidNonce = round.Params().SessionNonce()
	ssid, err := round.getSSID()
	if err == nil || ssid != nil {
		t.Fatalf("nil message: SSID = %x, error = %v", ssid, err)
	}
}

func TestLegacySigningKeepsHistoricalProofContext(t *testing.T) {
	for _, width := range []int{31, 32} {
		party := newSigningContextTestParty(t, 0, tss.ProtocolModeLegacy, big.NewInt(42), nil, width)
		if err := party.Start(); err != nil {
			t.Fatal(err)
		}
		if party.temp.ssid != nil || party.temp.ssidNonce != nil {
			t.Fatal("legacy signing must not derive a session identifier")
		}
		if context := party.FirstRound().(*round1).proofContext(1); context != nil {
			t.Fatalf("legacy proof context = %x, want nil", context)
		}
	}
}

func TestSigningConstructorsCopyMessage(t *testing.T) {
	keys, partyIDs, err := keygen.LoadKeygenTestFixtures(testThreshold + 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, constructor := range []struct {
		name     string
		newParty func(*big.Int, *tss.Parameters) tss.Party
	}{
		{"NewLocalParty", func(message *big.Int, params *tss.Parameters) tss.Party {
			return NewLocalParty(message, params, keys[0], nil, nil, 32)
		}},
		{"NewLocalPartyWithKDD", func(message *big.Int, params *tss.Parameters) tss.Party {
			return NewLocalPartyWithKDD(message, params, keys[0], big.NewInt(1), nil, nil, 32)
		}},
	} {
		for _, mode := range []struct {
			name  string
			value tss.ProtocolMode
		}{
			{"legacy", tss.ProtocolModeLegacy},
			{"security-v2", tss.ProtocolModeSecurityV2},
		} {
			t.Run(constructor.name+"/"+mode.name, func(t *testing.T) {
				params := tss.NewParameters(tss.S256(), tss.NewPeerContext(partyIDs), partyIDs[0], len(partyIDs), testThreshold)
				params.SetProtocolMode(mode.value)
				if mode.value == tss.ProtocolModeSecurityV2 {
					params.SetSessionNonce(big.NewInt(1))
				}
				message := new(big.Int).Lsh(big.NewInt(1), 200)
				want := new(big.Int).Set(message)
				party := constructor.newParty(message, params).(*LocalParty)
				round := party.FirstRound().(*round1)
				var ssid []byte
				if mode.value == tss.ProtocolModeSecurityV2 {
					round.temp.ssidNonce = params.SessionNonce()
					ssid, err = round.getSSID()
					if err != nil {
						t.Fatal(err)
					}
				}
				// Add preserves the nonzero magnitude's size and can reuse its
				// backing words, exposing both pointer and shallow-copy aliases.
				message.Add(message, big.NewInt(1))
				if party.temp.m.Cmp(want) != 0 {
					t.Fatal("caller mutation changed the party's message")
				}
				if mode.value == tss.ProtocolModeSecurityV2 {
					got, err := round.getSSID()
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(ssid, got) {
						t.Fatal("caller mutation changed the party's signing context")
					}
				}
			})
		}
	}
}
