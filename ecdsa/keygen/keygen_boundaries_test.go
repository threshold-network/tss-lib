// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/tss"
)

// ----- Deterministic out-of-order readiness accumulation for round.ok -----

// keygenRound1ReadinessFixture constructs a round1 with temp arrays pre-allocated
// and ok[0]=true (self). Returns the round and party IDs.
func keygenRound1ReadinessFixture(t *testing.T, n int) (*round1, tss.SortedPartyIDs) {
	t.Helper()

	keys, pIDs, err := LoadKeygenTestFixtures(n)
	require.NoError(t, err)

	threshold := n - 1
	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(pIDs), pIDs[0], n, threshold)
	params.SetProtocolMode(tss.ProtocolModeLegacy)

	// Initialize localTempData with the embedded localMessageStore
	temp := &localTempData{
		localMessageStore: localMessageStore{
			kgRound1Messages: make([]tss.ParsedMessage, n),
		},
	}
	base := &base{
		Parameters: params,
		save:       &keys[0],
		temp:       temp,
		out:        make(chan tss.Message, n),
		end:        nil,
		ok:         make([]bool, n),
		started:    true,
		number:     1,
	}
	// Mark self as ready (as round1.Start does)
	base.ok[0] = true

	return &round1{base}, pIDs
}

// buildMinimalKGRound1Message constructs a minimal valid KGRound1Message for testing.
// Round1.Update only checks CanAccept (type + IsBroadcast), not cryptographic content.
// We construct a ParsedMessage directly with the correct content type and broadcast flag.
func buildMinimalKGRound1Message(t *testing.T, from *tss.PartyID) tss.ParsedMessage {
	t.Helper()

	// Minimal content with correct type
	content := &KGRound1Message{
		Commitment: commitments.NewHashCommitment(big.NewInt(1)).C.Bytes(),
		PaillierN:  big.NewInt(1).Bytes(),
		NTilde:     big.NewInt(1).Bytes(),
		H1:         big.NewInt(1).Bytes(),
		H2:         big.NewInt(1).Bytes(),
		Dlnproof_1: &KGRound1Message_DLNProof{
			Alpha: [][]byte{{1}},
			T:     [][]byte{{1}},
		},
		Dlnproof_2: &KGRound1Message_DLNProof{
			Alpha: [][]byte{{1}},
			T:     [][]byte{{1}},
		},
		Modproof: &KGRound1Message_ModProof{
			W: big.NewInt(1).Bytes(),
			X: [][]byte{{1}},
			A: []bool{true},
			B: []bool{true},
			Z: [][]byte{{1}},
		},
		ModproofTilde: &KGRound1Message_ModProof{
			W: big.NewInt(1).Bytes(),
			X: [][]byte{{1}},
			A: []bool{true},
			B: []bool{true},
			Z: [][]byte{{1}},
		},
	}

	meta := tss.MessageRouting{
		From:        from,
		IsBroadcast: true,
	}
	wrapper := tss.NewMessageWrapper(meta, content)
	return tss.NewMessage(meta, content, wrapper)
}

func TestKeygenRound1OutOfOrderReadinessAccumulation(t *testing.T) {
	n := 3 // self + 2 peers (indices 0,1,2)
	rnd, pIDs := keygenRound1ReadinessFixture(t, n)

	// Build minimal KGRound1Messages for peers 1 and 2
	msgPeer1 := buildMinimalKGRound1Message(t, pIDs[1])
	msgPeer2 := buildMinimalKGRound1Message(t, pIDs[2])

	// First delivery: peer 2 (later index) complete, peer 1 (earlier index) incomplete
	rnd.temp.kgRound1Messages[2] = msgPeer2

	ret, err := rnd.Update()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	require.False(t, ret, "not all peers ready")
	require.False(t, rnd.ok[1], "peer 1 must not be ready")
	require.True(t, rnd.ok[2], "peer 2 must be recorded as ready despite peer 1 being incomplete")

	// Second delivery: now complete peer 1
	rnd.temp.kgRound1Messages[1] = msgPeer1

	ret, err = rnd.Update()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	require.True(t, ret, "all peers now ready")
	require.True(t, rnd.ok[1])
	require.True(t, rnd.ok[2])
	require.True(t, rnd.CanProceed())
}
