// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/crypto/mta"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/test"
	"github.com/bnb-chain/tss-lib/tss"
)

// ----- Security-v2 ceremony abort: message / width mismatch -----

// securityV2CeremonyAbortFixture constructs N parties from keygen fixtures with
// the given message and width overrides per party. Returns parties, their out
// channels, end channels, and the peer context used for routing.
func securityV2CeremonyAbortFixture(t *testing.T, n int, overrides func(i int) (*big.Int, int)) ([]*LocalParty, []chan tss.Message, []chan common.SignatureData, *tss.PeerContext) {
	t.Helper()

	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(n)
	require.NoError(t, err)
	require.Equal(t, n, len(keys))
	require.Equal(t, n, len(signPIDs))

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, n)
	outChs := make([]chan tss.Message, n)
	endChs := make([]chan common.SignatureData, n)

	ceremonyNonce := big.NewInt(1)
	for i := 0; i < n; i++ {
		msg, width := overrides(i)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], n, test.TestThreshold)
		params.SetProtocolMode(tss.ProtocolModeSecurityV2)
		params.SetSessionNonce(ceremonyNonce)

		// Buffer large enough to hold both a full round-1 emission (n messages)
		// and, if the SSID check regresses and round 2 unexpectedly succeeds, a
		// full round-2 emission (n-1 messages) without blocking a Start() call.
		outCh := make(chan tss.Message, 2*n)
		endCh := make(chan common.SignatureData, 1)
		outChs[i] = outCh
		endChs[i] = endCh

		P := NewLocalParty(msg, params, keys[i], outCh, endCh, width).(*LocalParty)
		parties[i] = P
	}
	return parties, outChs, endChs, p2pCtx
}

// startAllAndAwait starts every party concurrently and blocks until every
// Start() call has returned, recording any error per party index. This
// avoids relying on goroutine scheduling order and ensures round-1 output is
// fully queued before any message collection begins.
func startAllAndAwait(parties []*LocalParty) []*tss.Error {
	n := len(parties)
	errs := make([]*tss.Error, n)
	done := make(chan struct{}, n)
	for i, P := range parties {
		go func(idx int, P *LocalParty) {
			defer func() { done <- struct{}{} }()
			if err := P.Start(); err != nil {
				errs[idx] = err
			}
		}(i, P)
	}
	for range n {
		<-done
	}
	return errs
}

// drainOwnRound1Output drains a party's own out channel of its round-1
// emission (n-1 directed messages + 1 broadcast = n messages), so that a
// later round-2 emission (on unexpected success) cannot block on a full
// channel.
func drainOwnRound1Output(t *testing.T, outCh chan tss.Message, n int) {
	t.Helper()
	for range n {
		select {
		case <-outCh:
		case <-time.After(time.Second):
			t.Fatal("timed out draining party's own round-1 output")
		}
	}
}

// collectRound1Messages drains each peer's out channel and returns the
// round-1 messages intended for the target party (directed to target, or broadcast).
func collectRound1Messages(t *testing.T, parties []*LocalParty, outChs []chan tss.Message, target *tss.PartyID) []tss.ParsedMessage {
	t.Helper()

	var msgs []tss.ParsedMessage
	for i, P := range parties {
		if P.PartyID().Index == target.Index {
			continue
		}
		// Each peer emits (n-1) directed messages and 1 broadcast; drain all.
		for range len(parties) {
			select {
			case msg := <-outChs[i]:
				if dest := msg.GetTo(); dest == nil || dest[0].Index == target.Index {
					bz, _, err := msg.WireBytes()
					require.NoError(t, err)
					parsed, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
					require.NoError(t, err)
					msgs = append(msgs, parsed)
				}
			case <-time.After(time.Second):
				t.Fatal("timed out collecting round-1 messages from peer")
			}
		}
	}
	return msgs
}

// assertOpposingCulpritAndNoSignature drives the mismatch scenario: starts
// all parties, drains party 0's own round-1 output (deadlock guard), feeds
// party 0 every peer round-1 message, and asserts round-2 aborts with the
// opposing party attributed among the culprits (BobMid and BobMidWC may both
// attribute to the same peer, so the culprit set can contain a duplicate).
// Asserts no signature is produced on any party's end channel within a
// bounded deadline.
func assertOpposingCulpritAndNoSignature(t *testing.T, n int, overrides func(i int) (*big.Int, int)) {
	t.Helper()

	parties, outChs, endChs, _ := securityV2CeremonyAbortFixture(t, n, overrides)

	// Start every party and await completion before touching any channel.
	startErrs := startAllAndAwait(parties)
	for i, err := range startErrs {
		require.Nil(t, err, "party %d Start must not fail in round 1", i)
	}

	// Drain party 0's own round-1 emission so a possible (regressed) round-2
	// success cannot block on a full out channel.
	drainOwnRound1Output(t, outChs[0], n)

	// Collect round-1 messages destined for party 0 from every peer.
	msgs := collectRound1Messages(t, parties, outChs, parties[0].PartyID())

	// Feed messages to party 0; the message that completes round 1 triggers
	// round-2 Start synchronously and returns its error (if any).
	var lastErr *tss.Error
	for _, msg := range msgs {
		_, err := parties[0].Update(msg)
		if err != nil {
			lastErr = err
		}
	}

	require.NotNil(t, lastErr, "expected round-2 proof verification to fail")
	require.Equal(t, 2, lastErr.Round(), "abort must occur in round 2, the first proof-verification stage")

	// Culprits must include the opposing party (party 1). BobMid and BobMidWC
	// both attribute failures to the same peer, so the culprit set is
	// expected to contain that party's ID (possibly more than once).
	require.NotEmpty(t, lastErr.Culprits(), "culprits must be attributed to the peer with mismatched context")
	opposingIdx := parties[1].PartyID().Index
	found := false
	for _, c := range lastErr.Culprits() {
		if c.Index == opposingIdx {
			found = true
			break
		}
	}
	require.True(t, found, "culprit set must include the party with the mismatched context")
	for _, c := range lastErr.Culprits() {
		require.Equal(t, opposingIdx, c.Index, "every culprit must be the single opposing party, not an unrelated peer")
	}

	// No signature may be produced on any end channel; give a bounded
	// deadline in case the check above regressed and the ceremony proceeded.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	for i, endCh := range endChs {
		select {
		case <-endCh:
			t.Errorf("party %d produced a signature despite mismatched context", i)
		case <-ctx.Done():
			// timeout expected; no signature was produced
		}
	}
}

func TestSecurityV2CeremonyAbortsOnMessageMismatch(t *testing.T) {
	t.Run("opposingPartySignsDifferentMessage", func(t *testing.T) {
		n := test.TestThreshold + 1 // 11 parties
		overrides := func(i int) (*big.Int, int) {
			if i == 1 {
				return big.NewInt(43), 32 // party 1 signs a different message
			}
			return big.NewInt(42), 32
		}
		assertOpposingCulpritAndNoSignature(t, n, overrides)
	})

	t.Run("opposingPartyUsesDifferentFullBytesLen", func(t *testing.T) {
		n := test.TestThreshold + 1
		overrides := func(i int) (*big.Int, int) {
			if i == 1 {
				return big.NewInt(42), 31 // same message, different width
			}
			return big.NewInt(42), 32
		}
		assertOpposingCulpritAndNoSignature(t, n, overrides)
	})
}

// ----- Signing Start range gate: m == N rejected, m == N-1 accepted -----

func TestSigningStartMessageRangeGate(t *testing.T) {
	q := tss.S256().Params().N
	// Use a minimal 2-party setup (threshold 1) for speed
	keys, pIDs, err := keygen.LoadKeygenTestFixtures(2)
	require.NoError(t, err)

	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(pIDs), pIDs[0], 2, 1)
	params.SetProtocolMode(tss.ProtocolModeLegacy)

	t.Run("rejectsMessageEqualToCurveOrder", func(t *testing.T) {
		out := make(chan tss.Message, 2)
		end := make(chan common.SignatureData, 1)
		msg := new(big.Int).Set(q)

		P := NewLocalParty(msg, params, keys[0], out, end, 32).(*LocalParty)
		err := P.Start()
		require.NotNil(t, err, "Start must reject m == curve order")

		// No messages should have been emitted (gate is before any emission)
		assert.Empty(t, out, "no round-1 messages emitted on rejection")
	})

	t.Run("acceptsMessageEqualToOrderMinusOne", func(t *testing.T) {
		out := make(chan tss.Message, 2)
		end := make(chan common.SignatureData, 1)
		msg := new(big.Int).Sub(q, big.NewInt(1))

		P := NewLocalParty(msg, params, keys[0], out, end, 32).(*LocalParty)
		err := P.Start()
		require.Nil(t, err, "Start must accept m == q-1 through the range gate")

		// Round-1 messages must be emitted: 1 directed + 1 broadcast = 2
		msgs := make([]tss.Message, 0, 2)
		for range 2 {
			select {
			case m := <-out:
				msgs = append(msgs, m)
			}
		}
		assert.Len(t, msgs, 2, "expected 2 round-1 messages (directed + broadcast)")
	})
}

// ----- Deterministic out-of-order readiness accumulation for round.ok -----

// signingRound1ReadinessFixture constructs a round1 with temp arrays pre-allocated
// and ok[0]=true (self). Returns the round and party IDs.
func signingRound1ReadinessFixture(t *testing.T, n int) (*round1, tss.SortedPartyIDs) {
	t.Helper()

	keys, pIDs, err := keygen.LoadKeygenTestFixtures(n)
	require.NoError(t, err)

	threshold := n - 1
	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(pIDs), pIDs[0], n, threshold)
	params.SetProtocolMode(tss.ProtocolModeLegacy)

	// Initialize localTempData with the embedded localMessageStore
	temp := &localTempData{
		localMessageStore: localMessageStore{
			signRound1Message1s: make([]tss.ParsedMessage, n),
			signRound1Message2s: make([]tss.ParsedMessage, n),
		},
	}
	base := &base{
		Parameters: params,
		key:        &keys[0],
		data:       &common.SignatureData{},
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

func TestSigningRound1OutOfOrderReadinessAccumulation(t *testing.T) {
	n := 3 // self + 2 peers (indices 0,1,2) (need later-ready peer after earlier-incomplete)
	rnd, pIDs := signingRound1ReadinessFixture(t, n)

	// Construct valid round-1 messages for peers 1 and 2
	// Message1: directed to self, not broadcast
	// Message2: broadcast with HashCommitment (type *big.Int)
	buildMsg := func(peerIdx int) (tss.ParsedMessage, tss.ParsedMessage) {
		from := pIDs[peerIdx]
		to := pIDs[0]
		c := big.NewInt(int64(peerIdx*100 + 1))
		// Dummy range proof: zero big ints pass ValidateBasic and CanAccept (no proof verification in round 1)
		proof := &mta.RangeProofAlice{
			Z: big.NewInt(0), U: big.NewInt(0), W: big.NewInt(0),
			S: big.NewInt(0), S1: big.NewInt(0), S2: big.NewInt(0),
		}
		msg1 := NewSignRound1Message1(to, from, c, proof)
		// HashCommitment is *big.Int; use a simple secret to create one
		commitment := commitments.NewHashCommitment(big.NewInt(int64(peerIdx*10 + 1))).C
		msg2 := NewSignRound1Message2(from, commitment)
		return msg1, msg2
	}

	// First delivery: peer 2 (later index) complete, peer 1 (earlier index) incomplete
	msg1_2, msg2_2 := buildMsg(2)
	rnd.temp.signRound1Message1s[2] = msg1_2
	rnd.temp.signRound1Message2s[2] = msg2_2

	ret, err := rnd.Update()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	require.False(t, ret, "not all peers ready")
	require.False(t, rnd.ok[1], "peer 1 must not be ready")
	require.True(t, rnd.ok[2], "peer 2 must be recorded as ready despite peer 1 being incomplete")

	// Second delivery: now complete peer 1
	msg1_1, msg2_1 := buildMsg(1)
	rnd.temp.signRound1Message1s[1] = msg1_1
	rnd.temp.signRound1Message2s[1] = msg2_1

	ret, err = rnd.Update()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	require.True(t, ret, "all peers now ready")
	require.True(t, rnd.ok[1])
	require.True(t, rnd.ok[2])
	require.True(t, rnd.CanProceed())
}
