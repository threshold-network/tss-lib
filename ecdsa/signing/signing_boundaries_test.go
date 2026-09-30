// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"
	"testing"

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
	if err != nil { t.Fatalf("unexpected error: %v", err) }
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

		outCh := make(chan tss.Message, n)
		endCh := make(chan common.SignatureData, 1)
		outChs[i] = outCh
		endChs[i] = endCh

		P := NewLocalParty(msg, params, keys[i], outCh, endCh, width).(*LocalParty)
		parties[i] = P
	}
	return parties, outChs, endChs, p2pCtx
}

// collectRound1Messages drains each party's out channel and returns the
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
					if err != nil { t.Fatalf("unexpected error: %v", err) }
					parsed, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
					if err != nil { t.Fatalf("unexpected error: %v", err) }
					msgs = append(msgs, parsed)
				}
			}
		}
	}
	return msgs
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

		parties, outChs, endChs, _ := securityV2CeremonyAbortFixture(t, n, overrides)

		// Start all parties (round 1)
		errCh := make(chan *tss.Error, n)
		for _, P := range parties {
			go func(P *LocalParty) {
				if err := P.Start(); err != nil {
					errCh <- err
				}
			}(P)
		}

		// Drain round-1 messages from peers and feed to party 0
		msgs := collectRound1Messages(t, parties, outChs, parties[0].PartyID())

		// Feed messages to party 0 via Update
		var lastErr *tss.Error
		for _, msg := range msgs {
			_, err := parties[0].Update(msg)
			if err != nil {
				lastErr = err
			}
		}

		// The last Update should have triggered round-2 Start and failed
		require.NotNil(t, lastErr, "expected round-2 proof verification to fail")

		// Culprit must be the opposing party (party 1)
		require.NotEmpty(t, lastErr.Culprits(), "culprits should be attributed to the peer with mismatched context")
		require.Equal(t, parties[1].PartyID().Index, lastErr.Culprits()[0].Index, "culprit should be the party with the different message")

		// No signature may be produced on any end channel
		for i, endCh := range endChs {
			select {
			case <-endCh:
				t.Errorf("party %d produced a signature despite mismatched context", i)
			default:
			}
		}
	})

	t.Run("opposingPartyUsesDifferentFullBytesLen", func(t *testing.T) {
		n := test.TestThreshold + 1
		overrides := func(i int) (*big.Int, int) {
			if i == 1 {
				return big.NewInt(42), 31 // same message, different width
			}
			return big.NewInt(42), 32
		}

		parties, outChs, endChs, _ := securityV2CeremonyAbortFixture(t, n, overrides)

		errCh := make(chan *tss.Error, n)
		for _, P := range parties {
			go func(P *LocalParty) {
				if err := P.Start(); err != nil {
					errCh <- err
				}
			}(P)
		}

		msgs := collectRound1Messages(t, parties, outChs, parties[0].PartyID())

		var lastErr *tss.Error
		for _, msg := range msgs {
			_, err := parties[0].Update(msg)
			if err != nil {
				lastErr = err
			}
		}

		require.NotNil(t, lastErr, "expected round-2 proof verification to fail")
		require.NotEmpty(t, lastErr.Culprits(), "culprits should be attributed to the peer with mismatched width")
		require.Equal(t, parties[1].PartyID().Index, lastErr.Culprits()[0].Index)

		for i, endCh := range endChs {
			select {
			case <-endCh:
				t.Errorf("party %d produced a signature despite mismatched width", i)
			default:
			}
		}
	})
}

// ----- Signing Start range gate: m == N rejected, m == N-1 accepted -----

func TestSigningStartMessageRangeGate(t *testing.T) {
	q := tss.S256().Params().N
	// Use a minimal 2-party setup (threshold 1) for speed
	keys, pIDs, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil { t.Fatalf("unexpected error: %v", err) }

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
	if err != nil { t.Fatalf("unexpected error: %v", err) }

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
	n := 3 // 3 parties, threshold 2
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
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	require.False(t, ret, "not all peers ready")
	require.False(t, rnd.ok[1], "peer 1 must not be ready")
	require.True(t, rnd.ok[2], "peer 2 must be recorded as ready despite peer 1 being incomplete")

	// Second delivery: now complete peer 1
	msg1_1, msg2_1 := buildMsg(1)
	rnd.temp.signRound1Message1s[1] = msg1_1
	rnd.temp.signRound1Message2s[1] = msg2_1

	ret, err = rnd.Update()
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	require.True(t, ret, "all peers now ready")
	require.True(t, rnd.ok[1])
	require.True(t, rnd.ok[2])
	require.True(t, rnd.CanProceed())
}