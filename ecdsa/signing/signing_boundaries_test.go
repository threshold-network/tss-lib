// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"context"
	"math/big"
	"sync"
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
// channels, and end channels.
func securityV2CeremonyAbortFixture(t *testing.T, n int, overrides func(i int) (*big.Int, int)) ([]*LocalParty, []chan tss.Message, []chan *common.SignatureData) {
	t.Helper()

	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(n)
	require.NoError(t, err)
	require.Equal(t, n, len(keys))
	require.Equal(t, n, len(signPIDs))

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, n)
	outChs := make([]chan tss.Message, n)
	endChs := make([]chan *common.SignatureData, n)

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
		endCh := make(chan *common.SignatureData, 1)
		outChs[i] = outCh
		endChs[i] = endCh

		P := NewLocalParty(msg, params, keys[i], outCh, endCh, width).(*LocalParty)
		parties[i] = P
	}
	return parties, outChs, endChs
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

// collectRound1MessagesForTargets drains every party's round-1 output exactly
// once (n messages per party: n-1 directed + 1 broadcast) and partitions the
// messages addressed to target0 and target1 (a broadcast message is
// delivered to both targets except the originating target itself, which
// already has its own broadcast stored locally by Start(); a directed
// message only goes to its specific recipient). Draining every party's own
// channel, not just the two targets', also guards against a full
// out-channel deadlocking a later round if the SSID check regresses and
// round 2 unexpectedly succeeds.
func collectRound1MessagesForTargets(
	t *testing.T,
	parties []*LocalParty,
	outChs []chan tss.Message,
	target0, target1 *tss.PartyID,
) (forTarget0, forTarget1 []tss.ParsedMessage) {
	t.Helper()
	n := len(parties)

	for i, P := range parties {
		for range n {
			var msg tss.Message
			select {
			case msg = <-outChs[i]:
			case <-time.After(time.Second):
				t.Fatalf("timed out draining round-1 output from party %d", i)
			}

			dest := msg.GetTo()
			isBroadcast := dest == nil
			wantsTarget := func(target *tss.PartyID) bool {
				if P.PartyID().Index == target.Index {
					// The sender's own broadcast is already stored locally by
					// its own Start(); it never needs to be delivered back.
					return false
				}
				return isBroadcast || dest[0].Index == target.Index
			}

			want0 := wantsTarget(target0)
			want1 := wantsTarget(target1)
			if !want0 && !want1 {
				continue
			}

			bz, _, err := msg.WireBytes()
			require.NoError(t, err)
			parsed, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
			require.NoError(t, err)

			if want0 {
				forTarget0 = append(forTarget0, parsed)
			}
			if want1 {
				forTarget1 = append(forTarget1, parsed)
			}
		}
	}
	return
}

// assertNoSignatureWithinWindow concurrently monitors every end channel for
// the given window, so that channels later in the slice are not shortchanged
// by a shared timeout that already elapsed while sequentially checking
// earlier ones (which could randomly mask an already-buffered signature via
// select's race between a ready channel and an already-canceled context). A
// final nonblocking check per channel, with no competing canceled context,
// guards against a signature buffered exactly at the window boundary.
func assertNoSignatureWithinWindow(t *testing.T, endChs []chan *common.SignatureData, window time.Duration) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), window)
	defer cancel()

	got := make([]bool, len(endChs))
	var wg sync.WaitGroup
	for i, endCh := range endChs {
		wg.Add(1)
		go func(i int, endCh chan *common.SignatureData) {
			defer wg.Done()
			select {
			case <-endCh:
				got[i] = true
			case <-ctx.Done():
			}
		}(i, endCh)
	}
	wg.Wait()

	// Final nonblocking check with no competing canceled context: catches a
	// signature buffered exactly at the boundary that the racy select above
	// could have missed by resolving via ctx.Done() instead of the ready endCh.
	for i, endCh := range endChs {
		if got[i] {
			continue
		}
		select {
		case <-endCh:
			got[i] = true
		default:
		}
	}

	for i, produced := range got {
		if produced {
			t.Errorf("party %d produced a signature despite mismatched context", i)
		}
	}
}

// culpritIndexSet returns the unique set of party indices among err's culprits.
func culpritIndexSet(err *tss.Error) map[int]struct{} {
	set := make(map[int]struct{})
	for _, c := range err.Culprits() {
		set[c.Index] = struct{}{}
	}
	return set
}

func indexSet(pids ...*tss.PartyID) map[int]struct{} {
	set := make(map[int]struct{}, len(pids))
	for _, p := range pids {
		set[p.Index] = struct{}{}
	}
	return set
}

// assertOpposingCulpritsAndNoSignature drives the mismatch scenario from both
// receivers' viewpoints. Party 0 (majority context) should reject only the
// single opposing party (party 1), since every other peer shares party 0's
// context. Party 1 (minority context) should reject every other party, since
// its own SSID differs from all of them. Both must abort in round 2 (the
// first proof-verification stage) with the exact expected culprit set, and
// no party may ever produce a signature.
func assertOpposingCulpritsAndNoSignature(t *testing.T, n int, overrides func(i int) (*big.Int, int)) {
	t.Helper()

	parties, outChs, endChs := securityV2CeremonyAbortFixture(t, n, overrides)

	startErrs := startAllAndAwait(parties)
	for i, err := range startErrs {
		require.Nil(t, err, "party %d Start must not fail in round 1", i)
	}

	msgsFor0, msgsFor1 := collectRound1MessagesForTargets(t, parties, outChs, parties[0].PartyID(), parties[1].PartyID())

	var lastErr0 *tss.Error
	for _, msg := range msgsFor0 {
		_, err := parties[0].Update(msg)
		if err != nil {
			lastErr0 = err
		}
	}
	var lastErr1 *tss.Error
	for _, msg := range msgsFor1 {
		_, err := parties[1].Update(msg)
		if err != nil {
			lastErr1 = err
		}
	}

	// Party 0 (majority context) only disagrees with party 1.
	require.NotNil(t, lastErr0, "party 0 expected round-2 proof verification to fail")
	require.Equal(t, 2, lastErr0.Round(), "party 0 abort must occur in round 2")
	require.NotEmpty(t, lastErr0.Culprits())
	wantCulprits0 := indexSet(parties[1].PartyID())
	require.Equal(t, wantCulprits0, culpritIndexSet(lastErr0), "party 0's culprit set must be exactly the opposing party")

	// Party 1 (minority context) disagrees with every other party.
	require.NotNil(t, lastErr1, "party 1 expected round-2 proof verification to fail")
	require.Equal(t, 2, lastErr1.Round(), "party 1 abort must occur in round 2")
	require.NotEmpty(t, lastErr1.Culprits())
	wantOthers := make([]*tss.PartyID, 0, n-1)
	for i, P := range parties {
		if i == 1 {
			continue
		}
		wantOthers = append(wantOthers, P.PartyID())
	}
	wantCulprits1 := indexSet(wantOthers...)
	require.Equal(t, wantCulprits1, culpritIndexSet(lastErr1), "party 1's culprit set must be every other party")

	assertNoSignatureWithinWindow(t, endChs, 500*time.Millisecond)
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
		assertOpposingCulpritsAndNoSignature(t, n, overrides)
	})

	t.Run("opposingPartyUsesDifferentFullBytesLen", func(t *testing.T) {
		n := test.TestThreshold + 1
		overrides := func(i int) (*big.Int, int) {
			if i == 1 {
				return big.NewInt(42), 31 // same message, different width
			}
			return big.NewInt(42), 32
		}
		assertOpposingCulpritsAndNoSignature(t, n, overrides)
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
		end := make(chan *common.SignatureData, 1)
		msg := new(big.Int).Set(q)

		P := NewLocalParty(msg, params, keys[0], out, end, 32).(*LocalParty)
		err := P.Start()
		require.NotNil(t, err, "Start must reject m == curve order")

		// No messages should have been emitted (gate is before any emission)
		assert.Empty(t, out, "no round-1 messages emitted on rejection")
	})

	t.Run("acceptsMessageEqualToOrderMinusOne", func(t *testing.T) {
		out := make(chan tss.Message, 2)
		end := make(chan *common.SignatureData, 1)
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
