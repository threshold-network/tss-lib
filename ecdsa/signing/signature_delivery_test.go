// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"crypto/ecdsa"
	"math/big"
	"testing"
	"time"

	btcecdsa "github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/test"
	"github.com/bnb-chain/tss-lib/tss"
)

// assertR5Stored asserts that P's round-5 temp state (every field round 5
// writes) is fully populated: the round stores it in program order before
// P emits its round-5 message.
func assertR5Stored(t *testing.T, P *LocalParty) {
	t.Helper()
	idx := P.PartyID().Index
	assert.NotNil(t, P.temp.signRound5Messages[idx], "round 5 must store its own message before emitting")
	assert.NotNil(t, P.temp.li, "round 5 must store li before emitting")
	assert.NotNil(t, P.temp.bigAi, "round 5 must store bigAi before emitting")
	assert.NotNil(t, P.temp.bigVi, "round 5 must store bigVi before emitting")
	assert.NotNil(t, P.temp.roi, "round 5 must store roi before emitting")
	assert.NotNil(t, P.temp.DPower, "round 5 must store the decommitment before emitting")
	assert.NotNil(t, P.temp.si, "round 5 must store si before emitting")
	assert.NotNil(t, P.temp.rx, "round 5 must store rx before emitting")
	assert.NotNil(t, P.temp.ry, "round 5 must store ry before emitting")
	assert.NotNil(t, P.temp.bigR, "round 5 must store bigR before emitting")
}

// assertR7Stored asserts that P's round-7 temp state (every field round 7
// writes) is fully populated before P emits its round-7 message.
func assertR7Stored(t *testing.T, P *LocalParty) {
	t.Helper()
	idx := P.PartyID().Index
	assert.NotNil(t, P.temp.signRound7Messages[idx], "round 7 must store its own message before emitting")
	assert.NotNil(t, P.temp.Ui, "round 7 must store Ui before emitting")
	assert.NotNil(t, P.temp.Ti, "round 7 must store Ti before emitting")
	assert.NotNil(t, P.temp.DTelda, "round 7 must store the decommitment before emitting")
}

// signatureDataSnapshot copies the caller-visible fields of a SignatureData
// so a test can compare the delivered value with the party's internal state
// after mutating the delivered copy.
type signatureDataSnapshot struct {
	signature,
	signatureRecovery,
	r,
	s,
	m []byte
}

func snapshotSignatureData(sd *common.SignatureData) signatureDataSnapshot {
	if sd == nil {
		return signatureDataSnapshot{}
	}
	cp := func(b []byte) []byte {
		out := make([]byte, len(b))
		copy(out, b)
		return out
	}
	return signatureDataSnapshot{cp(sd.Signature), cp(sd.SignatureRecovery), cp(sd.R), cp(sd.S), cp(sd.M)}
}

// verifyDeliveredSignatureData checks the *common.SignatureData values
// delivered on the parties' end channel: the R/S encoding, the combined
// signature, the recovery byte, the message width, low-S normalization,
// ECDSA verification, pubkey recovery from the compact form, and that the
// delivered value is a deep copy of the party's internal state.
func verifyDeliveredSignatureData(t *testing.T, delivered []*common.SignatureData, parties []*LocalParty, keys []keygen.LocalPartySaveData, msg *big.Int, fullBytesLen int) {
	t.Helper()
	require.Len(t, delivered, len(parties))

	N := tss.S256().Params().N
	halfN := new(big.Int).Rsh(N, 1)
	pkX, pkY := keys[0].ECDSAPub.X(), keys[0].ECDSAPub.Y()
	pk := ecdsa.PublicKey{Curve: tss.EC(), X: pkX, Y: pkY}

	// expectedM is the fixed-width big-endian (left-padded) encoding of msg
	expectedM := make([]byte, fullBytesLen)
	msg.FillBytes(expectedM)

	// Snapshot the parties' internal signature data before mutating any
	// delivered value below.
	internal := make([]signatureDataSnapshot, len(parties))
	for i, P := range parties {
		internal[i] = snapshotSignatureData(P.data)
		require.NotEmpty(t, internal[i].signature, "party %d must hold its signature data", i)
	}

	for _, sd := range delivered {
		// R and S must each be exactly fullBytesLen bytes of equal width
		assert.Equal(t, fullBytesLen, len(sd.R), "R must be fullBytesLen bytes")
		assert.Equal(t, fullBytesLen, len(sd.S), "S must be fullBytesLen bytes")
		assert.Equal(t, len(sd.R), len(sd.S), "R and S must have equal width")
		// M must match the left-padded fixed-width message encoding
		assert.Equal(t, expectedM, sd.M, "M encoding must match")
		// Signature must be R||S
		combined := make([]byte, 0, 2*fullBytesLen)
		combined = append(combined, sd.R...)
		combined = append(combined, sd.S...)
		assert.Equal(t, combined, sd.Signature, "Signature must be R||S")
		// Recovery byte must be present and in [0,3]
		require.Len(t, sd.SignatureRecovery, 1, "recovery byte must be present")
		recid := int(sd.SignatureRecovery[0])
		assert.True(t, recid >= 0 && recid <= 3, "recovery byte must be in [0,3]")
		// S must be low (canonical)
		sInt := new(big.Int).SetBytes(sd.S)
		assert.True(t, sInt.Cmp(halfN) <= 0, "S must be low (S <= N/2)")
		// ECDSA verification
		rInt := new(big.Int).SetBytes(sd.R)
		assert.True(t, ecdsa.Verify(&pk, sd.M, rInt, sInt), "signature must verify")
		// Pubkey recovery from the compact signature
		compact := make([]byte, 0, 65)
		compact = append(compact, byte(27+recid))
		compact = append(compact, sd.R...)
		compact = append(compact, sd.S...)
		recovered, _, recErr := btcecdsa.RecoverCompact(compact, sd.M)
		require.NoError(t, recErr, "pubkey recovery must succeed")
		assert.True(t, recovered.X().Cmp(pkX) == 0, "recovered X must match")
		assert.True(t, recovered.Y().Cmp(pkY) == 0, "recovered Y must match")
	}

	// The delivered values must be deep copies. Mutate every field of every
	// delivered value first, then compare every party's internal data with
	// its snapshot, so a delivered value that aliases any party's data is
	// caught whatever its position in delivered.
	for _, sd := range delivered {
		for _, b := range [][]byte{sd.Signature, sd.SignatureRecovery, sd.R, sd.S, sd.M} {
			if len(b) > 0 {
				b[0] ^= 0xff
			}
		}
	}
	for i, P := range parties {
		assert.Equal(t, internal[i], snapshotSignatureData(P.data),
			"mutating the delivered signatures must not affect party %d's internal data", i)
	}
}

// TestRound5AndRound7StoreBeforeEmit pins the store-before-emit ordering
// of signing rounds 5 and 7: by the time a party emits its round-5 or
// round-7 message on its out channel, that party's temp state written by
// the round (its own message slot plus the round's scratch values) must
// already be fully populated. An emit-before-store regression would leave
// the sender's temp fields nil at the moment its message is received.
//
// The test gives each party an unbuffered out channel and drives rounds 1
// through 7 itself. Receiving party P's round-5 or round-7 message on P's
// channel is the happens-before point of P's send completing, and P's
// round stores P's temp in program order before the send. The test asserts
// P's temp at that point, before routing P's message to any peer, then
// stops; a 2-party subset cannot complete the ceremony.
func TestRound5AndRound7StoreBeforeEmit(t *testing.T) {
	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(2)
	require.NoError(t, err)

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 2)
	outChs := make([]chan tss.Message, 2)
	endChs := make([]chan *common.SignatureData, 2)
	// Unbuffered out channels: a party's emit blocks until the test
	// receives it, which is what makes the store-before-emit check
	// race-free.
	for i := range 2 {
		outChs[i] = make(chan tss.Message)
		endChs[i] = make(chan *common.SignatureData, 1)
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], 2, 1)
		params.SetProtocolMode(tss.ProtocolModeLegacy)
		parties[i] = NewLocalParty(big.NewInt(1), params, keys[i], outChs[i], endChs[i], 32).(*LocalParty)
	}

	errCh := make(chan *tss.Error, 4)
	for i := range 2 {
		go func(i int) {
			if err := parties[i].Start(); err != nil {
				errCh <- err
			}
		}(i)
	}

	sawR5 := [2]bool{}
	sawR7 := [2]bool{}
	hook := func(sender int, m tss.Message) {
		pm, ok := m.(tss.ParsedMessage)
		if !ok {
			return
		}
		switch pm.Content().(type) {
		case *SignRound5Message:
			if !sawR5[sender] {
				assertR5Stored(t, parties[sender])
				sawR5[sender] = true
			}
		case *SignRound7Message:
			if !sawR7[sender] {
				assertR7Stored(t, parties[sender])
				sawR7[sender] = true
			}
		}
	}

	// Drive the ceremony by routing each party's out-channel messages to
	// its peers via fresh goroutines. Stop once both parties have emitted
	// their round-5 and round-7 messages; a 2-party (threshold-1) subset
	// cannot complete the ceremony and fails later, in round 9.
	updater := test.SharedPartyUpdater
	route := func(sender int, m tss.Message) {
		dest := m.GetTo()
		if dest == nil {
			go updater(parties[1-sender], m, errCh)
		} else {
			go updater(parties[dest[0].Index], m, errCh)
		}
	}
	// The parties keep running after the checks below finish. Keep draining
	// their channels for a while so blocked sends can complete and no
	// party or routing goroutine is left blocked forever.
	t.Cleanup(func() {
		go func() {
			idle := time.NewTimer(30 * time.Second)
			defer idle.Stop()
			for {
				select {
				case <-outChs[0]:
				case <-outChs[1]:
				case <-errCh:
				case <-idle.C:
					return
				}
				idle.Reset(30 * time.Second)
			}
		}()
	})

	deadline := time.After(2 * time.Minute)
	for {
		if sawR5[0] && sawR5[1] && sawR7[0] && sawR7[1] {
			break
		}
		select {
		case err := <-errCh:
			// A 2-party subset fails in round 9, which needs both round-7
			// messages; the loop stops as soon as both are seen, so any
			// error here came too early.
			t.Fatalf("party error before both round-5 and round-7 emissions were observed: %v", err)
		case <-deadline:
			t.Fatalf("did not observe round-5 and round-7 emissions within timeout")
		case m := <-outChs[0]:
			hook(0, m)
			route(0, m)
		case m := <-outChs[1]:
			hook(1, m)
			route(1, m)
		}
	}
	require.True(t, sawR5[0] && sawR5[1], "both parties must have emitted a round-5 message")
	require.True(t, sawR7[0] && sawR7[1], "both parties must have emitted a round-7 message")
}

// TestSigningSessionFailsClosedMixedMode verifies that a ceremony mixing
// one legacy party with security-v2 peers fails closed with exact culprit
// attribution and no signature. Each security-v2 party verifies its
// peers' range proofs against its session-tagged transcript, so a legacy
// party's untagged proof is the exact rejection culprit from every
// security-v2 party's viewpoint. From the legacy party's viewpoint, every
// security-v2 peer's tagged proof fails under the untagged legacy
// transcript, so its rejection culprit set is exactly every other party.
// Both aborts occur in round 2, the first proof-verification stage.
func TestSigningSessionFailsClosedMixedMode(t *testing.T) {
	const legacyIdx = 0
	n := 3
	threshold := 2

	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(n)
	require.NoError(t, err)

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, n)
	outChs := make([]chan tss.Message, n)
	endChs := make([]chan *common.SignatureData, n)

	ceremonyNonce := big.NewInt(1)
	msg := big.NewInt(42)
	for i := range n {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], n, threshold)
		if i == legacyIdx {
			params.SetProtocolMode(tss.ProtocolModeLegacy)
		} else {
			params.SetProtocolMode(tss.ProtocolModeSecurityV2)
			params.SetSessionNonce(ceremonyNonce)
		}
		// Buffer large enough to hold a full round-1 emission (n messages)
		// and, if the abort regresses, a full round-2 emission (n-1
		// messages) without blocking a Start() call.
		outChs[i] = make(chan tss.Message, 2*n)
		endChs[i] = make(chan *common.SignatureData, 1)
		parties[i] = NewLocalParty(msg, params, keys[i], outChs[i], endChs[i], 32).(*LocalParty)
	}

	startErrs := startAllAndAwait(parties)
	for i, startErr := range startErrs {
		require.Nil(t, startErr, "party %d Start must not fail in round 1", i)
	}

	// Drive the mismatch scenario from both viewpoints: the legacy party
	// and one security-v2 peer.
	msgsForLegacy, msgsForV2 := collectRound1MessagesForTargets(t, parties, outChs, parties[legacyIdx].PartyID(), parties[1].PartyID())

	var lastErrLegacy *tss.Error
	for _, m := range msgsForLegacy {
		if _, err := parties[legacyIdx].Update(m); err != nil {
			lastErrLegacy = err
		}
	}
	var lastErrV2 *tss.Error
	for _, m := range msgsForV2 {
		if _, err := parties[1].Update(m); err != nil {
			lastErrV2 = err
		}
	}

	// The security-v2 peer rejects only the legacy party.
	require.NotNil(t, lastErrV2, "security-v2 peer expected a round-2 rejection")
	require.Equal(t, 2, lastErrV2.Round(), "security-v2 abort must occur in round 2")
	require.Equal(t, indexSet(parties[legacyIdx].PartyID()), culpritIndexSet(lastErrV2),
		"security-v2 peer's culprit set must be exactly the legacy party")

	// The legacy party rejects every security-v2 peer.
	require.NotNil(t, lastErrLegacy, "legacy party expected a round-2 rejection")
	require.Equal(t, 2, lastErrLegacy.Round(), "legacy abort must occur in round 2")
	wantV2Peers := make([]*tss.PartyID, 0, n-1)
	for i, P := range parties {
		if i != legacyIdx {
			wantV2Peers = append(wantV2Peers, P.PartyID())
		}
	}
	require.Equal(t, indexSet(wantV2Peers...), culpritIndexSet(lastErrLegacy),
		"legacy party's culprit set must be exactly the security-v2 peers")

	assertNoSignatureWithinWindow(t, endChs, 500*time.Millisecond)
}

// TestConstructorPanicsWithNoMode verifies that NewLocalParty panics when
// no protocol mode is set on params before construction.
func TestConstructorPanicsWithNoMode(t *testing.T) {
	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(2)
	require.NoError(t, err)

	p2pCtx := tss.NewPeerContext(signPIDs)
	params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[0], 2, 1)
	// Do NOT call SetProtocolMode; params has no mode set.
	// Pass a valid fullBytesLen so the mode check is reached.
	assert.PanicsWithValue(t,
		"tss: protocol mode must be selected before local party construction",
		func() {
			NewLocalParty(big.NewInt(1), params, keys[0], nil, nil, 32)
		},
		"must panic when protocol mode is not set")
}

// TestConstructorPanicsWithLegacyPlusNonce verifies that NewLocalParty
// panics when legacy mode is combined with a session nonce.
func TestConstructorPanicsWithLegacyPlusNonce(t *testing.T) {
	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(2)
	require.NoError(t, err)

	p2pCtx := tss.NewPeerContext(signPIDs)
	params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[0], 2, 1)
	params.SetProtocolMode(tss.ProtocolModeLegacy)
	params.SetSessionNonce(big.NewInt(1)) // not valid with legacy
	assert.PanicsWithValue(t,
		"tss: legacy protocol mode must not set a session nonce",
		func() {
			NewLocalParty(big.NewInt(1), params, keys[0], nil, nil, 32)
		},
		"must panic when legacy mode is combined with a session nonce")
}

// TestConstructorSettersPanicAfterConstruction verifies that the setter
// methods panic when called after the party has been constructed.
func TestConstructorSettersPanicAfterConstruction(t *testing.T) {
	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(2)
	require.NoError(t, err)

	p2pCtx := tss.NewPeerContext(signPIDs)
	params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[0], 2, 1)
	params.SetProtocolMode(tss.ProtocolModeLegacy)

	out := make(chan tss.Message, 1)
	end := make(chan *common.SignatureData, 1)
	P := NewLocalParty(big.NewInt(1), params, keys[0], out, end, 32).(*LocalParty)

	assert.PanicsWithValue(t,
		"tss: protocol mode is immutable after local party construction",
		func() {
			P.params.SetProtocolMode(tss.ProtocolModeSecurityV2)
		},
		"SetProtocolMode must panic after construction")
	assert.PanicsWithValue(t,
		"tss: session nonce is immutable after local party construction",
		func() {
			P.params.SetSessionNonce(big.NewInt(1))
		},
		"SetSessionNonce must panic after construction")
	assert.PanicsWithValue(t,
		"tss: legacy historical Bob compatibility is immutable after local party construction",
		func() {
			P.params.SetLegacyHistoricalBobCompatibility(true)
		},
		"SetLegacyHistoricalBobCompatibility must panic after construction")
}

// TestNewLocalPartyWithKDDCopiesDelta pins that the constructor copies the
// key derivation delta: a caller that later mutates its *big.Int must not
// change the party's signing context.
func TestNewLocalPartyWithKDDCopiesDelta(t *testing.T) {
	keys, signPIDs, err := keygen.LoadKeygenTestFixtures(2)
	require.NoError(t, err)

	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(signPIDs), signPIDs[0], 2, 1)
	params.SetProtocolMode(tss.ProtocolModeLegacy)
	delta := big.NewInt(12345)
	P := NewLocalPartyWithKDD(big.NewInt(1), params, keys[0], delta, nil, nil, 32).(*LocalParty)

	delta.SetInt64(999)
	require.NotNil(t, P.temp.keyDerivationDelta)
	assert.Zero(t, P.temp.keyDerivationDelta.Cmp(big.NewInt(12345)),
		"mutating the caller's delta must not change the party's copy")
}
