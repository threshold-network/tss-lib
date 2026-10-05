// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/tss"
)

// ----- Constructor protocol-mode enforcement -----

// assertPanicsWith runs fn and fails unless it panics with exactly message.
func assertPanicsWith(t *testing.T, message string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		require.Equal(t, message, r, "panic value must equal the expected message")
	}()
	fn()
}

// TestNewLocalPartyRequiresProtocolMode pins the constructor-level
// enforcement of the explicit protocol-mode rule: building a keygen party
// without a selected mode, or with a legacy mode plus a session nonce,
// panics synchronously at the call site instead of silently picking a
// transcript.
func TestNewLocalPartyRequiresProtocolMode(t *testing.T) {
	pIDs := tss.GenerateTestPartyIDs(2)
	p2pCtx := tss.NewPeerContext(pIDs)

	modeless := tss.NewParameters(tss.S256(), p2pCtx, pIDs[0], 2, 1)
	// No protocol mode selected: the constructor must fail fast.
	assertPanicsWith(t, "tss: protocol mode must be selected before local party construction",
		func() {
			_ = NewLocalParty(modeless, nil, nil)
		})

	legacyWithNonce := tss.NewParameters(tss.S256(), p2pCtx, pIDs[0], 2, 1)
	legacyWithNonce.SetProtocolMode(tss.ProtocolModeLegacy)
	legacyWithNonce.SetSessionNonce(big.NewInt(1))
	assertPanicsWith(t, "tss: legacy protocol mode must not set a session nonce",
		func() {
			_ = NewLocalParty(legacyWithNonce, nil, nil)
		})

	// A security-v2 party with a nonce must construct without panicking, so
	// the two panics above are not vacuous.
	securityV2 := tss.NewParameters(tss.S256(), p2pCtx, pIDs[0], 2, 1)
	securityV2.SetProtocolMode(tss.ProtocolModeSecurityV2)
	securityV2.SetSessionNonce(big.NewInt(1))
	require.NotPanics(t, func() {
		_ = NewLocalParty(securityV2, nil, nil)
	})
}

// TestNewLocalPartyFreezesProtocolMode pins that the constructor freezes the
// transcript configuration: after construction the mode, the session nonce,
// and the legacy historical-Bob opt-in are all immutable on the party's own
// Parameters.
func TestNewLocalPartyFreezesProtocolMode(t *testing.T) {
	pIDs := tss.GenerateTestPartyIDs(2)
	p2pCtx := tss.NewPeerContext(pIDs)

	params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[0], 2, 1)
	params.SetProtocolMode(tss.ProtocolModeSecurityV2)
	params.SetSessionNonce(big.NewInt(1))
	_ = NewLocalParty(params, nil, nil)

	assertPanicsWith(t, "tss: protocol mode is immutable after local party construction",
		func() {
			params.SetProtocolMode(tss.ProtocolModeLegacy)
		})
	assertPanicsWith(t, "tss: session nonce is immutable after local party construction",
		func() {
			params.SetSessionNonce(big.NewInt(2))
		})
	assertPanicsWith(t, "tss: legacy historical Bob compatibility is immutable after local party construction",
		func() {
			params.SetLegacyHistoricalBobCompatibility(true)
		})
}

// ----- Legacy / security-v2 proof transcript selection -----

// keygenBaseForMode builds a bare base round in the given mode with the
// session state round1.Start would establish: security-v2 derives
// round.temp.ssid from the nonce, legacy leaves it nil.
func keygenBaseForMode(t *testing.T, mode tss.ProtocolMode, nonce *big.Int, pIDs tss.SortedPartyIDs) *base {
	t.Helper()

	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(pIDs), pIDs[0], len(pIDs), 1)
	params.SetProtocolMode(mode)
	temp := &localTempData{}
	if nonce != nil {
		params.SetSessionNonce(nonce)
		temp.ssidNonce = new(big.Int).Set(nonce)
	}
	round := &base{
		Parameters: params,
		temp:       temp,
		number:     1,
	}
	if mode == tss.ProtocolModeSecurityV2 {
		round.temp.ssid = round.getSSID()
	}
	return round
}

// TestKeygenProofTranscriptSelection pins the legacy keygen transcript
// selection: legacy rounds pass no proof session or per-party context so the
// proof primitives reproduce their historical untagged challenges, while
// security-v2 rounds use the ssid and the ssid+index contexts.
func TestKeygenProofTranscriptSelection(t *testing.T) {
	pIDs := tss.GenerateTestPartyIDs(3)

	legacy := keygenBaseForMode(t, tss.ProtocolModeLegacy, nil, pIDs)
	require.Nil(t, legacy.proofSession(), "legacy keygen must pass no proof session")
	require.Nil(t, legacy.proofContext(1), "legacy keygen must pass no per-party proof context")
	require.Nil(t, legacy.proofContext(2), "legacy keygen must pass no per-party proof context")

	v2 := keygenBaseForMode(t, tss.ProtocolModeSecurityV2, big.NewInt(42), pIDs)
	require.Len(t, v2.temp.ssid, 32, "security-v2 ssid must be the full 32-byte digest")
	require.Equal(t, [][]byte{v2.temp.ssid}, v2.proofSession(),
		"security-v2 proof session must be the ssid alone")

	// The per-party context must be the ssid with the producer index
	// appended and must differ per index.
	ctx1 := v2.proofContext(1)
	ctx2 := v2.proofContext(2)
	require.Len(t, ctx1, 1)
	require.Len(t, ctx2, 1)
	require.Equal(t, common.AppendUint64ToBytesSlice(v2.temp.ssid, 1), ctx1[0])
	require.Equal(t, common.AppendUint64ToBytesSlice(v2.temp.ssid, 2), ctx2[0])
	assert.NotEqual(t, ctx1, ctx2, "contexts must differ per producing party index")

	// An independently constructed round over identical inputs must derive
	// the same ssid and per-party contexts, so a derivation change in
	// getSSID or proofContext is caught here rather than only in the E2E.
	recomputed := keygenBaseForMode(t, tss.ProtocolModeSecurityV2, big.NewInt(42), pIDs)
	require.Equal(t, v2.temp.ssid, recomputed.temp.ssid,
		"ssid derivation must be deterministic for identical inputs")
	require.Equal(t, v2.proofContext(1), recomputed.proofContext(1),
		"per-party context must match the getSSID derivation")
}

// ----- Mixed-mode keygen ceremony -----

// TestMixedModeKeygenFailsClosed pins that a ceremony mixing one legacy
// party with security-v2 peers fails closed on both sides: each side's
// round-2 proof verification attributes the opposing mode as the culprit,
// and no party ever produces save data. The legacy party emits historical
// untagged proofs; the security-v2 party verifies them under its
// ssid-tagged transcript (and vice versa), so every cross-verification is a
// guaranteed mismatch. The ceremony stops at the first fatal round-2 error
// so the test stays short; the round-2 message leg is covered by the
// mixed-binary CI harness instead.
func TestMixedModeKeygenFailsClosed(t *testing.T) {
	setUp("info")

	fixtures, pIDs, err := LoadKeygenTestFixtures(2)
	if err != nil {
		t.Skip("keygen test fixtures are required (avoids safe-prime generation)")
	}
	require.Equal(t, 2, len(fixtures))

	p2pCtx := tss.NewPeerContext(pIDs)

	// Party 0 is security-v2 with the per-ceremony nonce; party 1 is legacy
	// and deliberately gets no nonce.
	v2Params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[0], 2, 1)
	v2Params.SetProtocolMode(tss.ProtocolModeSecurityV2)
	v2Params.SetSessionNonce(big.NewInt(7))
	legacyParams := tss.NewParameters(tss.S256(), p2pCtx, pIDs[1], 2, 1)
	legacyParams.SetProtocolMode(tss.ProtocolModeLegacy)

	// Each party emits exactly one round-1 broadcast; the buffers make both
	// Starts non-blocking.
	outV2 := make(chan tss.Message, 2)
	outLegacy := make(chan tss.Message, 2)
	endCh := make(chan LocalPartySaveData, 2)

	v2Party := NewLocalParty(v2Params, outV2, endCh, fixtures[0].LocalPreParams).(*LocalParty)
	legacyParty := NewLocalParty(legacyParams, outLegacy, endCh, fixtures[1].LocalPreParams).(*LocalParty)

	// Round 1: both parties start successfully and emit their broadcasts.
	require.Nil(t, v2Party.Start(), "security-v2 party round-1 Start must not fail")
	require.Nil(t, legacyParty.Start(), "legacy party round-1 Start must not fail")
	msgV2 := <-outV2
	msgLegacy := <-outLegacy

	// Deliver the round-1 messages; each Update advances into round 2, where
	// the cross-verification of the mismatched transcripts fails.
	_, updV2Err := v2Party.Update(parseMessage(t, msgLegacy))
	_, updLegacyErr := legacyParty.Update(parseMessage(t, msgV2))

	// The security-v2 party aborts in round 2 and attributes the legacy
	// party as the sole culprit.
	require.NotNil(t, updV2Err, "security-v2 party must fail the mixed ceremony")
	require.Equal(t, 2, updV2Err.Round(), "mixed-mode abort must occur in round 2")
	require.Len(t, updV2Err.Culprits(), 1, "security-v2 culprit set must contain exactly one party")
	assert.Equal(t, legacyParty.PartyID().Index, updV2Err.Culprits()[0].Index,
		"security-v2 culprit must be the legacy party")

	// The legacy party aborts in round 2 and attributes the security-v2
	// party as the sole culprit.
	require.NotNil(t, updLegacyErr, "legacy party must fail the mixed ceremony")
	require.Equal(t, 2, updLegacyErr.Round(), "mixed-mode abort must occur in round 2")
	require.Len(t, updLegacyErr.Culprits(), 1, "legacy culprit set must contain exactly one party")
	assert.Equal(t, v2Party.PartyID().Index, updLegacyErr.Culprits()[0].Index,
		"legacy culprit must be the security-v2 party")

	// Round-2 starts fail before emitting any round-2 messages, so the out
	// channels hold only the round-1 broadcasts drained above.
	require.Empty(t, outV2, "security-v2 party emitted a round-2 message before aborting")
	require.Empty(t, outLegacy, "legacy party emitted a round-2 message before aborting")

	// No party may ever produce save data.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	select {
	case save := <-endCh:
		t.Fatalf("mixed-mode ceremony produced save data: %+v", save)
	case <-ctx.Done():
	}
}

// parseMessage parses a wire message for delivery to a receiver, mirroring
// test.SharedPartyUpdater without the error-channel side effect.
func parseMessage(t *testing.T, msg tss.Message) tss.ParsedMessage {
	t.Helper()
	bz, _, err := msg.WireBytes()
	require.NoError(t, err, "wire encoding must succeed")
	parsed, err := tss.ParseWireMessage(bz, msg.GetFrom(), msg.IsBroadcast())
	require.NoError(t, err, "wire parsing must succeed")
	return parsed
}
