// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
	"runtime"
	"time"

	"github.com/bnb-chain/tss-lib/common"
)

type (
	// ProtocolMode selects the wire-compatible GG20 proof transcript used by
	// an ECDSA local party. It is configured per Parameters value before the
	// party is constructed and frozen for that party's lifetime.
	ProtocolMode uint8

	Parameters struct {
		ec                  elliptic.Curve
		partyID             *PartyID
		parties             *PeerContext
		partyCount          int
		threshold           int
		concurrency         int
		safePrimeGenTimeout time.Duration
		// sessionNonce provides per-session SSID uniqueness for security-v2
		// GG20 proof binding. Security-v2 keygen and signing require callers
		// to coordinate a shared positive nonce before Start; legacy mode must
		// leave it unset.
		sessionNonce *big.Int
		// protocolMode is the explicit per-party proof-transcript mode. It has
		// no default: callers must select legacy or security-v2 before
		// constructing an ECDSA local party.
		protocolMode       ProtocolMode
		protocolModeFrozen bool
	}
)

const (
	defaultSafePrimeGenTimeout = 5 * time.Minute

	// ProtocolModeLegacy reproduces the untagged GG20 proof transcript used
	// before session binding was introduced.
	ProtocolModeLegacy ProtocolMode = 1
	// ProtocolModeSecurityV2 requires and uses the session-bound, domain-tagged
	// GG20 proof transcript.
	ProtocolModeSecurityV2 ProtocolMode = 2
)

// Exported, used in `tss` client
func NewParameters(ec elliptic.Curve, ctx *PeerContext, partyID *PartyID, partyCount, threshold int) *Parameters {
	if partyCount < 2 {
		panic("tss: party count must be at least 2")
	}
	if threshold < 1 {
		panic("tss: threshold must be at least 1")
	}
	if threshold >= partyCount {
		panic("tss: threshold must be less than party count")
	}
	assertDistinctIDsModQ(ec, ctx)
	return &Parameters{
		ec:                  ec,
		parties:             ctx,
		partyID:             partyID,
		partyCount:          partyCount,
		threshold:           threshold,
		concurrency:         runtime.GOMAXPROCS(0),
		safePrimeGenTimeout: defaultSafePrimeGenTimeout,
	}
}

func assertDistinctIDsModQ(ec elliptic.Curve, ctx *PeerContext) {
	if ec == nil || ctx == nil {
		return
	}
	q := ec.Params().N
	seen := make(map[string]*PartyID, len(ctx.IDs()))
	for _, partyID := range ctx.IDs() {
		if partyID == nil || partyID.Key == nil {
			continue
		}
		residue := new(big.Int).Mod(partyID.KeyInt(), q)
		if residue.Sign() == 0 {
			panic(fmt.Errorf("tss: party %s has key congruent to 0 mod q", partyID))
		}
		key := residue.Text(16)
		if previous, exists := seen[key]; exists {
			panic(fmt.Errorf("tss: party keys for %s and %s collide mod q", previous, partyID))
		}
		seen[key] = partyID
	}
}

func (params *Parameters) EC() elliptic.Curve {
	return params.ec
}

func (params *Parameters) Parties() *PeerContext {
	return params.parties
}

func (params *Parameters) PartyID() *PartyID {
	return params.partyID
}

func (params *Parameters) PartyCount() int {
	return params.partyCount
}

func (params *Parameters) Threshold() int {
	return params.threshold
}

func (params *Parameters) Concurrency() int {
	return params.concurrency
}

func (params *Parameters) SafePrimeGenTimeout() time.Duration {
	return params.safePrimeGenTimeout
}

// The concurrency level must be >= 1.
func (params *Parameters) SetConcurrency(concurrency int) {
	params.concurrency = concurrency
}

func (params *Parameters) SetSafePrimeGenTimeout(timeout time.Duration) {
	params.safePrimeGenTimeout = timeout
}

// ProtocolMode returns the explicit per-party proof-transcript mode.
func (params *Parameters) ProtocolMode() ProtocolMode {
	return params.protocolMode
}

// SetProtocolMode selects the proof transcript for the ECDSA local party that
// will be constructed from params. There is no implicit/default mode.
//
// A local party freezes this setting during construction. Changing it
// afterwards panics so an in-flight party can never switch transcripts.
func (params *Parameters) SetProtocolMode(mode ProtocolMode) {
	if params.protocolModeFrozen {
		panic("tss: protocol mode is immutable after local party construction")
	}
	switch mode {
	case ProtocolModeLegacy, ProtocolModeSecurityV2:
	default:
		panic(fmt.Sprintf("tss: invalid protocol mode %d", mode))
	}
	if params.protocolMode != 0 && params.protocolMode != mode {
		panic("tss: protocol mode cannot be changed after selection")
	}
	params.protocolMode = mode
}

// FreezeProtocolMode validates and freezes the transcript configuration.
// ECDSA local-party constructors call it before retaining params.
func (params *Parameters) FreezeProtocolMode() {
	if params.protocolModeFrozen {
		return
	}
	switch params.protocolMode {
	case ProtocolModeLegacy:
		if params.sessionNonce != nil {
			panic("tss: legacy protocol mode must not set a session nonce")
		}
	case ProtocolModeSecurityV2:
	default:
		panic("tss: protocol mode must be selected before local party construction")
	}
	params.protocolModeFrozen = true
}

// SessionNonce returns a defensive copy of the optional per-session nonce used
// in proof challenges.
func (params *Parameters) SessionNonce() *big.Int {
	if params.sessionNonce == nil {
		return nil
	}
	return new(big.Int).Set(params.sessionNonce)
}

// SetSessionNonce sets a per-session nonce that all security-v2 parties in a
// protocol run must agree on. It must be called before constructing the local
// party. Legacy parties must not set a nonce.
//
// Keygen and signing fail closed if no nonce is set. The previous zero
// (keygen) and SHA512_256(messageBytes) (signing) fallbacks caused two
// ceremonies with otherwise-identical inputs to derive the same SSID, breaking
// the session-binding property that the proofs rely on. The caller must supply
// a per-ceremony unique nonce; reusing the same nonce across distinct
// ceremonies on the same inputs reintroduces transcript-splicing risk. Set the
// nonce before constructing the party on the same goroutine; do not mutate
// Parameters concurrently with a running protocol.
func (params *Parameters) SetSessionNonce(nonce *big.Int) {
	if params.protocolModeFrozen {
		panic("tss: session nonce is immutable after local party construction")
	}
	if nonce == nil || nonce.Sign() <= 0 {
		panic("tss: session nonce must be positive")
	}
	params.sessionNonce = new(big.Int).Set(nonce)
}

// SetSessionNonceBytes hashes an application-level session ID into the
// per-session nonce. All parties must call it with the same session ID before
// constructing local parties for a protocol run.
//
// The session ID must be:
//
//   - At least 16 bytes (enforced by panic). 16 bytes = 128 bits is the
//     birthday-bound minimum below which random collisions become plausible.
//   - Unique per ceremony. Reusing the same session ID across two distinct
//     ceremonies on the same inputs reintroduces the transcript-splicing risk
//     that the session-binding contract is meant to prevent.
//   - Drawn from a high-entropy source for collision resistance. The bytes are
//     hashed through SHA512_256 to a 256-bit nonce; if the application uses
//     structured IDs (timestamps, counters, slot numbers), prefer concatenating
//     them with a per-ceremony random seed so two ceremonies cannot collide
//     under the hash.
//
// Callers that already have an unpredictable big.Int (e.g., a draw from a
// CSPRNG) can pass it through SetSessionNonce directly instead.
func (params *Parameters) SetSessionNonceBytes(sessionID []byte) {
	if len(sessionID) < 16 {
		panic("tss: session ID must be at least 16 bytes")
	}
	params.SetSessionNonce(new(big.Int).SetBytes(common.SHA512_256(sessionID)))
}
