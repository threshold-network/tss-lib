// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss

import (
	"crypto/elliptic"
	"math/big"
	"runtime"
	"time"

	"github.com/bnb-chain/tss-lib/common"
)

type (
	Parameters struct {
		ec                  elliptic.Curve
		partyID             *PartyID
		parties             *PeerContext
		partyCount          int
		threshold           int
		concurrency         int
		safePrimeGenTimeout time.Duration
		// sessionNonce provides per-session SSID uniqueness for GG20 proof
		// binding. Keygen and signing require callers to coordinate a shared
		// positive nonce before Start.
		sessionNonce *big.Int
	}
)

const (
	defaultSafePrimeGenTimeout = 5 * time.Minute
)

// Exported, used in `tss` client
func NewParameters(ec elliptic.Curve, ctx *PeerContext, partyID *PartyID, partyCount, threshold int) *Parameters {
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

// SessionNonce returns the optional per-session nonce used in proof challenges.
func (params *Parameters) SessionNonce() *big.Int {
	return params.sessionNonce
}

// SetSessionNonce sets a per-session nonce that all parties in a protocol run
// must agree on. It must be called before Start.
//
// Keygen and signing fail closed if no nonce is set. The previous zero
// (keygen) and SHA512_256(messageBytes) (signing) fallbacks caused two
// ceremonies with otherwise-identical inputs to derive the same SSID, breaking
// the session-binding property that the proofs rely on. The caller must supply
// a per-ceremony unique nonce; reusing the same nonce across distinct
// ceremonies on the same inputs reintroduces transcript-splicing risk. Set the
// nonce before Start on the same goroutine that constructs the party; do not
// mutate Parameters concurrently with a running protocol.
func (params *Parameters) SetSessionNonce(nonce *big.Int) {
	if nonce == nil || nonce.Sign() <= 0 {
		panic("tss: session nonce must be positive")
	}
	params.sessionNonce = new(big.Int).Set(nonce)
}

// SetSessionNonceBytes hashes an application-level session ID into the
// per-session nonce. All parties must call it with the same high-entropy
// session ID before constructing local parties for a protocol run. It panics if
// the session ID is shorter than 16 bytes.
func (params *Parameters) SetSessionNonceBytes(sessionID []byte) {
	if len(sessionID) < 16 {
		panic("tss: session ID must be at least 16 bytes")
	}
	params.SetSessionNonce(new(big.Int).SetBytes(common.SHA512_256(sessionID)))
}
