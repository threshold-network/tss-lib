// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Per-owner constant-time state cache for Paillier public keys.
//
// The exported PublicKey layout stays immutable (no cache fields, no
// mutex, no new exported struct members), so the reusable state lives here
// instead, keyed by weak.Pointer to the owning key object. On first use, an
// empty entry is installed for the owner before any context is constructed,
// and runtime.AddCleanup removes the entry when the owner object becomes
// unreachable; the cleanup callback's only argument is the weak owner key,
// so neither the map nor the cleanup closure strongly retains the key.
//
// Only public values (N, N^2 and the N^2 constant-time context) are cached.
// Private-key decryption state is deliberately not cached: it measured no
// Decrypt speedup and would keep secret-derived LambdaN copies in
// package-global state (see PrivateKey.Decrypt).
//
// Each entry is initialized exactly once, under its own mutex, for an
// immutable value snapshot of the exported N field. The entry's own mutable
// fields are read and written only under that mutex; the caller's exported
// N is compared by value against the snapshot copy inside the mutex and is
// mutated only sequentially between calls (per the math/big ownership
// rule), never during one. When the caller mutates it, the snapshot
// mismatch triggers a rebuild, so the cache never observes a stale value by
// pointer identity alone.
package paillier

import (
	"math/big"
	"runtime"
	"sync"
	"weak"

	"github.com/bnb-chain/tss-lib/common"
)

// paillierPublicState is the per-PublicKey reuse state: the N^2 value and
// the shared N^2 constant-time context, valid for one N value snapshot.
type paillierPublicState struct {
	mu sync.Mutex

	// snapN is the immutable value snapshot this entry was built from; nil
	// means the entry has not been built for any value yet.
	snapN *big.Int

	n2      *big.Int         // N^2 for snapN
	modN2   *common.CTModInt // lazily built: only needed by constant-time callers
	ctBuilt bool             // modN2 corresponds to the current snapshot
}

var paillierPublicStates sync.Map // weak.Pointer[PublicKey] -> *paillierPublicState

// paillierPublicStateFor returns the receiver's per-owner cache entry,
// installing an empty one (and registering its owner-lifetime cleanup) on
// first use. The hit path is allocation-free: only the miss path allocates
// the entry.
func (publicKey *PublicKey) paillierPublicStateFor() *paillierPublicState {
	wk := weak.Make(publicKey)
	if v, ok := paillierPublicStates.Load(wk); ok {
		return v.(*paillierPublicState)
	}
	state := new(paillierPublicState)
	actual, loaded := paillierPublicStates.LoadOrStore(wk, state)
	if loaded {
		// Lost the race; use the winner's entry and let our throwaway be
		// GC'd without registering a cleanup.
		return actual.(*paillierPublicState)
	}
	// The cleanup's only argument is the weak key: it must never capture
	// publicKey itself, or the entry would strongly retain its own owner.
	runtime.AddCleanup(publicKey, func(k weak.Pointer[PublicKey]) {
		paillierPublicStates.Delete(k)
	}, wk)
	return state
}

// n2Value returns the receiver's current N^2, rebuilding the snapshot only
// when the exported N value has changed.
func (st *paillierPublicState) n2Value(publicKey *PublicKey) (*big.Int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := st.syncLocked(publicKey); err != nil {
		return nil, err
	}
	return st.n2, nil
}

// ctN2 returns the shared N^2 constant-time context for the receiver's
// current N, building the bigmod setup exactly once per N value snapshot.
func (st *paillierPublicState) ctN2(publicKey *PublicKey) (*common.CTModInt, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := st.syncLocked(publicKey); err != nil {
		return nil, err
	}
	if !st.ctBuilt {
		st.modN2 = common.NewCTModInt(st.n2)
		st.ctBuilt = true
	}
	return st.modN2, nil
}

// syncLocked re-validates the modulus precondition and refreshes the
// entry's snapshot (invalidating any derived constant-time context) when
// the exported N value has been mutated or reassigned. Caller holds st.mu.
func (st *paillierPublicState) syncLocked(publicKey *PublicKey) error {
	if err := checkPaillierModulus(publicKey.N); err != nil {
		st.snapN, st.n2, st.modN2, st.ctBuilt = nil, nil, nil, false
		return err
	}
	if st.snapN == nil || st.snapN.Cmp(publicKey.N) != 0 {
		st.snapN = new(big.Int).Set(publicKey.N)
		st.n2 = new(big.Int).Mul(st.snapN, st.snapN)
		st.modN2, st.ctBuilt = nil, false
	}
	return nil
}
