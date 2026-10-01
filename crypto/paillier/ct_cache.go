// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Per-owner constant-time state cache for Paillier key material.
//
// The exported PublicKey / PrivateKey layouts stay immutable (no cache
// fields, no mutex, no new exported struct members), so the reusable state
// lives here instead, keyed by weak.Pointer to the owning key object. On
// first use, an empty entry is installed for the owner before any context
// is constructed, and runtime.AddCleanup removes the entry when the owner
// object becomes unreachable; the cleanup callback's only argument is the
// weak owner key, so neither the map nor the cleanup closure ever strongly
// retains the (potentially private) key it was built from. Secret material
// is never used as a map key -- only the weak key identity is.
//
// Each entry is initialized exactly once, under its own mutex, for an
// immutable value snapshot of the exported N (and, for private keys,
// LambdaN) fields. The entry's own mutable fields are read and written only
// under that mutex; the caller's exported big.Int fields are compared by
// value against the snapshot copies inside the mutex and are mutated only
// sequentially between calls (per the math/big ownership rule), never during
// one. When the caller mutates them, the snapshot mismatch triggers a rebuild, so
// the cache never observes a stale value by pointer identity alone.
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

// paillierPrivateCTView is an immutable snapshot of a private key's
// constant-time decryption state for one (N, LambdaN) value snapshot. The
// fields are not mutated in place: a rebuild replaces them wholesale under
// the entry's mutex. Returned by value so callers can use it without a heap
// allocation per decryption.
type paillierPrivateCTView struct {
	modN2 *common.CTModInt
	// lamExp is the fixed-width LambdaN encoding (big-endian, left-padded
	// to ceil(N.BitLen()/8)) for the constant-time byte-exponent primitive.
	// It is caller-owned storage that lives with this entry; the primitive
	// must read it without retaining, mutating, or wiping it.
	lamExp []byte
	// coeff is the ciphertext-independent decryption coefficient
	// mu = L((N+1)^LambdaN mod N^2)^(-1) mod N.
	coeff *big.Int
}

// paillierPrivateState is the per-PrivateKey reuse state: the public N^2
// state plus the fixed-width LambdaN encoding and decryption coefficient,
// valid for one (N, LambdaN) value snapshot.
type paillierPrivateState struct {
	mu sync.Mutex

	snapN, snapLambda *big.Int

	n2 *big.Int

	modN2  *common.CTModInt
	lamExp []byte
	coeff  *big.Int

	// initErr is the consistent initialization failure for the current
	// snapshot (nil once initialization has succeeded); it is cached so a
	// malformed snapshot returns the same error on every use instead of
	// retrying the work, and so both operation modes agree.
	initErr     error
	initialized bool
}

var paillierPrivateStates sync.Map // weak.Pointer[PrivateKey] -> *paillierPrivateState

// paillierPrivateStateFor returns the receiver's per-owner cache entry,
// installing an empty one (and registering its owner-lifetime cleanup) on
// first use. The hit path is allocation-free: only the miss path allocates
// the entry.
func (privateKey *PrivateKey) paillierPrivateStateFor() *paillierPrivateState {
	wk := weak.Make(privateKey)
	if v, ok := paillierPrivateStates.Load(wk); ok {
		return v.(*paillierPrivateState)
	}
	state := new(paillierPrivateState)
	actual, loaded := paillierPrivateStates.LoadOrStore(wk, state)
	if loaded {
		return actual.(*paillierPrivateState)
	}
	runtime.AddCleanup(privateKey, func(k weak.Pointer[PrivateKey]) {
		paillierPrivateStates.Delete(k)
	}, wk)
	return state
}

// n2Value returns the receiver's current N^2 via the shared cache, without
// requiring the constant-time decryption state to be initialized.
func (st *paillierPrivateState) n2Value(privateKey *PrivateKey) (*big.Int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := st.syncLocked(privateKey, false); err != nil {
		return nil, err
	}
	return st.n2, nil
}

// ctView ensures the constant-time decryption state for the receiver's
// current (N, LambdaN) snapshot -- initializing it exactly once per
// snapshot -- and returns it by value, without a per-call heap allocation.
func (st *paillierPrivateState) ctView(privateKey *PrivateKey) (paillierPrivateCTView, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if err := st.syncLocked(privateKey, true); err != nil {
		return paillierPrivateCTView{}, err
	}
	return paillierPrivateCTView{modN2: st.modN2, lamExp: st.lamExp, coeff: st.coeff}, nil
}

// syncLocked re-validates the private key preconditions, refreshes the
// value snapshot when the exported fields have been mutated or reassigned,
// and -- when wantCT -- initializes the constant-time decryption state
// exactly once per unchanged valid snapshot. Caller holds st.mu.
func (st *paillierPrivateState) syncLocked(privateKey *PrivateKey, wantCT bool) error {
	if err := checkPaillierPrivateKey(privateKey); err != nil {
		st.resetLocked()
		return err
	}
	if st.snapN == nil || st.snapN.Cmp(privateKey.N) != 0 ||
		st.snapLambda == nil || st.snapLambda.Cmp(privateKey.LambdaN) != 0 {
		st.resetLocked()
		st.snapN = new(big.Int).Set(privateKey.N)
		st.snapLambda = new(big.Int).Set(privateKey.LambdaN)
		st.n2 = new(big.Int).Mul(st.snapN, st.snapN)
	}
	if wantCT && !st.initialized {
		st.initErr = st.initCTLocked()
		st.initialized = true
	}
	if st.initErr != nil {
		return st.initErr
	}
	return nil
}

// initCTLocked builds the N^2 constant-time context, the fixed-width
// LambdaN encoding, and the ciphertext-independent decryption coefficient
// for the current snapshot. Caller holds st.mu; snapN/snapLambda/n2 are
// already set.
func (st *paillierPrivateState) initCTLocked() error {
	// N^2 is odd and > 1: guaranteed by checkPaillierPrivateKey.
	st.modN2 = common.NewCTModInt(st.n2)

	// Fixed-width LambdaN encoding: a caller-owned big-endian zero-padded
	// buffer at ceil(N.BitLen()/8) bytes, the same layout the legacy
	// per-call exponent padding used. checkPaillierPrivateKey already
	// proved LambdaN.BitLen() <= N.BitLen(), so the value fits.
	width := (st.snapN.BitLen() + 7) / 8
	st.lamExp = make([]byte, width)
	st.snapLambda.FillBytes(st.lamExp)

	// Decryption coefficient mu = L((N+1)^LambdaN mod N^2)^(-1) mod N: by
	// the binomial identity (N+1)^LambdaN == 1 + LambdaN*N (mod N^2), the
	// coefficient's numerator is LambdaN mod N, and its inverse is
	// independent of any ciphertext -- computed once per unchanged key
	// value snapshot instead of on every decryption.
	lg := new(big.Int).Mod(st.snapLambda, st.snapN)
	coeff := common.NewCTModIntWithPhi(st.snapN, st.snapLambda).ModInverseCT(lg)
	if coeff == nil {
		// A non-invertible coefficient means the key material is
		// malformed: the same error is returned on every use of this
		// snapshot, in both operation modes.
		st.modN2, st.lamExp = nil, nil
		return ErrMalformedKey
	}
	st.coeff = coeff
	return nil
}

// resetLocked discards the derived state (and the value snapshot) so the
// next valid use rebuilds from scratch. Caller holds st.mu.
func (st *paillierPrivateState) resetLocked() {
	st.snapN, st.snapLambda = nil, nil
	st.n2, st.modN2, st.lamExp, st.coeff = nil, nil, nil, nil
	st.initErr, st.initialized = nil, false
}
