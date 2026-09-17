// Copyright © 2019-2026 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

// init enables constant-time cryptographic operations unconditionally for this
// fork, closing the timing side-channel described in constant_time.go by
// default rather than leaving it opt-in.
//
// Upstream ships EnableConstantTimeOps disabled by default with no in-tree
// caller: the capability exists but nothing turns it on. This fork's
// maintainers decided every consumer should get the fix automatically,
// accepting the constant-time CPU cost on secret-exponent operations
// (Paillier, DLN, MtA, Schnorr, and the affected keygen/signing rounds) in
// exchange for closing the leak without requiring a coordinated opt-in change
// in every downstream caller (e.g. threshold-network/keep-core).
//
// Callers who have measured this cost and explicitly accept the timing risk
// may call DisableConstantTimeOps() themselves; this is not recommended for
// production custody use.
func init() {
	EnableConstantTimeOps()
}
