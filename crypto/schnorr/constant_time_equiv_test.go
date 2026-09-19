// Copyright © 2019-2026 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package schnorr_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	. "github.com/bnb-chain/tss-lib/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/tss"
)

// withCTMode saves the ambient constant-time mode, sets it to `enabled`, and
// restores the saved mode on cleanup. CT is enabled by default in this package,
// so tests that want a genuine non-CT baseline must disable it explicitly rather
// than assume it is off; restoring afterwards keeps coverage independent of test
// order and preserves default-path coverage for the other Schnorr tests.
func withCTMode(t *testing.T, enabled bool) {
	t.Helper()
	prev := common.IsConstantTimeEnabled()
	if enabled {
		common.EnableConstantTimeOps()
	} else {
		common.DisableConstantTimeOps()
	}
	t.Cleanup(func() {
		if prev {
			common.EnableConstantTimeOps()
		} else {
			common.DisableConstantTimeOps()
		}
	})
}

// TestSchnorrProofCTVerifies builds a valid ZK proof instance exactly as
// TestSchnorrProofVerify does, then checks that a proof generated with
// constant-time ops enabled still verifies, alongside the standard (non-CT)
// baseline. The proof is randomised, so this asserts correctness of the CT
// prover; the primitive-level ExpCT==Exp / MulCT==Mul equivalence is covered
// in common/constant_time_test.go.
func TestSchnorrProofCTVerifies(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	// Baseline: non-CT proof verifies.
	withCTMode(t, false)
	assert.False(t, common.IsConstantTimeEnabled(), "CT must be off for the baseline")
	proofOff, err := NewZKProof(u, X)
	assert.NoError(t, err)
	assert.True(t, proofOff.Verify(X), "non-CT Schnorr proof must verify")

	// CT proof must also verify.
	withCTMode(t, true)
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")
	proofOn, err := NewZKProof(u, X)
	assert.NoError(t, err)
	assert.True(t, proofOn.Verify(X), "CT Schnorr proof must verify")
}

// TestSchnorrVProofCTVerifies is the ZKVProof analogue of
// TestSchnorrProofCTVerifies.
func TestSchnorrVProofCTVerifies(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(q)
	s := common.GetRandomPositiveInt(q)
	l := common.GetRandomPositiveInt(q)
	R := crypto.ScalarBaseMult(tss.EC(), k)
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(tss.EC(), l)
	V, err := Rs.Add(lG)
	assert.NoError(t, err)

	// Baseline: non-CT proof verifies.
	withCTMode(t, false)
	assert.False(t, common.IsConstantTimeEnabled(), "CT must be off for the baseline")
	proofOff, err := NewZKVProof(V, R, s, l)
	assert.NoError(t, err)
	assert.True(t, proofOff.Verify(V, R), "non-CT Schnorr V proof must verify")

	// CT proof must also verify.
	withCTMode(t, true)
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")
	proofOn, err := NewZKVProof(V, R, s, l)
	assert.NoError(t, err)
	assert.True(t, proofOn.Verify(V, R), "CT Schnorr V proof must verify")
}
