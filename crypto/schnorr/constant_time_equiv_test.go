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
	proofOff, err := NewZKProof(u, X)
	assert.NoError(t, err)
	assert.True(t, proofOff.Verify(X), "non-CT Schnorr proof must verify")

	// CT proof must also verify.
	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()
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
	proofOff, err := NewZKVProof(V, R, s, l)
	assert.NoError(t, err)
	assert.True(t, proofOff.Verify(V, R), "non-CT Schnorr V proof must verify")

	// CT proof must also verify.
	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")
	proofOn, err := NewZKVProof(V, R, s, l)
	assert.NoError(t, err)
	assert.True(t, proofOn.Verify(V, R), "CT Schnorr V proof must verify")
}
