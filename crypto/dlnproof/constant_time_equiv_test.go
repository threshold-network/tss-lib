// Copyright © 2019-2020 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package dlnproof

import (
	"context"
	"math/big"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
)

// TestDLNProofCTVerifies builds a valid ring-Pedersen instance (h2 = h1^alpha mod NTilde)
// exactly as keygen does, then checks that a proof generated with constant-time ops enabled
// still verifies, alongside the standard (non-CT) baseline. The proof is randomised, so this
// asserts correctness of the CT prover; the primitive-level ExpCT==Exp / MulCT==Mul
// equivalence is covered in common/constant_time_test.go.
func TestDLNProofCTVerifies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sgps, err := common.GetRandomSafePrimesConcurrent(ctx, 512, 2, runtime.NumCPU())
	assert.NoError(t, err)
	assert.NotNil(t, sgps)

	P, Q := sgps[0].SafePrime(), sgps[1].SafePrime()
	NTilde := new(big.Int).Mul(P, Q)
	p, q := sgps[0].Prime(), sgps[1].Prime()
	modNTilde := common.ModInt(NTilde)

	f1 := common.GetRandomPositiveRelativelyPrimeInt(NTilde)
	alpha := common.GetRandomPositiveRelativelyPrimeInt(NTilde)
	h1 := modNTilde.Mul(f1, f1)
	h2 := modNTilde.Exp(h1, alpha)

	// Baseline: non-CT proof verifies.
	proofOff := NewDLNProof(h1, h2, alpha, p, q, NTilde)
	assert.True(t, proofOff.Verify(h1, h2, NTilde), "non-CT DLN proof must verify")

	// CT proof must also verify.
	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")
	proofOn := NewDLNProof(h1, h2, alpha, p, q, NTilde)
	assert.True(t, proofOn.Verify(h1, h2, NTilde), "CT DLN proof must verify")
}
