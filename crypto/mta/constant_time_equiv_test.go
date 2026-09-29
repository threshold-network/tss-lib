// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// These tests verify that the MtA flow run with constant-time ops enabled — which
// hardens the secret-witness exponentiations h1^x, h1^y (proofs.go) and h1^m
// (range_proof.go), plus the secret-exponent Paillier Encrypt (gamma^m) and HomoMult
// (c1^m) — still produces verifying proofs and the correct homomorphic result. The
// proofs are randomised, so outputs are not byte-identical across paths; the protocol
// completing and the result matching is the invariant. Primitive ExpCT==Exp / MulCT==Mul
// equivalence is covered in common/constant_time_test.go.

// TestShareProtocolWCConstantTime runs the full MtA "with check" share protocol with
// constant-time ops enabled. It exercises ProveRangeAlice (h1^m via AliceInit),
// ProveBobWC (h1^x, h1^y with x=b, y=betaPrm via BobMidWC), and the CT Paillier
// Encrypt/HomoMult paths, with proof verification happening inside BobMidWC/AliceEndWC.
func TestShareProtocolWCConstantTime(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	a := common.GetRandomPositiveInt(q)
	b := common.GetRandomPositiveInt(q)
	gBX, gBY := tss.EC().ScalarBaseMult(b.Bytes())

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(t, err)

	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")

	cA, pf, err := AliceInit(tss.EC(), pk, a, NTildej, h1j, h2j)
	assert.NoError(t, err)

	gBPoint, err := crypto.NewECPoint(tss.EC(), gBX, gBY)
	assert.NoError(t, err)
	_, cB, betaPrm, pfB, err := BobMidWC(tss.EC(), pk, pf, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j, gBPoint)
	assert.NoError(t, err)

	alpha, err := AliceEndWC(tss.EC(), pk, pfB, gBPoint, cA, cB, NTildei, h1i, h2i, sk)
	assert.NoError(t, err)

	// expect: alpha = ab + betaPrm (mod q) — proves the CT-hardened proofs verified and
	// the CT Encrypt/HomoMult produced the correct homomorphic ciphertext.
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, betaPrm)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(aTimesBPlusBetaModQ), "constant-time MtA must yield alpha = ab + betaPrm")
}
