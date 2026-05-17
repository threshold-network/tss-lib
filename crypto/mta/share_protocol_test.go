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

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
)

func TestShareProtocol(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	a := common.GetRandomPositiveInt(q)
	b := common.GetRandomPositiveInt(q)

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(t, err)

	cA, pf, err := AliceInit(tss.EC(), pk, a, NTildej, h1j, h2j)
	assert.NoError(t, err)

	_, cB, betaPrm, pfB, err := BobMid(tss.EC(), pk, pf, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j)
	assert.NoError(t, err)

	alpha, err := AliceEnd(tss.EC(), pk, pfB, h1i, h2i, cA, cB, NTildei, sk)
	assert.NoError(t, err)

	// expect: alpha = ab + betaPrm
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, betaPrm)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(aTimesBPlusBetaModQ))
}

func TestShareProtocolWC(t *testing.T) {
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

	cA, pf, err := AliceInit(tss.EC(), pk, a, NTildej, h1j, h2j)
	assert.NoError(t, err)

	gBPoint, err := crypto.NewECPoint(tss.EC(), gBX, gBY)
	assert.NoError(t, err)
	_, cB, betaPrm, pfB, err := BobMidWC(tss.EC(), pk, pf, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j, gBPoint)
	assert.NoError(t, err)
	assert.True(t, pfB.Verify(tss.EC(), pk, NTildei, h1i, h2i, cA, cB, gBPoint))

	badS1 := cloneProofBobWC(pfB)
	badS1.S1 = new(big.Int).Sub(q, big.NewInt(1))
	assert.False(t, badS1.Verify(tss.EC(), pk, NTildei, h1i, h2i, cA, cB, gBPoint), "S1 below q must fail")

	badV := cloneProofBobWC(pfB)
	badV.V = big.NewInt(0)
	assert.False(t, badV.Verify(tss.EC(), pk, NTildei, h1i, h2i, cA, cB, gBPoint), "V equal to zero must fail")

	wrongCurveX := crypto.NewECPointNoCurveCheck(tss.Edwards(), gBPoint.X(), gBPoint.Y())
	assert.False(t, pfB.Verify(tss.EC(), pk, NTildei, h1i, h2i, cA, cB, wrongCurveX), "X on a different curve must fail")

	alpha, err := AliceEndWC(tss.EC(), pk, pfB, gBPoint, cA, cB, NTildei, h1i, h2i, sk)
	assert.NoError(t, err)

	// expect: alpha = ab + betaPrm
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, betaPrm)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(aTimesBPlusBetaModQ))
}

func cloneProofBobWC(pf *ProofBobWC) *ProofBobWC {
	return &ProofBobWC{
		ProofBob: &ProofBob{
			Z:    new(big.Int).Set(pf.Z),
			ZPrm: new(big.Int).Set(pf.ZPrm),
			T:    new(big.Int).Set(pf.T),
			V:    new(big.Int).Set(pf.V),
			W:    new(big.Int).Set(pf.W),
			S:    new(big.Int).Set(pf.S),
			S1:   new(big.Int).Set(pf.S1),
			S2:   new(big.Int).Set(pf.S2),
			T1:   new(big.Int).Set(pf.T1),
			T2:   new(big.Int).Set(pf.T2),
		},
		U: pf.U,
	}
}
