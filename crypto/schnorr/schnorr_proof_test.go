// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package schnorr_test

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	. "github.com/bnb-chain/tss-lib/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/tss"
)

func TestSchnorrProof(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	uG := crypto.ScalarBaseMult(tss.EC(), u)
	proof, _ := NewZKProof(u, uG)

	assert.True(t, proof.Alpha.IsOnCurve())
	assert.NotZero(t, proof.Alpha.X())
	assert.NotZero(t, proof.Alpha.Y())
	assert.NotZero(t, proof.T)
}

func TestSchnorrProofVerify(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	proof, _ := NewZKProof(u, X)
	res := proof.Verify(X)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrProofVerifyAllowsUnregisteredCurve(t *testing.T) {
	ec := elliptic.P256()
	q := ec.Params().N
	u := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(ec, u)

	proof, err := NewZKProof(u, X)
	assert.NoError(t, err)
	assert.True(t, proof.Verify(X), "ZK proof must verify on an unregistered curve")
}

func TestSchnorrProofVerifySessionBinding(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	session := []byte("schnorr-session-a")
	proof, _ := NewZKProofWithSession(session, u, X)

	assert.True(t, proof.VerifyWithSession(session, X), "verify result must be true with the original session")
	assert.False(t, proof.VerifyWithSession([]byte("schnorr-session-b"), X), "proof must not replay across sessions")
	assert.False(t, proof.Verify(X), "session-bound proof must not verify without its session")
}

func TestSchnorrProofVerifyBadX(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	u2 := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)
	X2 := crypto.ScalarBaseMult(tss.EC(), u2)

	proof, _ := NewZKProof(u2, X2)
	res := proof.Verify(X)

	assert.False(t, res, "verify result must be false")
}

func TestSchnorrProofVerifyRejectsInvalidInputs(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	proof, _ := NewZKProof(u, X)

	assert.False(t, proof.Verify(nil), "nil public point must fail")
	assert.False(t, proof.Verify(crypto.NewECPointNoCurveCheck(tss.EC(), big.NewInt(1), big.NewInt(1))), "off-curve public point must fail")

	proof.T = big.NewInt(0)
	assert.NotPanics(t, func() {
		assert.False(t, proof.Verify(X), "zero proof scalar must fail")
	})
}

func TestSchnorrVProofVerify(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(q)
	s := common.GetRandomPositiveInt(q)
	l := common.GetRandomPositiveInt(q)
	R := crypto.ScalarBaseMult(tss.EC(), k) // k_-1 * G
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(tss.EC(), l)
	V, _ := Rs.Add(lG)

	proof, _ := NewZKVProof(V, R, s, l)
	res := proof.Verify(V, R)

	assert.True(t, res, "verify result must be true")
}

func TestSchnorrVProofVerifyAllowsUnregisteredCurve(t *testing.T) {
	ec := elliptic.P256()
	q := ec.Params().N
	k := common.GetRandomPositiveInt(q)
	s := common.GetRandomPositiveInt(q)
	l := common.GetRandomPositiveInt(q)
	R := crypto.ScalarBaseMult(ec, k)
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(ec, l)
	V, _ := Rs.Add(lG)

	proof, err := NewZKVProof(V, R, s, l)
	assert.NoError(t, err)
	assert.True(t, proof.Verify(V, R), "ZKV proof must verify on an unregistered curve")
}

func TestSchnorrVProofVerifyRejectsZeroScalars(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(q)
	s := common.GetRandomPositiveInt(q)
	l := common.GetRandomPositiveInt(q)
	R := crypto.ScalarBaseMult(tss.EC(), k)
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(tss.EC(), l)
	V, _ := Rs.Add(lG)

	proof, _ := NewZKVProof(V, R, s, l)
	proof.T = big.NewInt(0)
	assert.NotPanics(t, func() {
		assert.False(t, proof.Verify(V, R), "zero T must fail")
	})

	proof, _ = NewZKVProof(V, R, s, l)
	proof.U = big.NewInt(0)
	assert.NotPanics(t, func() {
		assert.False(t, proof.Verify(V, R), "zero U must fail")
	})
}

func TestSchnorrVProofVerifySessionBinding(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(q)
	s := common.GetRandomPositiveInt(q)
	l := common.GetRandomPositiveInt(q)
	R := crypto.ScalarBaseMult(tss.EC(), k) // k_-1 * G
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(tss.EC(), l)
	V, _ := Rs.Add(lG)

	session := []byte("schnorr-v-session-a")
	proof, _ := NewZKVProofWithSession(session, V, R, s, l)

	assert.True(t, proof.VerifyWithSession(session, V, R), "verify result must be true with the original session")
	assert.False(t, proof.VerifyWithSession([]byte("schnorr-v-session-b"), V, R), "proof must not replay across sessions")
	assert.False(t, proof.Verify(V, R), "session-bound proof must not verify without its session")
}

func TestSchnorrVProofVerifyBadPartialV(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(q)
	s := common.GetRandomPositiveInt(q)
	l := common.GetRandomPositiveInt(q)
	R := crypto.ScalarBaseMult(tss.EC(), k) // k_-1 * G
	Rs := R.ScalarMult(s)
	V := Rs

	proof, _ := NewZKVProof(V, R, s, l)
	res := proof.Verify(V, R)

	assert.False(t, res, "verify result must be false")
}

func TestSchnorrVProofVerifyBadS(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(q)
	s := common.GetRandomPositiveInt(q)
	s2 := common.GetRandomPositiveInt(q)
	l := common.GetRandomPositiveInt(q)
	R := crypto.ScalarBaseMult(tss.EC(), k) // k_-1 * G
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(tss.EC(), l)
	V, _ := Rs.Add(lG)

	proof, _ := NewZKVProof(V, R, s2, l)
	res := proof.Verify(V, R)

	assert.False(t, res, "verify result must be false")
}
