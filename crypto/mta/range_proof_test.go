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
	"github.com/bnb-chain/tss-lib/tss"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testSafePrimeBits = 1024
)

func TestProofSessionRejectsEmptyTag(t *testing.T) {
	assert.Panics(t, func() {
		_, _ = ProveRangeAlice(nil, nil, nil, nil, nil, nil, nil, nil, []byte{})
	})
}

func TestProveRangeAlice(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	m := common.GetRandomPositiveInt(q)
	c, r, err := sk.EncryptAndReturnRandomness(m)
	assert.NoError(t, err)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NTildei, h1i, h2i, err := crypto.GenerateNTildei(primes)
	assert.NoError(t, err)
	proof, err := ProveRangeAlice(tss.EC(), pk, c, NTildei, h1i, h2i, m, r)
	assert.NoError(t, err)

	ok := proof.Verify(tss.EC(), pk, NTildei, h1i, h2i, c)
	assert.True(t, ok, "proof must verify")
}

func TestProveRangeAliceBypassed(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk0, pk0, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	m0 := common.GetRandomPositiveInt(q)
	c0, r0, err := sk0.EncryptAndReturnRandomness(m0)
	assert.NoError(t, err)

	primes0 := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NTildei0, h1i0, h2i0, err := crypto.GenerateNTildei(primes0)
	assert.NoError(t, err)
	proof0, err := ProveRangeAlice(tss.EC(), pk0, c0, NTildei0, h1i0, h2i0, m0, r0)
	assert.NoError(t, err)

	assert.True(t, proof0.Verify(tss.EC(), pk0, NTildei0, h1i0, h2i0, c0), "proof 0 must verify against its own parameters")

	sk1, pk1, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	m1 := common.GetRandomPositiveInt(q)
	c1, r1, err := sk1.EncryptAndReturnRandomness(m1)
	assert.NoError(t, err)

	primes1 := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NTildei1, h1i1, h2i1, err := crypto.GenerateNTildei(primes1)
	assert.NoError(t, err)
	proof1, err := ProveRangeAlice(tss.EC(), pk1, c1, NTildei1, h1i1, h2i1, m1, r1)
	assert.NoError(t, err)

	assert.True(t, proof1.Verify(tss.EC(), pk1, NTildei1, h1i1, h2i1, c1), "proof 1 must verify against its own parameters")

	assert.False(t, proof0.Verify(tss.EC(), pk1, NTildei1, h1i1, h2i1, c1), "proof 0 must not verify against proof 1 parameters")
	assert.False(t, proof1.Verify(tss.EC(), pk0, NTildei0, h1i0, h2i0, c0), "proof 1 must not verify against proof 0 parameters")

	bypassedProof := &RangeProofAlice{
		S:  big.NewInt(1),
		S1: big.NewInt(0),
		S2: big.NewInt(0),
		Z:  big.NewInt(1),
		U:  big.NewInt(1),
		W:  big.NewInt(1),
	}
	assert.False(t, bypassedProof.Verify(tss.EC(), pk1, NTildei1, h1i1, h2i1, big.NewInt(1)), "bypassed proof must not verify")
}

func TestProveRangeAliceSessionBinding(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	m := common.GetRandomPositiveInt(q)
	c, r, err := sk.EncryptAndReturnRandomness(m)
	assert.NoError(t, err)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NTildei, h1i, h2i, err := crypto.GenerateNTildei(primes)
	assert.NoError(t, err)

	session := []byte("range-proof-session-a")
	proof, err := ProveRangeAlice(tss.EC(), pk, c, NTildei, h1i, h2i, m, r, session)
	assert.NoError(t, err)
	assert.True(t, proof.Verify(tss.EC(), pk, NTildei, h1i, h2i, c, session), "proof must verify with the original session")
	assert.False(t, proof.Verify(tss.EC(), pk, NTildei, h1i, h2i, c, []byte("range-proof-session-b")), "proof must not replay across sessions")
	assert.False(t, proof.Verify(tss.EC(), pk, NTildei, h1i, h2i, c), "session-bound proof must not verify without its session")
}

func TestRangeProofAliceRejectsMalformedInputs(t *testing.T) {
	q := tss.EC().Params().N

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sk, pk, err := paillier.GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)

	m := common.GetRandomPositiveInt(q)
	c, r, err := sk.EncryptAndReturnRandomness(m)
	assert.NoError(t, err)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NTildei, h1i, h2i, err := crypto.GenerateNTildei(primes)
	assert.NoError(t, err)
	proof, err := ProveRangeAlice(tss.EC(), pk, c, NTildei, h1i, h2i, m, r)
	assert.NoError(t, err)

	assert.False(t, proof.Verify(tss.EC(), pk, NTildei, h1i, h2i, pk.N), "ciphertext must be coprime to Paillier N")

	badS1 := *proof
	badS1.S1 = new(big.Int).Sub(q, big.NewInt(1))
	assert.False(t, badS1.Verify(tss.EC(), pk, NTildei, h1i, h2i, c), "S1 below q must fail")

	badS := *proof
	badS.S = big.NewInt(1)
	assert.False(t, badS.Verify(tss.EC(), pk, NTildei, h1i, h2i, c), "S equal to one must fail")

	badSZero := *proof
	badSZero.S = big.NewInt(0)
	assert.False(t, badSZero.Verify(tss.EC(), pk, NTildei, h1i, h2i, c), "S equal to zero must fail")

	q3 := new(big.Int).Mul(q, q)
	q3.Mul(q3, q)
	tooLargeS2 := new(big.Int).Mul(q3, NTildei)
	tooLargeS2.Lsh(tooLargeS2, 1)
	tooLargeS2.Add(tooLargeS2, big.NewInt(1))
	badS2 := *proof
	badS2.S2 = tooLargeS2
	assert.False(t, badS2.Verify(tss.EC(), pk, NTildei, h1i, h2i, c), "overwide S2 must fail before exponentiation")

	badZ := *proof
	badZ.Z = big.NewInt(1)
	assert.False(t, badZ.Verify(tss.EC(), pk, NTildei, h1i, h2i, c), "Z equal to one must fail")
}
