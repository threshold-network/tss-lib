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

	badZ := *proof
	badZ.Z = big.NewInt(1)
	assert.False(t, badZ.Verify(tss.EC(), pk, NTildei, h1i, h2i, c), "Z equal to one must fail")
}
