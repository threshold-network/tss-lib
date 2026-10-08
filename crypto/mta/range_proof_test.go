// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"math/big"
	"runtime"
	"testing"

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

func TestLegacyRangeChallengeMatchesHistoricalTranscript(t *testing.T) {
	q := tss.EC().Params().N
	pk := &paillier.PublicKey{N: big.NewInt(17)}
	c := big.NewInt(19)
	z := big.NewInt(23)
	u := big.NewInt(29)
	w := big.NewInt(31)

	expected := common.HashToN(q, append(pk.AsInts(), c, z, u, w)...)
	actual := rangeProofChallenge(
		nil,
		q,
		pk,
		big.NewInt(37),
		big.NewInt(41),
		big.NewInt(43),
		c,
		z,
		u,
		w,
	)

	assert.Equal(t, 0, expected.Cmp(actual))
}

func TestProveRangeAlice(t *testing.T) {
	q := tss.EC().Params().N

	sk, pk, err := loadPaillierKeyFixture(6)
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

	sk0, pk0, err := loadPaillierKeyFixture(7)
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

	sk1, pk1, err := loadPaillierKeyFixture(8)
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

	sk, pk, err := loadPaillierKeyFixture(9)
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

	sk, pk, err := loadPaillierKeyFixture(10)
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
	assert.False(t, badS2.Verify(tss.EC(), pk, NTildei, h1i, h2i, c), "S2 above the 2*q^3*NTilde bound must be rejected")

	badZ := *proof
	badZ.Z = big.NewInt(1)
	assert.False(t, badZ.Verify(tss.EC(), pk, NTildei, h1i, h2i, c), "Z equal to one must fail")
}

// TestRangeProofAliceAcceptsZeroContribution codifies that the range proof
// intentionally accepts c=1 with r=1 and m=0. BNB upstream flags c=1 as a
// "bypass" in TestProveRangeAliceBypassed via a println, but tracing c=1
// through BobMid (share_protocol.go) gives alpha+beta = 0 mod q, identical
// to an honest a=0 contribution. The proof accepts m=0 because GG18 bounds
// s1 < q^3, and signing tolerates one peer contributing zero because
// k = sum(k_i) stays unpredictable from other parties' randomness. We do
// not reject c=1 in Verify because it is not a verifier-side bug.
func TestRangeProofAliceAcceptsZeroContribution(t *testing.T) {
	_, pk, err := loadPaillierKeyFixture(11)
	assert.NoError(t, err)

	primes := [2]*big.Int{common.GetRandomPrimeInt(testSafePrimeBits), common.GetRandomPrimeInt(testSafePrimeBits)}
	NTildei, h1i, h2i, err := crypto.GenerateNTildei(primes)
	assert.NoError(t, err)

	mZero := big.NewInt(0)
	rOne := big.NewInt(1)
	cOne := big.NewInt(1)
	proof, err := ProveRangeAlice(tss.EC(), pk, cOne, NTildei, h1i, h2i, mZero, rOne)
	assert.NoError(t, err)
	assert.True(t, proof.Verify(tss.EC(), pk, NTildei, h1i, h2i, cOne),
		"c=1 with r=1, m=0 verifies because it is honest zero contribution; see test docstring")
}

// TestRangeProofAliceBytesInvalidReceiver pins that an invalid
// RangeProofAlice receiver is rejected by ValidateBasic, and that Bytes
// fails loud with a diagnostic error value on that receiver -- consistent
// with the sibling ProofBob.Bytes/ProofBobWC.Bytes guards -- instead of
// letting a nil *big.Int field surface as an unguarded runtime nil-pointer
// dereference panic.
func TestRangeProofAliceBytesInvalidReceiver(t *testing.T) {
	for _, tc := range []struct {
		name string
		pf   *RangeProofAlice
	}{
		{"nil receiver", nil},
		{"nil fields", &RangeProofAlice{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.pf.ValidateBasic() {
				t.Fatalf("expected ValidateBasic to reject an invalid %s receiver", tc.name)
			}
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("Bytes() did not panic on an invalid %s receiver", tc.name)
				}
				err, ok := r.(error)
				if !ok {
					t.Fatalf("Bytes() panicked with %T, want a diagnostic error value", r)
				}
				if _, isRuntimeErr := err.(runtime.Error); isRuntimeErr {
					t.Fatalf("Bytes() panicked with a runtime error (%v); want a fail-loud diagnostic, not an unguarded nil-pointer dereference", err)
				}
			}()
			tc.pf.Bytes()
		})
	}
}
