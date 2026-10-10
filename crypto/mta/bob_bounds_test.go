// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// TestBobVerifierT1BoundEdges pins the exact T1 upper bound of each Bob
// verifier mode. The proofs use the honest prover equations with y = 0, so
// T1 = gamma + e*y = gamma for every challenge e. Setting gamma to the bound
// minus one and to the bound gives two proofs whose equations all hold and
// whose T1 sits on each side of the edge. Only the T1 bound check can tell
// them apart.
func TestBobVerifierT1BoundEdges(t *testing.T) {
	fixtures, _, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil {
		t.Fatal(err)
	}
	owner := fixtures[0]
	aux := fixtures[1]
	pk := &owner.PaillierSK.PublicKey
	ec := tss.EC()

	x := big.NewInt(7)
	y := big.NewInt(0)
	r := firstSmallUnit(pk.N, 2)
	c1 := fixedPaillierEncryption(pk, big.NewInt(5), firstSmallUnit(pk.N, 3))
	X := crypto.ScalarBaseMult(ec, x)

	q := ec.Params().N
	q6 := new(big.Int).Exp(q, big.NewInt(6), nil)
	q7 := new(big.Int).Mul(q6, q)
	session := []byte("mta-test/bob/t1-bound")

	// verify checks a Bob proof when wcX is nil, and a BobWC proof for wcX
	// otherwise.
	type verifyFn func(pf *ProofBobWC, c2 *big.Int, wcX *crypto.ECPoint) bool
	cases := []struct {
		name    string
		bound   *big.Int // exclusive upper bound on T1
		session []byte
		verify  verifyFn
	}{
		{
			// Session-less default: T1 < N + q^6.
			name:  "legacy default",
			bound: new(big.Int).Add(pk.N, q6),
			verify: func(pf *ProofBobWC, c2 *big.Int, wcX *crypto.ECPoint) bool {
				if wcX == nil {
					return pf.ProofBob.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2)
				}
				return pf.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, wcX)
			},
		},
		{
			// Opt-in historical compatibility: T1 < (q+1)*N.
			name:  "legacy historical compatibility",
			bound: new(big.Int).Mul(new(big.Int).Add(q, one), pk.N),
			verify: func(pf *ProofBobWC, c2 *big.Int, wcX *crypto.ECPoint) bool {
				if wcX == nil {
					return pf.ProofBob.VerifyLegacy(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, true)
				}
				return pf.VerifyLegacy(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, wcX, true)
			},
		},
		{
			// Session-bound: T1 <= q^7.
			name:    "session",
			bound:   new(big.Int).Add(q7, one),
			session: session,
			verify: func(pf *ProofBobWC, c2 *big.Int, wcX *crypto.ECPoint) bool {
				if wcX == nil {
					return pf.ProofBob.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, session)
				}
				return pf.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, wcX, session)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, edge := range []struct {
				name  string
				gamma *big.Int
				want  bool
			}{
				{"bound minus one accepted", new(big.Int).Sub(tc.bound, one), true},
				{"bound rejected", new(big.Int).Set(tc.bound), false},
			} {
				t.Run(edge.name, func(t *testing.T) {
					bob, c2 := historicalBobProofForWitnessY(t, ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, x, y, r, edge.gamma, nil, tc.session)
					bobWC, _ := historicalBobProofForWitnessY(t, ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, x, y, r, edge.gamma, X, tc.session)
					require.Zero(t, bob.T1.Cmp(edge.gamma), "y = 0 must give T1 = gamma")
					require.Zero(t, bobWC.T1.Cmp(edge.gamma), "y = 0 must give T1 = gamma")

					assert.Equal(t, edge.want, tc.verify(bob, c2, nil), "Bob verdict")
					assert.Equal(t, edge.want, tc.verify(bobWC, c2, X), "BobWC verdict")
				})
			}
		})
	}
}

// TestAliceEndLegacyCompatFlagPlumbing pins the historicalBobCompat flag
// plumbing of the AliceEndLegacy/AliceEndWCLegacy entry points: with the flag
// off the tight N + q^6 bound rejects the historical-witness (y = N-1)
// proof, while the flag on admits it and decrypts.
func TestAliceEndLegacyCompatFlagPlumbing(t *testing.T) {
	fixtures, _, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil {
		t.Fatal(err)
	}
	owner := fixtures[0]
	aux := fixtures[1]
	pk := &owner.PaillierSK.PublicKey
	ec := tss.EC()

	x := big.NewInt(7)
	r := firstSmallUnit(pk.N, 2)
	c1 := fixedPaillierEncryption(pk, big.NewInt(5), firstSmallUnit(pk.N, 3))
	y := new(big.Int).Sub(pk.N, one)
	bobProof, c2 := historicalBobProofForWitnessY(t, ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, x, y, r, nil, nil, nil)
	q := ec.Params().N
	tightMaxT1 := new(big.Int).Add(pk.N, new(big.Int).Exp(q, big.NewInt(6), nil))
	if bobProof.T1.Cmp(tightMaxT1) < 0 {
		t.Fatal("y = N-1 did not place T1 above the tight N + q^6 bound; the compat flag is not exercised")
	}
	if _, err := AliceEndLegacy(ec, pk, bobProof.ProofBob, aux.H1i, aux.H2i, c1, c2, aux.NTildei, owner.PaillierSK, false); err == nil {
		t.Fatal("AliceEndLegacy with compat off accepted a historical-witness proof")
	}
	if _, err := AliceEndLegacy(ec, pk, bobProof.ProofBob, aux.H1i, aux.H2i, c1, c2, aux.NTildei, owner.PaillierSK, true); err != nil {
		t.Fatalf("AliceEndLegacy with compat on rejected the historical-witness proof: %v", err)
	}

	X := crypto.ScalarBaseMult(ec, x)
	wcProof, wcC2 := historicalBobProofForWitnessY(t, ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, x, y, r, nil, X, nil)
	if wcProof.T1.Cmp(tightMaxT1) < 0 {
		t.Fatal("y = N-1 WC did not place T1 above the tight N + q^6 bound; the compat flag is not exercised")
	}
	if _, err := AliceEndWCLegacy(ec, pk, wcProof, X, c1, wcC2, aux.NTildei, aux.H1i, aux.H2i, owner.PaillierSK, false); err == nil {
		t.Fatal("AliceEndWCLegacy with compat off accepted a historical-witness proof")
	}
	if _, err := AliceEndWCLegacy(ec, pk, wcProof, X, c1, wcC2, aux.NTildei, aux.H1i, aux.H2i, owner.PaillierSK, true); err != nil {
		t.Fatalf("AliceEndWCLegacy with compat on rejected the historical-witness proof: %v", err)
	}
}

// ringPedersenOrderMultiple returns 4*P*Q for the keygen fixture party. With
// NTilde = (2P+1)(2Q+1), this is a multiple of the order of every unit mod
// NTilde, so adding it to an exponent of h1 or h2 does not change the
// result.
func ringPedersenOrderMultiple(t *testing.T, P, Q *big.Int) *big.Int {
	t.Helper()
	if P == nil || Q == nil {
		t.Skip("keygen fixture party does not expose the NTilde safe-prime halves")
	}
	lambda := new(big.Int).Mul(P, Q)
	return lambda.Lsh(lambda, 2)
}

// shiftAroundBound returns v + (k-1)*step and v + k*step, where k >= 1 is
// the smallest value with v + k*step >= bound. The first value is below the
// bound and the second is at or above it.
func shiftAroundBound(v, step, bound *big.Int) (below, atOrAbove *big.Int) {
	gap := new(big.Int).Sub(bound, v)
	k := new(big.Int).Add(gap, new(big.Int).Sub(step, one))
	k.Div(k, step)
	if k.Sign() <= 0 {
		k.SetInt64(1)
	}
	atOrAbove = new(big.Int).Add(v, new(big.Int).Mul(k, step))
	below = new(big.Int).Sub(atOrAbove, step)
	return below, atOrAbove
}

// TestBobBoundCheckRejectsShiftedResponses pins the S2 and T2 bounds of the
// Bob verifier (S2, T2 < 2*q^3*NTilde). S2 and T2 appear only in the h1/h2
// equations mod NTilde, so adding a multiple of 4*P*Q keeps every equation
// true. The response is shifted to the last value below the bound (must
// verify, which also proves the equations still hold) and to the first
// value at or above it (must be rejected by the bound check alone).
func TestBobBoundCheckRejectsShiftedResponses(t *testing.T) {
	fixtures, _, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil {
		t.Fatal(err)
	}
	owner := fixtures[0]
	aux := fixtures[1]
	lambda := ringPedersenOrderMultiple(t, aux.P, aux.Q)
	pk := &owner.PaillierSK.PublicKey
	ec := tss.EC()

	x := big.NewInt(7)
	y := big.NewInt(11)
	r := firstSmallUnit(pk.N, 2)
	c1 := fixedPaillierEncryption(pk, big.NewInt(5), firstSmallUnit(pk.N, 3))

	q := ec.Params().N
	q3 := new(big.Int).Exp(q, big.NewInt(3), nil)
	maxResponse := new(big.Int).Lsh(new(big.Int).Mul(q3, aux.NTildei), 1)
	session := []byte("mta-test/bob/response-bound")
	// gamma = q^7/2 keeps T1 below the session bound, so the unshifted
	// proof is fully honest.
	gamma := new(big.Int).Rsh(new(big.Int).Exp(q, big.NewInt(7), nil), 1)
	proof, c2 := historicalBobProofForWitnessY(t, ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, x, y, r, gamma, nil, session)
	require.True(t, proof.ProofBob.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, session),
		"unshifted proof must verify")

	for _, field := range []string{"S2", "T2"} {
		t.Run(field, func(t *testing.T) {
			value := proof.S2
			if field == "T2" {
				value = proof.T2
			}
			below, atOrAbove := shiftAroundBound(value, lambda, maxResponse)
			for _, tc := range []struct {
				name  string
				value *big.Int
				want  bool
			}{
				{"last shift below the bound verifies", below, true},
				{"first shift at or above the bound is rejected", atOrAbove, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					shifted := cloneProofBobWC(proof)
					if field == "S2" {
						shifted.S2 = tc.value
					} else {
						shifted.T2 = tc.value
					}
					assert.Equal(t, tc.want, shifted.ProofBob.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, session))
				})
			}
		})
	}
}

// TestAliceBoundCheckRejectsShiftedS2 pins the S2 bound of the Alice range
// proof verifier (S2 < 2*q^3*NTilde) the same way: S2 appears only in the
// h1/h2 equation mod NTilde, so a shift by a multiple of 4*P*Q keeps the
// equations true and only the bound check can reject.
func TestAliceBoundCheckRejectsShiftedS2(t *testing.T) {
	fixtures, _, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil {
		t.Fatal(err)
	}
	owner := fixtures[0]
	aux := fixtures[1]
	lambda := ringPedersenOrderMultiple(t, aux.P, aux.Q)
	pk := &owner.PaillierSK.PublicKey
	ec := tss.EC()

	m := big.NewInt(424242)
	rMsg := firstSmallUnit(pk.N, 2)
	c := fixedPaillierEncryption(pk, m, rMsg)
	session := []byte("mta-test/alice/s2-bound")
	proof, err := ProveRangeAlice(ec, pk, c, aux.NTildei, aux.H1i, aux.H2i, m, rMsg, session)
	require.NoError(t, err)
	require.True(t, proof.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c, session), "unshifted proof must verify")

	q3 := new(big.Int).Exp(ec.Params().N, big.NewInt(3), nil)
	maxS2 := new(big.Int).Lsh(new(big.Int).Mul(q3, aux.NTildei), 1)
	below, atOrAbove := shiftAroundBound(proof.S2, lambda, maxS2)

	accepted := *proof
	accepted.S2 = below
	assert.True(t, accepted.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c, session),
		"last shift below the bound must verify")
	rejected := *proof
	rejected.S2 = atOrAbove
	assert.False(t, rejected.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c, session),
		"first shift at or above the bound must be rejected")
}
