// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// historicalBobProofForWitnessY builds a session-less legacy Bob/BobWC proof
// from the exact historical (2e712689) prover equations via
// fixedHistoricalBobProof, with the MtA blinding witness y and the c2
// ciphertext parameterized so the honest T1 = e*y + gamma range can be
// exercised at the documented acceptance boundary. It returns the proof and
// the c2 ciphertext used in its verification.
func historicalBobProofForWitnessY(
	t *testing.T,
	ec elliptic.Curve,
	pk *paillier.PublicKey,
	nTilde, h1, h2, c1 *big.Int,
	x, y, r *big.Int,
	X *crypto.ECPoint,
) (*ProofBobWC, *big.Int) {
	t.Helper()
	modNSquared := common.ModInt(pk.NSquare())
	c2 := modNSquared.Mul(
		modNSquared.Exp(c1, x),
		modNSquared.Mul(
			modNSquared.Exp(pk.Gamma(), y),
			modNSquared.Exp(r, pk.N),
		),
	)
	return fixedHistoricalBobProof(ec, pk, nTilde, h1, h2, c1, c2, x, y, r, X), c2
}

// deterministicHistoricalWitnessY returns a deterministic witness y in
// [q^5, N) that is not a hand-picked constant: a fixed 32-byte seed is
// hashed through SHA512_256 and reduced into the historical range.
func deterministicHistoricalWitnessY(t *testing.T, pk *paillier.PublicKey, q5 *big.Int) *big.Int {
	t.Helper()
	rangeSize := new(big.Int).Sub(new(big.Int).Sub(pk.N, q5), big.NewInt(1))
	y := new(big.Int).SetBytes(common.SHA512_256([]byte("historical-bob-witness-y-seed")))
	y.Mod(y, rangeSize)
	y.Add(y, q5)
	return y
}

// TestLegacyBobWidenedVerifierAcceptsHistoricalWitnessRange pins the
// documented T1 acceptance boundary of the session-less legacy Bob/BobWC
// verifiers and the opt-in historical witness-range bound (q+1)*N:
//
//   - The PR9 legacy prover samples y below q^5, so the default tight bound
//     N + q^6 admits y up to q^5 (y = q^5-1 and y = q^5 are boundary
//     controls that must verify by default).
//   - The historical (2e712689) prover samples y below the Paillier modulus
//     N, so honest historical T1 = e*y + gamma with e < q, y < N, gamma < N
//     reaches the exclusive bound (q+1)*N, which the default tight verifier
//     rejects for T1 >= N + q^6 and the opt-in widened verifier admits.
//
// The widened bound is only reachable through the explicit VerifyLegacy
// entry point; the standalone Verify API stays tight.
func TestLegacyBobWidenedVerifierAcceptsHistoricalWitnessRange(t *testing.T) {
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

	q := ec.Params().N
	q5 := new(big.Int).Exp(q, big.NewInt(5), nil)
	q6 := new(big.Int).Mul(q5, q)
	tightMaxT1 := new(big.Int).Add(pk.N, q6)
	widenedMaxT1 := legacyT1Max(ec, pk, true)
	// The widened bound must be exactly the historical witness-range bound:
	// T1 = e*y + gamma with e < q, y < N, gamma < N gives T1 < q*N + N.
	if widenedMaxT1.Cmp(new(big.Int).Mul(new(big.Int).Add(q, big.NewInt(1)), pk.N)) != 0 {
		t.Fatal("widened legacy T1 bound is not (q+1)*N")
	}
	if legacyT1Max(ec, pk, false).Cmp(tightMaxT1) != 0 {
		t.Fatal("tight legacy T1 bound is not N + q^6")
	}

	X := crypto.ScalarBaseMult(ec, x)
	cases := []struct {
		name string
		y    *big.Int
	}{
		{"q5-minus-1", new(big.Int).Sub(q5, big.NewInt(1))},
		{"q5", new(big.Int).Set(q5)},
		{"random-in-range", deterministicHistoricalWitnessY(t, pk, q5)},
		{"n-half", new(big.Int).Rsh(pk.N, 1)},
		{"n-minus-1", new(big.Int).Sub(pk.N, big.NewInt(1))},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bobProof, c2 := historicalBobProofForWitnessY(t, ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, x, tc.y, r, nil)
			wcProof, _ := historicalBobProofForWitnessY(t, ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, x, tc.y, r, X)
			// An honest historical proof must never exceed the widened
			// historical bound, in either check mode.
			if bobProof.T1.Cmp(widenedMaxT1) >= 0 || wcProof.T1.Cmp(widenedMaxT1) >= 0 {
				t.Fatal("honest historical T1 exceeded the widened historical bound")
			}
			// The documented acceptance boundary: the tight default accepts
			// exactly the T1 < N + q^6 responses, in both Bob and BobWC
			// check modes.
			bobInTightRange := bobProof.T1.Cmp(tightMaxT1) < 0
			if got := bobProof.ProofBob.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2); got != bobInTightRange {
				t.Fatalf("default tight Bob verdict = %v, want %v (documented T1 boundary)", got, bobInTightRange)
			}
			if got := bobProof.ProofBob.VerifyLegacy(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, false); got != bobInTightRange {
				t.Fatalf("legacy Bob entry point with compatibility off = %v, want %v", got, bobInTightRange)
			}
			if !bobProof.ProofBob.VerifyLegacy(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, true) {
				t.Fatal("opt-in widened legacy Bob verifier rejected a historical-witness proof")
			}

			wcInTightRange := wcProof.T1.Cmp(tightMaxT1) < 0
			if got := wcProof.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, X); got != wcInTightRange {
				t.Fatalf("default tight BobWC verdict = %v, want %v (documented T1 boundary)", got, wcInTightRange)
			}
			if got := wcProof.VerifyLegacy(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, X, false); got != wcInTightRange {
				t.Fatalf("legacy BobWC entry point with compatibility off = %v, want %v", got, wcInTightRange)
			}
			if !wcProof.VerifyLegacy(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, X, true) {
				t.Fatal("opt-in widened legacy BobWC verifier rejected a historical-witness proof")
			}
		})
	}
}

// TestLegacyHistoricalWitnessRangeRejectsWiderT1 pins the y = N-1 attack
// family end-to-end through the signing-level helpers: the default
// AliceEnd/AliceEndWC remain tight and reject historical-witness proofs
// whose T1 sits above N + q^6, while the explicit compatibility-aware
// AliceEndLegacy/AliceEndWCLegacy admit them and still decrypt the honest
// MtA result.
func TestLegacyHistoricalWitnessRangeRejectsWiderT1(t *testing.T) {
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
	y := new(big.Int).Sub(pk.N, big.NewInt(1))
	bobProof, c2 := historicalBobProofForWitnessY(t, ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, x, y, r, nil)

	if bobProof.T1.Cmp(legacyT1Max(ec, pk, false)) < 0 {
		t.Fatal("y = N - 1 witness did not place T1 above the tight bound; the y = N-T wrap family is not exercised")
	}
	if _, err := AliceEnd(ec, pk, bobProof.ProofBob, aux.H1i, aux.H2i, c1, c2, aux.NTildei, owner.PaillierSK); err == nil {
		t.Fatal("default AliceEnd accepted a proof with T1 above the tight bound")
	}
	if !bobProof.ProofBob.VerifyLegacy(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, true) {
		t.Fatal("opt-in widened legacy Bob verifier rejected the historical y = N - 1 proof")
	}
	alphaPrm, err := AliceEndLegacy(ec, pk, bobProof.ProofBob, aux.H1i, aux.H2i, c1, c2, aux.NTildei, owner.PaillierSK, true)
	if err != nil {
		t.Fatal(err)
	}
	// c1 encrypts 5; the honest MtA plaintext is x*5 + y mod N (Paillier),
	// and AliceEndLegacy reduces it to the curve order q.
	q := ec.Params().N
	expected := new(big.Int).Mod(
		new(big.Int).Mod(new(big.Int).Add(new(big.Int).Mul(x, big.NewInt(5)), y), pk.N),
		q,
	)
	if alphaPrm.Cmp(expected) != 0 {
		t.Fatalf("widened AliceEndLegacy decrypted the wrong MtA value")
	}

	X := crypto.ScalarBaseMult(ec, x)
	wcProof, _ := historicalBobProofForWitnessY(t, ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, x, y, r, X)
	if wcProof.T1.Cmp(legacyT1Max(ec, pk, false)) < 0 {
		t.Fatal("y = N - 1 WC witness did not place T1 above the tight bound; the y = N-T wrap family is not exercised")
	}
	if _, err := AliceEndWC(ec, pk, wcProof, X, c1, c2, aux.NTildei, aux.H1i, aux.H2i, owner.PaillierSK); err == nil {
		t.Fatal("default AliceEndWC accepted a proof with T1 above the tight bound")
	}
	if !wcProof.VerifyLegacy(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, X, true) {
		t.Fatal("opt-in widened legacy BobWC verifier rejected the historical y = N - 1 proof")
	}
	if _, err := AliceEndWCLegacy(ec, pk, wcProof, X, c1, c2, aux.NTildei, aux.H1i, aux.H2i, owner.PaillierSK, true); err != nil {
		t.Fatalf("opt-in widened AliceEndWCLegacy rejected the historical y = N - 1 proof: %v", err)
	}
}

// TestLegacyProverOutputStillVerifiesByDefault pins the reverse direction
// at the verifier level: this branch's own legacy prover samples y below
// q^5, so its output must keep passing the default tight legacy verifier
// and both legacy entry-point bounds. The historical 2e712689 verifier
// accepting this branch's output is covered by the packaged oracle under
// testdata/legacy_transcript.
func TestLegacyProverOutputStillVerifiesByDefault(t *testing.T) {
	fixtures, _, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil {
		t.Fatal(err)
	}
	owner := fixtures[0]
	aux := fixtures[1]
	pk := &owner.PaillierSK.PublicKey
	ec := tss.EC()

	q := ec.Params().N
	q5 := new(big.Int).Exp(q, big.NewInt(5), nil)

	x := big.NewInt(7)
	r := firstSmallUnit(pk.N, 2)
	y := common.GetRandomPositiveInt(q5) // the PR9 prover's own y < q^5 range
	c1 := fixedPaillierEncryption(pk, big.NewInt(5), firstSmallUnit(pk.N, 3))
	c2 := c2ForWitness(t, ec, pk, c1, x, y, r)

	X := crypto.ScalarBaseMult(ec, x)
	proof, err := ProveBobWC(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, x, y, r, X)
	if err != nil {
		t.Fatal(err)
	}
	// No session argument = the legacy untagged transcript, matching the
	// historical challenge construction.
	if !proof.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, X) {
		t.Fatal("default legacy verifier rejected this branch's own prover output")
	}
	if !proof.VerifyLegacy(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, X, false) {
		t.Fatal("legacy entry point rejected this branch's own prover output with compatibility off")
	}
	if !proof.VerifyLegacy(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, X, true) {
		t.Fatal("opt-in widened verifier must also accept this branch's own prover output")
	}
}

func c2ForWitness(t *testing.T, ec elliptic.Curve, pk *paillier.PublicKey, c1, x, y, r *big.Int) *big.Int {
	t.Helper()
	modNSquared := common.ModInt(pk.NSquare())
	return modNSquared.Mul(
		modNSquared.Exp(c1, x),
		modNSquared.Mul(
			modNSquared.Exp(pk.Gamma(), y),
			modNSquared.Exp(r, pk.N),
		),
	)
}
