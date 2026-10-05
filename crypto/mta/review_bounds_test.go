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

// TestVerifyLegacyCompatBoundRejectsOverwideWitness pins the upper edge of the
// opt-in historical-compat T1 bound: the widened verifier must reject a
// historical-shaped proof whose witness y = (q+1)*N places T1 = e*y + gamma
// at or above (q+1)*N, while the honest y = N-1 control still verifies.
// Without this, deleting or widening the compat T1 bound (unbounded, +N, 2x)
// passes every mta and signing test: the existing unguarded helpers only ever
// exercise y <= N-1.
func TestVerifyLegacyCompatBoundRejectsOverwideWitness(t *testing.T) {
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
	// The widened bound is (q+1)*N; y set to exactly that value makes
	// T1 = e*y + gamma reach it for e >= 1.
	overwideY := new(big.Int).Mul(new(big.Int).Add(q, one), pk.N)
	widenedMaxT1 := new(big.Int).Set(overwideY)

	X := crypto.ScalarBaseMult(ec, x)
	bobProof, c2 := historicalBobProofForWitnessY(t, ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, x, overwideY, r, nil)
	wcProof, wcC2 := historicalBobProofForWitnessY(t, ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, x, overwideY, r, X)
	if bobProof.T1.Cmp(widenedMaxT1) < 0 || wcProof.T1.Cmp(widenedMaxT1) < 0 {
		t.Fatal("overwide witness did not place T1 above the (q+1)*N compat bound")
	}
	if bobProof.ProofBob.VerifyLegacy(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, true) {
		t.Fatal("widened legacy Bob verifier accepted a T1 above the (q+1)*N bound")
	}
	if wcProof.VerifyLegacy(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, wcC2, X, true) {
		t.Fatal("widened legacy BobWC verifier accepted a T1 above the (q+1)*N bound")
	}
	if _, err := AliceEndLegacy(ec, pk, bobProof.ProofBob, aux.H1i, aux.H2i, c1, c2, aux.NTildei, owner.PaillierSK, true); err == nil {
		t.Fatal("widened AliceEndLegacy accepted a T1 above the (q+1)*N bound")
	}
	if _, err := AliceEndWCLegacy(ec, pk, wcProof, X, c1, wcC2, aux.NTildei, aux.H1i, aux.H2i, owner.PaillierSK, true); err == nil {
		t.Fatal("widened AliceEndWCLegacy accepted a T1 above the (q+1)*N bound")
	}

	// Honest y = N-1 control: T1 stays below the widened bound and must
	// verify with compatibility on.
	honestY := new(big.Int).Sub(pk.N, one)
	control, controlC2 := historicalBobProofForWitnessY(t, ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, x, honestY, r, nil)
	controlWC, controlWCC2 := historicalBobProofForWitnessY(t, ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, x, honestY, r, X)
	if control.T1.Cmp(widenedMaxT1) >= 0 || controlWC.T1.Cmp(widenedMaxT1) >= 0 {
		t.Fatal("honest y = N-1 T1 exceeded the widened bound; fixture invariant broken")
	}
	if !control.ProofBob.VerifyLegacy(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, controlC2, true) {
		t.Fatal("widened legacy Bob verifier rejected the honest y = N-1 control")
	}
	if !controlWC.VerifyLegacy(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, controlWCC2, X, true) {
		t.Fatal("widened legacy BobWC verifier rejected the honest y = N-1 control")
	}
}

// TestSessionBobVerifierQ7T1Bound pins the security-v2 (session) T1 bound:
// T1 must stay below q^7 + 1. The proof is built from the historical prover
// equations with the session-tagged challenge, so the algebra is satisfied
// and only the T1 bound can differ between the reject and control cases.
func TestSessionBobVerifierQ7T1Bound(t *testing.T) {
	fixtures, _, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil {
		t.Fatal(err)
	}
	owner := fixtures[0]
	aux := fixtures[1]
	pk := &owner.PaillierSK.PublicKey
	ec := tss.EC()

	x := big.NewInt(7)
	y := big.NewInt(11)
	r := firstSmallUnit(pk.N, 2)
	c1 := fixedPaillierEncryption(pk, big.NewInt(5), firstSmallUnit(pk.N, 3))
	modNSquared := common.ModInt(pk.NSquare())
	c2 := modNSquared.Mul(
		modNSquared.Exp(c1, x),
		modNSquared.Mul(
			modNSquared.Exp(pk.Gamma(), y),
			modNSquared.Exp(r, pk.N),
		),
	)

	q := ec.Params().N
	q7 := new(big.Int).Exp(q, big.NewInt(7), nil)
	q7Plus1 := new(big.Int).Add(q7, one)
	session := []byte("R01/security-v2/bob/q7-bound")
	X := crypto.ScalarBaseMult(ec, x)

	// The historical gamma range (units below the 2048-bit N) sits above
	// q^7 for the fixture modulus and must be rejected.
	historicalGamma := new(big.Int).Sub(pk.N, one)
	reject := sessionHistoricalBobProof(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, x, y, r, historicalGamma, nil, session)
	rejectWC := sessionHistoricalBobProof(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, x, y, r, historicalGamma, X, session)
	if reject.T1.Cmp(q7) <= 0 || rejectWC.T1.Cmp(q7) <= 0 {
		t.Fatal("fixture did not place the historical gamma range above q^7")
	}
	if reject.ProofBob.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, session) {
		t.Fatal("session verifier accepted a T1 above the q^7 + 1 bound")
	}
	if rejectWC.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, X, session) {
		t.Fatal("session WC verifier accepted a T1 above the q^7 + 1 bound")
	}

	// Control: the security-v2 gamma range (below q^7) keeps T1 below
	// q^7 + 1 and must verify.
	honestGamma := new(big.Int).Rsh(q7, 1)
	control := sessionHistoricalBobProof(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, x, y, r, honestGamma, nil, session)
	controlWC := sessionHistoricalBobProof(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, x, y, r, honestGamma, X, session)
	if control.T1.Cmp(q7Plus1) >= 0 || controlWC.T1.Cmp(q7Plus1) >= 0 {
		t.Fatal("control T1 is not below the q^7 + 1 session bound")
	}
	if !control.ProofBob.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, session) {
		t.Fatal("session verifier rejected a T1 below the q^7 + 1 bound")
	}
	if !controlWC.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, X, session) {
		t.Fatal("session WC verifier rejected a T1 below the q^7 + 1 bound")
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
	bobProof, c2 := historicalBobProofForWitnessY(t, ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, x, y, r, nil)
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
	wcProof, wcC2 := historicalBobProofForWitnessY(t, ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, x, y, r, X)
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

// TestBobBoundCheckRejectsOverwideS2 pins that the cheap response-bound
// check, not the verification equations, rejects an overwide response. The
// keygen fixture exposes P and Q with NTilde = (2P+1)(2Q+1), so the group
// exponent modulo NTilde is lambda = lcm(2P, 2Q) = 4*P*Q (P and Q are
// coprime), a multiple of both ord(h1) and ord(h2). S2
// appears only in the h1/h2 equation, so shifting an honest session-bound
// proof's S2 by (2*q^3+1)*lambda keeps every verification equation satisfied
// while pushing S2 above maxS2 = 2*q^3*NTilde. The shifted proof must fail
// and the unshifted control must verify; without the cheap bound check the
// shifted proof would pass every equation.
func TestBobBoundCheckRejectsOverwideS2(t *testing.T) {
	fixtures, _, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil {
		t.Fatal(err)
	}
	owner := fixtures[0]
	aux := fixtures[1]
	if aux.P == nil || aux.Q == nil {
		t.Skip("keygen fixture party 1 does not expose the NTilde safe-prime halves; the bound-only rejection cannot be constructed")
	}
	pk := &owner.PaillierSK.PublicKey
	ec := tss.EC()

	x := big.NewInt(7)
	y := big.NewInt(11)
	r := firstSmallUnit(pk.N, 2)
	c1 := fixedPaillierEncryption(pk, big.NewInt(5), firstSmallUnit(pk.N, 3))
	modNSquared := common.ModInt(pk.NSquare())
	c2 := modNSquared.Mul(
		modNSquared.Exp(c1, x),
		modNSquared.Mul(
			modNSquared.Exp(pk.Gamma(), y),
			modNSquared.Exp(r, pk.N),
		),
	)

	q := ec.Params().N
	q3 := new(big.Int).Exp(q, big.NewInt(3), nil)
	session := []byte("R01/security-v2/bob/s2-bound")
	// gamma = q^7/2 keeps the honest T1 below the q^7 + 1 session bound, so
	// the unshifted control is a fully honest proof.
	gamma := new(big.Int).Rsh(new(big.Int).Exp(q, big.NewInt(7), nil), 1)
	proof := sessionHistoricalBobProof(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, x, y, r, gamma, nil, session)
	if !proof.ProofBob.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, session) {
		t.Fatal("unshifted control proof must verify under the session path")
	}

	// lambda = 4*P*Q is a multiple of ord(h1) and ord(h2), so S2' stays
	// congruent to S2 in the h1/h2 equation.
	lambdaNTilde := new(big.Int).Mul(aux.P, aux.Q)
	lambdaNTilde.Lsh(lambdaNTilde, 2)
	shift := new(big.Int).Lsh(q3, 1)
	shift.Add(shift, one)
	shift.Mul(shift, lambdaNTilde)
	shifted := cloneProofBobWC(proof)
	shifted.S2 = new(big.Int).Add(shifted.S2, shift)
	maxS2 := new(big.Int).Lsh(new(big.Int).Mul(q3, aux.NTildei), 1)
	if shifted.S2.Cmp(maxS2) < 0 {
		t.Fatal("shifted S2 did not reach the 2*q^3*NTilde bound")
	}
	// Manual equation check: S2 is the only shifted response and it appears
	// only in the h1/h2 equation, so the rejection below must come from the
	// bound check, not from an equation failure.
	e := bobProofChallenge(session, q, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, nil, nil, proof.Z, proof.ZPrm, proof.T, proof.V, proof.W)
	modNTilde := common.ModInt(aux.NTildei)
	left := modNTilde.ExpMulExp(aux.H1i, proof.S1, aux.H2i, shifted.S2)
	right := modNTilde.Mul(modNTilde.Exp(proof.Z, e), proof.ZPrm)
	if left.Cmp(right) != 0 {
		t.Fatal("shifted S2 no longer satisfies the h1/h2 equation; the rejection would be an equation failure, not a bound failure")
	}
	if shifted.ProofBob.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, session) {
		t.Fatal("session verifier accepted an S2 at or above the 2*q^3*NTilde bound despite satisfied equations")
	}
}

// sessionHistoricalBobProof is the session-aware variant of
// fixedHistoricalBobProof: the exact historical prover equations with the
// fixed witnesses and a parameterized gamma, but the challenge is computed
// the way the security-v2 (session) path does, via the tagged
// bobProofChallenge, so the proof can be exercised against the q^7 T1 bound.
func sessionHistoricalBobProof(
	ec elliptic.Curve,
	pk *paillier.PublicKey,
	nTilde, h1, h2, c1, c2, x, y, r, gamma *big.Int,
	X *crypto.ECPoint,
	session []byte,
) *ProofBobWC {
	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q3, q)
	qNTilde := new(big.Int).Mul(q, nTilde)
	q3NTilde := new(big.Int).Mul(q3, nTilde)

	alpha := new(big.Int).Rsh(new(big.Int).Set(q3), 1)
	rho := new(big.Int).Rsh(new(big.Int).Set(qNTilde), 2)
	sigma := new(big.Int).Rsh(new(big.Int).Set(qNTilde), 3)
	tau := new(big.Int).Sub(qNTilde, one)
	rhoPrime := new(big.Int).Rsh(new(big.Int).Set(q3NTilde), 2)
	beta := firstSmallUnit(pk.N, 5)

	var u *crypto.ECPoint
	if X != nil {
		u = crypto.ScalarBaseMult(ec, alpha)
	}
	modNTilde := common.ModInt(nTilde)
	z := modNTilde.ExpMulExp(h1, x, h2, rho)
	zPrime := modNTilde.ExpMulExp(h1, alpha, h2, rhoPrime)
	transcriptT := modNTilde.ExpMulExp(h1, y, h2, sigma)
	modNSquared := common.ModInt(pk.NSquare())
	v := modNSquared.Exp(c1, alpha)
	v = modNSquared.Mul(v, modNSquared.Exp(pk.Gamma(), gamma))
	v = modNSquared.Mul(v, modNSquared.Exp(beta, pk.N))
	w := modNTilde.ExpMulExp(h1, gamma, h2, tau)

	e := bobProofChallenge(
		session,
		q,
		pk,
		nTilde,
		h1,
		h2,
		c1,
		c2,
		X,
		u,
		z,
		zPrime,
		transcriptT,
		v,
		w,
	)
	sResponse := common.ModInt(pk.N).Mul(
		common.ModInt(pk.N).Exp(r, e),
		beta,
	)

	return &ProofBobWC{
		ProofBob: &ProofBob{
			Z:    z,
			ZPrm: zPrime,
			T:    transcriptT,
			V:    v,
			W:    w,
			S:    sResponse,
			S1:   common.AddMul(alpha, e, x),
			S2:   common.AddMul(rhoPrime, e, rho),
			T1:   common.AddMul(gamma, e, y),
			T2:   common.AddMul(tau, e, sigma),
		},
		U: u,
	}
}
