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

// TestLegacyBobVerifierAcceptsHistoricalGammaRange pins a historical proof
// shape the security-v2 verifier intentionally rejects. PRIOR and the restored
// legacy prover sample gamma as a unit below the 2048-bit Paillier modulus;
// the security-v2 prover samples below q^7 instead. The proof is otherwise
// generated from the exact historical equations with fixed test-only witnesses
// and blinders.
func TestLegacyBobVerifierAcceptsHistoricalGammaRange(t *testing.T) {
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

	legacy := fixedHistoricalBobProof(
		ec,
		pk,
		aux.NTildei,
		aux.H1i,
		aux.H2i,
		c1,
		c2,
		x,
		y,
		r,
		nil,
	)
	if !legacy.ProofBob.Verify(
		ec,
		pk,
		aux.NTildei,
		aux.H1i,
		aux.H2i,
		c1,
		c2,
	) {
		t.Fatal("legacy Bob verifier rejected a proof in PRIOR's gamma range")
	}

	X := crypto.ScalarBaseMult(ec, x)
	legacyWC := fixedHistoricalBobProof(
		ec,
		pk,
		aux.NTildei,
		aux.H1i,
		aux.H2i,
		c1,
		c2,
		x,
		y,
		r,
		X,
	)
	if !legacyWC.Verify(
		ec,
		pk,
		aux.NTildei,
		aux.H1i,
		aux.H2i,
		c1,
		c2,
		X,
	) {
		t.Fatal("legacy BobWC verifier rejected a proof in PRIOR's gamma range")
	}

	q := ec.Params().N
	q3 := new(big.Int).Exp(q, big.NewInt(3), nil)
	q7 := new(big.Int).Exp(q, big.NewInt(7), nil)
	if legacy.T1.Cmp(q7) <= 0 || legacyWC.T1.Cmp(q7) <= 0 {
		t.Fatal("fixture does not exercise PRIOR's wider gamma range")
	}
	// BobMid samples the T1 witness y below q^5, so the exact honest legacy
	// range is gamma + e*y < N + q^6.
	legacyMaxT1 := new(big.Int).Add(pk.N, new(big.Int).Mul(q3, q3))
	if legacy.T1.Cmp(legacyMaxT1) >= 0 || legacyWC.T1.Cmp(legacyMaxT1) >= 0 {
		t.Fatal("fixture exceeds the historical honest T1 bound")
	}
	if legacy.S1.Cmp(q3) >= 0 || legacyWC.S1.Cmp(q3) >= 0 {
		t.Fatal("fixture accidentally exceeds the shared S1 bound")
	}

	session := []byte("R01/security-v2/bob/range")
	if legacy.ProofBob.Verify(
		ec,
		pk,
		aux.NTildei,
		aux.H1i,
		aux.H2i,
		c1,
		c2,
		session,
	) || legacyWC.Verify(
		ec,
		pk,
		aux.NTildei,
		aux.H1i,
		aux.H2i,
		c1,
		c2,
		X,
		session,
	) {
		t.Fatal("historical Bob proof crossed into security-v2")
	}
}

func fixedHistoricalBobProof(
	ec elliptic.Curve,
	pk *paillier.PublicKey,
	nTilde, h1, h2, c1, c2, x, y, r *big.Int,
	X *crypto.ECPoint,
) *ProofBobWC {
	q := ec.Params().N
	q3 := new(big.Int).Exp(q, big.NewInt(3), nil)
	qNTilde := new(big.Int).Mul(q, nTilde)
	q3NTilde := new(big.Int).Mul(q3, nTilde)

	alpha := new(big.Int).Rsh(new(big.Int).Set(q3), 1)
	rho := new(big.Int).Rsh(new(big.Int).Set(qNTilde), 2)
	sigma := new(big.Int).Rsh(new(big.Int).Set(qNTilde), 3)
	// PRIOR sampled tau below q*NTilde.
	tau := new(big.Int).Sub(qNTilde, big.NewInt(1))
	rhoPrime := new(big.Int).Rsh(new(big.Int).Set(q3NTilde), 2)
	beta := firstSmallUnit(pk.N, 5)
	// This is a valid PRIOR gamma (< pk.N and coprime to it) but is wider
	// than q^7 for the 2048-bit fixture modulus.
	gamma := new(big.Int).Sub(pk.N, big.NewInt(1))

	var u *crypto.ECPoint
	if X != nil {
		u = crypto.ScalarBaseMult(tss.EC(), alpha)
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
		nil,
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

func fixedPaillierEncryption(
	pk *paillier.PublicKey,
	message, randomness *big.Int,
) *big.Int {
	modNSquared := common.ModInt(pk.NSquare())
	return modNSquared.Mul(
		modNSquared.Exp(pk.Gamma(), message),
		modNSquared.Exp(randomness, pk.N),
	)
}

func firstSmallUnit(modulus *big.Int, start int64) *big.Int {
	result := big.NewInt(start)
	for new(big.Int).GCD(nil, nil, result, modulus).Cmp(big.NewInt(1)) != 0 {
		result.Add(result, big.NewInt(1))
	}
	return result
}
