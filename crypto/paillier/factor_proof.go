package paillier

import (
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
)

const (
	PARAM_E = 512 // 2 * secp256k1 element bit length
	PARAM_L = 256 // 1 * secp256k1 element bit length
)

type (
	FactorProof struct {
		// Commitment
		P     *big.Int
		Q     *big.Int
		A     *big.Int
		B     *big.Int
		T     *big.Int
		Sigma *big.Int
		// Response
		Z1 *big.Int
		Z2 *big.Int
		W1 *big.Int
		W2 *big.Int
		V  *big.Int
	}
)

// FactorProof is an implementation of the no small factor proof of
// Canetti, R., Gennaro, R., Goldfeder, S., Makriyannis, N., Peled, U.:
// UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.
// In: Cryptology ePrint Archive 2021/060
func (privateKey *PrivateKey) FactorProof(N, s, t *big.Int) *FactorProof {
	N0 := privateKey.PublicKey.N
	p, q := privateKey.GetPQ()

	a := common.GetRandomIntIn2PowerMulRange(PARAM_L+PARAM_E, new(big.Int).Sqrt(N0))
	b := common.GetRandomIntIn2PowerMulRange(PARAM_L+PARAM_E, new(big.Int).Sqrt(N0))

	mu := common.GetRandomIntIn2PowerMulRange(PARAM_L, N)
	v := common.GetRandomIntIn2PowerMulRange(PARAM_L, N)

	sigma := common.GetRandomIntIn2PowerMulRange(PARAM_L, new(big.Int).Mul(N0, N))
	r := common.GetRandomIntIn2PowerMulRange(PARAM_L+PARAM_E, new(big.Int).Mul(N0, N))

	x := common.GetRandomIntIn2PowerMulRange(PARAM_L+PARAM_E, N)
	y := common.GetRandomIntIn2PowerMulRange(PARAM_L+PARAM_E, N)

	modN := common.ModInt(N)

	P := modN.ExpMulExp(s, p, t, mu)
	Q := modN.ExpMulExp(s, q, t, v)
	A := modN.ExpMulExp(s, a, t, x)
	B := modN.ExpMulExp(s, b, t, y)
	T := modN.ExpMulExp(Q, a, t, r)

	// Use standard Fiat-Shamir transform.
	//
	// Section 2.3.1 ZK-Module:
	// Next, we present how to compile the protocols above using a random oracle via the Fiat-Shamir heuristic.
	// Namely, to generate a proof, the Prover computes the challenge e by querying the oracle on a suitable input,
	// which incorporates the theorem and the first message. Then, the Prover completes the transcript by computing
	// the last message with respect to e and communicates the entire transcript as the proof. Later, the Verifier
	// accepts the proof if it is a valid transcript of the underlying Σ-protocol and e is well-formed (verified by
	// querying the oracle as the Prover should have).
	e := FactorChallenge(N, s, t, N0, P, Q, A, B, T, sigma)

	sigmaH := new(big.Int)
	sigmaH.Mul(v, p)
	sigmaH.Sub(sigma, sigmaH)

	z1 := common.AddMul(a, e, p)
	z2 := common.AddMul(b, e, q)
	w1 := common.AddMul(x, e, mu)
	w2 := common.AddMul(y, e, v)
	vv := common.AddMul(r, e, sigmaH)

	return &FactorProof{P, Q, A, B, T, sigma, z1, z2, w1, w2, vv}
}

func (pf FactorProof) FactorVerify(pkN, N, s, t *big.Int) (bool, error) {
	if common.AnyIsNil(pkN, N, s, t) {
		return false, fmt.Errorf("fac proof verify: nil bigint present in args")
	}
	if common.AnyIsNil(pf.P, pf.Q, pf.A, pf.B, pf.T, pf.Sigma, pf.Z1, pf.Z2, pf.W1, pf.W2, pf.V) {
		return false, fmt.Errorf("fac proof verify: nil bigint present in proof")
	}

	e := FactorChallenge(N, s, t, pkN, pf.P, pf.Q, pf.A, pf.B, pf.T, pf.Sigma)

	modN := common.ModInt(N)

	R := modN.ExpMulExp(s, pkN, t, pf.Sigma)

	sz1tw1 := modN.ExpMulExp(s, pf.Z1, t, pf.W1)
	sz2tw2 := modN.ExpMulExp(s, pf.Z2, t, pf.W2)
	Qz1tv := modN.ExpMulExp(pf.Q, pf.Z1, t, pf.V)

	APe := modN.MulExp(pf.A, pf.P, e)
	BQe := modN.MulExp(pf.B, pf.Q, e)
	TRe := modN.MulExp(pf.T, R, e)

	if !common.Eq(sz1tw1, APe) {
		return false, fmt.Errorf("fac proof verify: s^z1*t^w1 = %x != A*P^e = %x", sz1tw1, APe)
	}

	if !common.Eq(sz2tw2, BQe) {
		return false, fmt.Errorf("fac proof verify: s^z2*t^w2 = %x != B*Q^e = %x", sz2tw2, BQe)
	}

	if !common.Eq(Qz1tv, TRe) {
		return false, fmt.Errorf("fac proof verify: Q^z1*t^v = %x != T*R^e = %x", Qz1tv, TRe)
	}

	limit := big.NewInt(1)
	limit.Lsh(limit, PARAM_L+PARAM_E)
	limit.Mul(limit, new(big.Int).Sqrt(pkN))

	if pf.Z1.CmpAbs(limit) > 0 {
		return false, fmt.Errorf("fac proof verify: z1 = %x exceeds limit %x", pf.Z1, limit)
	}

	if pf.Z2.CmpAbs(limit) > 0 {
		return false, fmt.Errorf("fac proof verify: z2 = %x exceeds limit %x", pf.Z2, limit)
	}

	return true, nil
}

func FactorChallenge(N, s, t, pkN, P, Q, A, B, T, sigma *big.Int) *big.Int {
	q := big.NewInt(1)
	q = q.Lsh(q, 256)                             // q = 2^256
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1)) // q-1
	qDoubleMinus1 := new(big.Int).Add(q, qMinus1) // q+q-1 = 2q-1

	// 2. Verifier replies with e <- +-q
	// The q here is not the secret factor q, but rather the order of secp256k1,
	// or in practical terms 2^256 as the value h does not involve elliptic curve operations
	// and q acts as a security parameter only.
	//
	// Calculate +-q by taking HashToN(2*q-1, ...) - q + 1
	h := common.HashToN(qDoubleMinus1, N, s, t, pkN, P, Q, A, B, T, sigma)
	h.Sub(h, qMinus1) // h - (q-1) = h - q + 1

	return h
}
