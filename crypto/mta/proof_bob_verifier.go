// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"crypto/elliptic"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
)

// verify is the shared Bob/BobWC verification core. historicalBobCompat selects
// the widened historical witness-range bound (q+1)*N; otherwise the bound is
// derived from the session state, which reproduces the exact historical
// behavior of Verify. The widened bound is computed here, after the
// malformed-input guard, so nil curve/key/modulus inputs return false instead
// of panicking.
func (pf *ProofBobWC) verify(
	ec elliptic.Curve,
	pk *paillier.PublicKey,
	NTilde, h1, h2, c1, c2 *big.Int,
	X *crypto.ECPoint,
	Session []byte,
	historicalBobCompat bool,
) bool {
	if pf == nil || pf.ProofBob == nil ||
		ec == nil || pk == nil || pk.N == nil ||
		NTilde == nil || h1 == nil || h2 == nil || c1 == nil || c2 == nil {
		return false
	}
	if X != nil {
		if !pf.ValidateBasic() {
			return false
		}
	} else if !pf.ProofBob.ValidateBasic() {
		return false
	}
	// Shared modulus/generator/ciphertext preamble: width ceiling before
	// IsUsableUnknownOrderModulus's ProbablyPrime call, then canonical
	// generators, then canonical ciphertexts. Preserves exact check order.
	if !validateVerifierParams(pk, NTilde, h1, h2, c1, c2) {
		return false
	}

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	q7 := new(big.Int).Mul(q3, q3)
	q7 = new(big.Int).Mul(q7, q)
	// Honest S2/T2 = e*rho + rho' with e < q, rho < q*NTilde,
	// rho' < q^3*NTilde, hence S2/T2 < 2*q^3*NTilde.
	q3NTilde := new(big.Int).Mul(q3, NTilde)
	maxS2 := new(big.Int).Lsh(q3NTilde, 1)
	maxT2 := new(big.Int).Set(maxS2)
	var maxT1 *big.Int
	switch {
	case historicalBobCompat:
		// The historical (2e712689) prover samples y below the Paillier
		// modulus: T1 = e*y + gamma with e < q, y < N, gamma < N, hence
		// T1 < (q-1)*N + N < (q+1)*N. Derived after the malformed-input guard
		// so nil curve/key inputs return false instead of panicking.
		maxT1 = new(big.Int).Mul(new(big.Int).Add(q, one), pk.N)
	case Session != nil:
		// The session-bound verifier historically accepted T1 == q^7; express
		// the exclusive upper bound as q^7 + 1 so the shared >= check below
		// preserves that behavior exactly.
		maxT1 = new(big.Int).Add(q7, big.NewInt(1))
	default:
		// This branch's legacy-mode (session-less) prover samples the
		// blinding value y below q^5 and gamma as a unit below pk.N, so an
		// honest T1 = e*y + gamma with e < q is below pk.N + q^6: the
		// default strict bound admits exactly that prover's responses.
		// The 2e712689 historical prover instead samples y below pk.N, so
		// its T1 reaches (q+1)*N and requires the historicalBobCompat
		// widened bound; applying the strict cap to the historical
		// 2e712689 prover's proofs rejects nearly all legitimate 2048-bit
		// y values and breaks mixed-binary legacy signing. Keep a finite
		// legacy-specific cap so adversarial exponents remain bounded,
		// without rewriting the historical acceptance range.
		q6 := new(big.Int).Mul(q3, q3)
		maxT1 = new(big.Int).Add(pk.N, q6)
	}

	if !common.IsInIntervalPositive(pf.Z, NTilde) {
		return false
	}
	if !common.IsInIntervalPositive(pf.ZPrm, NTilde) {
		return false
	}
	if !common.IsInIntervalPositive(pf.T, NTilde) {
		return false
	}
	if !common.IsInIntervalPositive(pf.V, pk.NSquare()) {
		return false
	}
	if !common.IsInIntervalPositive(pf.W, NTilde) {
		return false
	}
	if !common.IsInIntervalPositive(pf.S, pk.N) {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.Z, NTilde).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.ZPrm, NTilde).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.T, NTilde).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.V, pk.NSquare()).Cmp(one) != 0 {
		return false
	}
	if new(big.Int).GCD(nil, nil, pf.W, NTilde).Cmp(one) != 0 {
		return false
	}
	gcd := big.NewInt(0)
	if pf.S.Cmp(zero) == 0 {
		return false
	}
	if gcd.GCD(nil, nil, pf.S, pk.N).Cmp(one) != 0 {
		return false
	}
	if pf.S1.Cmp(q) == -1 {
		return false
	}
	if pf.S2.Cmp(q) == -1 {
		return false
	}
	if pf.T1.Cmp(q) == -1 {
		return false
	}
	if pf.T2.Cmp(q) == -1 {
		return false
	}

	// 3.
	if pf.S1.Cmp(q3) > 0 {
		return false
	}
	if pf.S2.Cmp(maxS2) >= 0 {
		return false
	}
	if pf.T1.Cmp(maxT1) >= 0 {
		return false
	}
	if pf.T2.Cmp(maxT2) >= 0 {
		return false
	}

	// 1-2. e'
	if X != nil {
		if !X.ValidateBasic() || !crypto.SameCurve(ec, X.Curve()) {
			return false
		}
		if !pf.U.ValidateBasic() || !crypto.SameCurve(ec, pf.U.Curve()) {
			return false
		}
	}
	e := bobProofChallenge(
		Session,
		q,
		pk,
		NTilde,
		h1,
		h2,
		c1,
		c2,
		X,
		pf.U,
		pf.Z,
		pf.ZPrm,
		pf.T,
		pf.V,
		pf.W,
	)
	if e.Sign() == 0 {
		return false
	}

	var left, right *big.Int // for the following conditionals

	// 4. runs only in the "with check" mode from Fig. 10
	if X != nil {
		s1ModQ := new(big.Int).Mod(pf.S1, ec.Params().N)
		gS1 := crypto.ScalarBaseMult(ec, s1ModQ)
		xE := X.ScalarMult(e)
		if xE == nil {
			return false
		}
		xEU, err := xE.Add(pf.U)
		if err != nil || xEU == nil || gS1 == nil || !gS1.Equals(xEU) {
			return false
		}
	}

	{ // 5-6.
		modNTilde := common.ModInt(NTilde)

		{ // 5.
			h1ExpS1 := modNTilde.Exp(h1, pf.S1)
			h2ExpS2 := modNTilde.Exp(h2, pf.S2)
			left = modNTilde.Mul(h1ExpS1, h2ExpS2)
			zExpE := modNTilde.Exp(pf.Z, e)
			right = modNTilde.Mul(zExpE, pf.ZPrm)
			if left.Cmp(right) != 0 {
				return false
			}
		}

		{ // 6.
			h1ExpT1 := modNTilde.Exp(h1, pf.T1)
			h2ExpT2 := modNTilde.Exp(h2, pf.T2)
			left = modNTilde.Mul(h1ExpT1, h2ExpT2)
			tExpE := modNTilde.Exp(pf.T, e)
			right = modNTilde.Mul(tExpE, pf.W)
			if left.Cmp(right) != 0 {
				return false
			}
		}
	}

	{ // 7.
		modNSquared := common.ModInt(pk.NSquare())

		c1ExpS1 := modNSquared.Exp(c1, pf.S1)
		sExpN := modNSquared.Exp(pf.S, pk.N)
		gammaExpT1 := modNSquared.Exp(pk.Gamma(), pf.T1)
		left = modNSquared.Mul(c1ExpS1, sExpN)
		left = modNSquared.Mul(left, gammaExpT1)
		c2ExpE := modNSquared.Exp(c2, e)
		right = modNSquared.Mul(c2ExpE, pf.V)
		if left.Cmp(right) != 0 {
			return false
		}
	}
	return true
}

func bobProofChallenge(
	session []byte,
	q *big.Int,
	pk *paillier.PublicKey,
	nTilde, h1, h2, c1, c2 *big.Int,
	x, u *crypto.ECPoint,
	z, zPrime, t, v, w *big.Int,
) *big.Int {
	if session == nil {
		if x == nil {
			return common.HashToN(
				q,
				append(pk.AsInts(), c1, c2, z, zPrime, t, v, w)...,
			)
		}
		return common.HashToN(
			q,
			append(
				pk.AsInts(),
				x.X(),
				x.Y(),
				c1,
				c2,
				u.X(),
				u.Y(),
				z,
				zPrime,
				t,
				v,
				w,
			)...,
		)
	}

	if x == nil {
		challengeHash := common.SHA512_256i_TAGGED(
			fsSessionBob(session),
			append(
				pk.AsInts(),
				nTilde,
				h1,
				h2,
				c1,
				c2,
				z,
				zPrime,
				t,
				v,
				w,
			)...,
		)
		return common.ModReduceHash(q, challengeHash)
	}

	challengeHash := common.SHA512_256i_TAGGED(
		fsSessionBobWC(session),
		append(
			pk.AsInts(),
			nTilde,
			h1,
			h2,
			x.X(),
			x.Y(),
			c1,
			c2,
			u.X(),
			u.Y(),
			z,
			zPrime,
			t,
			v,
			w,
		)...,
	)
	return common.ModReduceHash(q, challengeHash)
}

// validateVerifierParams is the shared modulus/generator/ciphertext preamble
// of this package's unknown-order verifiers. It preserves the exact check
// order: width ceiling before IsUsableUnknownOrderModulus's ProbablyPrime
// call, then canonical generators, then canonical ciphertext checks.
// All moduli and generators must be non-nil.
func validateVerifierParams(
	pk *paillier.PublicKey,
	NTilde, h1, h2 *big.Int,
	ciphertexts ...*big.Int,
) bool {
	// Width policy: reject caller-supplied moduli wider than the shared
	// ceiling before IsUsableUnknownOrderModulus's ProbablyPrime call or
	// any modulus-sized work is performed against them.
	if common.ExceedsUnknownOrderModulusCeiling(pk.N) ||
		common.ExceedsUnknownOrderModulusCeiling(NTilde) {
		return false
	}
	if !common.IsUsableUnknownOrderModulus(pk.N, common.MinUnknownOrderModulusBitLen) ||
		!common.IsUsableUnknownOrderModulus(NTilde, common.MinUnknownOrderModulusBitLen) {
		return false
	}
	if !common.IsCanonicalGenerator(NTilde, h1) ||
		!common.IsCanonicalGenerator(NTilde, h2) ||
		h1.Cmp(h2) == 0 {
		return false
	}
	for _, c := range ciphertexts {
		if !common.IsCanonicalPaillierCiphertext(c, pk.N) {
			return false
		}
	}
	return true
}
