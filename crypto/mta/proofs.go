// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
)

const (
	ProofBobBytesParts   = 10
	ProofBobWCBytesParts = 12
)

type (
	ProofBob struct {
		Z, ZPrm, T, V, W, S, S1, S2, T1, T2 *big.Int
	}

	ProofBobWC struct {
		*ProofBob
		U *crypto.ECPoint
	}
)

// ProveBobWC implements Bob's proof both with or without check "ProveMtawc_Bob" and "ProveMta_Bob" used in the MtA protocol from GG18Spec (9) Figs. 10 & 11.
// an absent `X` generates the proof without the X consistency check X = g^x
func ProveBobWC(ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2, x, y, r *big.Int, X *crypto.ECPoint, session ...[]byte) (*ProofBobWC, error) {
	Session := optionalProofSession(session)
	if ec == nil || pk == nil || NTilde == nil || h1 == nil || h2 == nil || c1 == nil || c2 == nil || x == nil || y == nil || r == nil {
		return nil, errors.New("ProveBob() received a nil argument")
	}

	NSquared := pk.NSquare()

	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	q7 := new(big.Int).Mul(q3, q3)
	q7 = new(big.Int).Mul(q7, q)
	qNTilde := new(big.Int).Mul(q, NTilde)
	q3NTilde := new(big.Int).Mul(q3, NTilde)

	// steps are numbered as shown in Fig. 10, but diverge slightly for Fig. 11
	// 1.
	alpha := common.GetRandomPositiveInt(q3)

	// 2.
	rho := common.GetRandomPositiveInt(qNTilde)
	sigma := common.GetRandomPositiveInt(qNTilde)
	var tau *big.Int
	if Session == nil {
		// The legacy transcript samples tau below q*N-tilde. Keep that exact
		// distribution for byte-compatible proof generation; security-v2 uses
		// the wider q^3*N-tilde range.
		tau = common.GetRandomPositiveInt(qNTilde)
	} else {
		tau = common.GetRandomPositiveInt(q3NTilde)
	}

	// 3.
	rhoPrm := common.GetRandomPositiveInt(q3NTilde)

	// 4.
	beta := common.GetRandomPositiveRelativelyPrimeInt(pk.N)
	if beta == nil {
		return nil, errors.New("ProveBob: could not sample randomness")
	}
	var gamma *big.Int
	if Session == nil {
		// Historical Bob proofs sample gamma as a unit modulo the Paillier
		// modulus. Besides reproducing PRIOR proof bytes, this is why the legacy
		// verifier must accept T1 above q^7.
		gamma = common.GetRandomPositiveRelativelyPrimeInt(pk.N)
	} else {
		gamma = common.GetRandomPositiveInt(q7)
	}

	// 5.
	u := crypto.NewECPointNoCurveCheck(ec, zero, zero) // initialization suppresses an IDE warning
	if X != nil {
		u = crypto.ScalarBaseMult(ec, alpha)
	}

	// 6, 7, 8: z and t carry the secret MtA witnesses x and y as exponents; zPrm and the
	// h2^* terms use one-time random blinds. Harden only the secret-exponent terms.
	modNTilde := common.ModInt(NTilde)
	zPrm := modNTilde.Exp(h1, alpha)
	zPrm = modNTilde.Mul(zPrm, modNTilde.Exp(h2, rhoPrm))

	var z, t *big.Int
	if common.IsConstantTimeEnabled() {
		// SECURITY: x and y are Bob's secret MtA inputs; exponentiate them in constant
		// time (NTilde is odd). The h2^rho / h2^sigma blinds use one-time randomness and
		// stay on math/big (see the coverage note in common/constant_time.go).
		ctModNTilde := common.NewCTModInt(NTilde)
		// Both inputs are Paillier plaintexts bounded by pk.N, which can be
		// wider than NTilde. Do not derive the exponent width from NTilde.
		exponentBits := pk.N.BitLen()
		z = modNTilde.Mul(ctModNTilde.ExpCTWithBitLen(h1, x, exponentBits), modNTilde.Exp(h2, rho))
		t = modNTilde.Mul(ctModNTilde.ExpCTWithBitLen(h1, y, exponentBits), modNTilde.Exp(h2, sigma))
	} else {
		z = modNTilde.Mul(modNTilde.Exp(h1, x), modNTilde.Exp(h2, rho))
		t = modNTilde.Mul(modNTilde.Exp(h1, y), modNTilde.Exp(h2, sigma))
	}

	// 9.
	modNSquared := common.ModInt(NSquared)
	v := modNSquared.Exp(c1, alpha)
	v = modNSquared.Mul(v, modNSquared.Exp(pk.Gamma(), gamma))
	v = modNSquared.Mul(v, modNSquared.Exp(beta, pk.N))

	// 10.
	w := modNTilde.Exp(h1, gamma)
	w = modNTilde.Mul(w, modNTilde.Exp(h2, tau))

	// 11-12. e'
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
		u,
		z,
		zPrm,
		t,
		v,
		w,
	)

	// 13.
	modN := common.ModInt(pk.N)
	s := modN.Exp(r, e)
	s = modN.Mul(s, beta)

	// 14.
	s1 := new(big.Int).Mul(e, x)
	s1 = s1.Add(s1, alpha)

	// 15.
	s2 := new(big.Int).Mul(e, rho)
	s2 = s2.Add(s2, rhoPrm)

	// 16.
	t1 := new(big.Int).Mul(e, y)
	t1 = t1.Add(t1, gamma)

	// 17.
	t2 := new(big.Int).Mul(e, sigma)
	t2 = t2.Add(t2, tau)

	// the regular Bob proof ("without check") is extracted and returned by ProveBob
	pf := &ProofBob{Z: z, ZPrm: zPrm, T: t, V: v, W: w, S: s, S1: s1, S2: s2, T1: t1, T2: t2}

	// or the WC ("with check") version is used in round 2 of the signing protocol
	return &ProofBobWC{ProofBob: pf, U: u}, nil
}

// ProveBob implements Bob's proof "ProveMta_Bob" used in the MtA protocol from GG18Spec (9) Fig. 11.
func ProveBob(ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2, x, y, r *big.Int, session ...[]byte) (*ProofBob, error) {
	// the Bob proof ("with check") contains the ProofBob "without check"; this method extracts and returns it
	// X is supplied as nil to exclude it from the proof hash
	pf, err := ProveBobWC(ec, pk, NTilde, h1, h2, c1, c2, x, y, r, nil, session...)
	if err != nil {
		return nil, err
	}
	return pf.ProofBob, nil
}

func ProofBobWCFromBytes(ec elliptic.Curve, bzs [][]byte) (*ProofBobWC, error) {
	// The base decoder also accepts the shorter ProofBob encoding.
	if !common.NonEmptyMultiBytes(bzs, ProofBobWCBytesParts) {
		return nil, fmt.Errorf("expected %d byte parts to construct ProofBobWC", ProofBobWCBytesParts)
	}
	proofBob, err := ProofBobFromBytes(bzs)
	if err != nil {
		return nil, err
	}
	point, err := crypto.NewECPoint(ec,
		new(big.Int).SetBytes(bzs[10]),
		new(big.Int).SetBytes(bzs[11]))
	if err != nil {
		return nil, err
	}
	return &ProofBobWC{
		ProofBob: proofBob,
		U:        point,
	}, nil
}

func ProofBobFromBytes(bzs [][]byte) (*ProofBob, error) {
	if !common.NonEmptyMultiBytes(bzs, ProofBobBytesParts) &&
		!common.NonEmptyMultiBytes(bzs, ProofBobWCBytesParts) {
		return nil, fmt.Errorf(
			"expected %d byte parts to construct ProofBob, or %d for ProofBobWC",
			ProofBobBytesParts, ProofBobWCBytesParts)
	}
	return &ProofBob{
		Z:    new(big.Int).SetBytes(bzs[0]),
		ZPrm: new(big.Int).SetBytes(bzs[1]),
		T:    new(big.Int).SetBytes(bzs[2]),
		V:    new(big.Int).SetBytes(bzs[3]),
		W:    new(big.Int).SetBytes(bzs[4]),
		S:    new(big.Int).SetBytes(bzs[5]),
		S1:   new(big.Int).SetBytes(bzs[6]),
		S2:   new(big.Int).SetBytes(bzs[7]),
		T1:   new(big.Int).SetBytes(bzs[8]),
		T2:   new(big.Int).SetBytes(bzs[9]),
	}, nil
}

// ProveBobWC.Verify implements verification of Bob's proof with check "VerifyMtawc_Bob" used in the MtA protocol from GG18Spec (9) Fig. 10.
// an absent `X` verifies a proof generated without the X consistency check X = g^x
func (pf *ProofBobWC) Verify(ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2 *big.Int, X *crypto.ECPoint, session ...[]byte) bool {
	return pf.verify(ec, pk, NTilde, h1, h2, c1, c2, X, optionalProofSession(session), nil)
}

// VerifyLegacy verifies a session-less legacy Bob/BobWC proof (the exact
// 2e712689 untagged challenge). It is the explicit compatibility-aware entry
// point used by signing round 3 for legacy parties. The shared verify core
// owns the default tight legacy bound, N + q^6: the session-less prover
// samples y below q^5 with T1 = e*y + gamma, e < q, gamma < N, so an honest
// legacy response stays below q^6 + N. historicalBobCompat passes the
// widened historical witness-range bound (q+1)*N as an explicit override,
// computed and passed only in that case; every other entry point gets the
// core's tight bound.
func (pf *ProofBobWC) VerifyLegacy(
	ec elliptic.Curve,
	pk *paillier.PublicKey,
	NTilde, h1, h2, c1, c2 *big.Int,
	X *crypto.ECPoint,
	historicalBobCompat bool,
) bool {
	var maxT1Override *big.Int
	if historicalBobCompat {
		// The historical (2e712689) prover samples y below the Paillier
		// modulus: T1 = e*y + gamma with e < q, y < N, gamma < N, hence
		// T1 < (q-1)*N + N < (q+1)*N.
		maxT1Override = new(big.Int).Mul(new(big.Int).Add(ec.Params().N, one), pk.N)
	}
	return pf.verify(ec, pk, NTilde, h1, h2, c1, c2, X, nil, maxT1Override)
}

// verify is the shared Bob/BobWC verification core. maxT1Override, when
// non-nil, is the exclusive T1 upper bound to enforce; nil means "derive the
// bound from the session state", which reproduces the exact historical
// behavior of Verify.
func (pf *ProofBobWC) verify(
	ec elliptic.Curve,
	pk *paillier.PublicKey,
	NTilde, h1, h2, c1, c2 *big.Int,
	X *crypto.ECPoint,
	Session []byte,
	maxT1Override *big.Int,
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
	// Width policy: reject caller-supplied moduli wider than the shared
	// ceiling before IsUsableUnknownOrderModulus's ProbablyPrime call or any
	// modulus-sized work is run against them.
	if common.ExceedsUnknownOrderModulusCeiling(pk.N) ||
		common.ExceedsUnknownOrderModulusCeiling(NTilde) {
		return false
	}
	if !common.IsUsableUnknownOrderModulus(pk.N, common.MinUnknownOrderModulusBitLen) ||
		!common.IsUsableUnknownOrderModulus(NTilde, common.MinUnknownOrderModulusBitLen) {
		return false
	}
	if !common.IsCanonicalGenerator(NTilde, h1) || !common.IsCanonicalGenerator(NTilde, h2) || h1.Cmp(h2) == 0 {
		return false
	}
	if !common.IsCanonicalPaillierCiphertext(c1, pk.N) || !common.IsCanonicalPaillierCiphertext(c2, pk.N) {
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
	case maxT1Override != nil:
		// Explicit legacy bound chosen by the caller (VerifyLegacy).
		maxT1 = maxT1Override
	case Session != nil:
		// The session-bound verifier historically accepted T1 == q^7; express
		// the exclusive upper bound as q^7 + 1 so the shared >= check below
		// preserves that behavior exactly.
		maxT1 = new(big.Int).Add(q7, big.NewInt(1))
	default:
		// The historical prover sampled gamma in [1, pk.N), while the
		// security-v2 prover samples it below q^7. Since T1 = e*y + gamma
		// with e < q and the MtA blinding value y < q^5, an honest legacy
		// response is below pk.N + q^6.
		// Applying the security-v2 q^7 cap to a PRIOR proof rejects almost
		// every legitimate 2048-bit gamma and breaks mixed-binary legacy
		// signing. Keep a finite legacy-specific cap so adversarial exponents
		// remain bounded without rewriting the historical acceptance range.
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

// ProveBob.Verify implements verification of Bob's proof without check "VerifyMta_Bob" used in the MtA protocol from GG18Spec (9) Fig. 11.
func (pf *ProofBob) Verify(ec elliptic.Curve, pk *paillier.PublicKey, NTilde, h1, h2, c1, c2 *big.Int, session ...[]byte) bool {
	if pf == nil {
		return false
	}
	pfWC := &ProofBobWC{ProofBob: pf, U: nil}
	return pfWC.Verify(ec, pk, NTilde, h1, h2, c1, c2, nil, session...)
}

// ProveBob.VerifyLegacy is the explicit compatibility-aware session-less
// counterpart of ProveBob.Verify: historicalBobCompat widens the T1 bound to
// the historical witness range via VerifyLegacy's (q+1)*N override; the prover and every other
// check are unchanged.
func (pf *ProofBob) VerifyLegacy(
	ec elliptic.Curve,
	pk *paillier.PublicKey,
	NTilde, h1, h2, c1, c2 *big.Int,
	historicalBobCompat bool,
) bool {
	if pf == nil {
		return false
	}
	pfWC := &ProofBobWC{ProofBob: pf, U: nil}
	return pfWC.VerifyLegacy(ec, pk, NTilde, h1, h2, c1, c2, nil, historicalBobCompat)
}

func optionalProofSession(session [][]byte) []byte {
	if len(session) == 0 {
		return nil
	}
	if len(session[0]) == 0 {
		panic("mta: proof session tag must be non-empty")
	}
	return session[0]
}

func (pf *ProofBob) ValidateBasic() bool {
	return pf != nil &&
		pf.Z != nil &&
		pf.ZPrm != nil &&
		pf.T != nil &&
		pf.V != nil &&
		pf.W != nil &&
		pf.S != nil &&
		pf.S1 != nil &&
		pf.S2 != nil &&
		pf.T1 != nil &&
		pf.T2 != nil
}

func (pf *ProofBobWC) ValidateBasic() bool {
	return pf != nil &&
		pf.ProofBob != nil &&
		pf.ProofBob.ValidateBasic() &&
		pf.U != nil &&
		pf.U.ValidateBasic()
}

func (pf *ProofBob) Bytes() [ProofBobBytesParts][]byte {
	if !pf.ValidateBasic() {
		panic(fmt.Errorf("ProofBob.Bytes: invalid receiver"))
	}
	return [...][]byte{
		pf.Z.Bytes(),
		pf.ZPrm.Bytes(),
		pf.T.Bytes(),
		pf.V.Bytes(),
		pf.W.Bytes(),
		pf.S.Bytes(),
		pf.S1.Bytes(),
		pf.S2.Bytes(),
		pf.T1.Bytes(),
		pf.T2.Bytes(),
	}
}

func (pf *ProofBobWC) Bytes() [ProofBobWCBytesParts][]byte {
	// The optional mode without X uses a coordinate placeholder for U, so
	// serialization requires the fields to be present without curve validation.
	if pf == nil || !pf.ProofBob.ValidateBasic() || pf.U == nil {
		panic(fmt.Errorf("ProofBobWC.Bytes: invalid receiver"))
	}
	var out [ProofBobWCBytesParts][]byte
	bobBzs := pf.ProofBob.Bytes()
	bobBzsSlice := bobBzs[:]
	bobBzsSlice = append(bobBzsSlice, pf.U.X().Bytes())
	bobBzsSlice = append(bobBzsSlice, pf.U.Y().Bytes())
	copy(out[:], bobBzsSlice[:12])
	return out
}
