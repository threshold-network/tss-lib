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

	// x and y are Bob's secret MtA inputs and Paillier plaintexts, so they
	// must sit in the intended 0 <= v < pk.N domain. Validate before any
	// sampling or exponentiation so a malformed direct-API witness returns an
	// error in either timing mode. Honest legacy and security-v2 witnesses
	// stay valid: b < q < N and the y < q^5 / y < N paths both bound y below
	// the Paillier modulus.
	if x.Cmp(zero) == -1 || x.Cmp(pk.N) != -1 || y.Cmp(zero) == -1 || y.Cmp(pk.N) != -1 {
		return nil, errors.New("ProveBob: witness outside the Paillier plaintext domain")
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
	// The shared core derives the T1 bound behind its malformed-input guards,
	// so every nil curve/key/modulus input returns false.
	return pf.verify(ec, pk, NTilde, h1, h2, c1, c2, X, optionalProofSession(session), false)
}

// VerifyLegacy verifies a session-less legacy Bob/BobWC proof (the exact
// 2e712689 untagged challenge). It is the explicit compatibility-aware entry
// point used by signing round 3 for legacy parties. The shared verify core
// owns the default tight legacy bound, N + q^6: the session-less prover
// samples y below q^5 with T1 = e*y + gamma, e < q, gamma < N, so an honest
// legacy response stays below q^6 + N. historicalBobCompat selects the
// widened historical witness-range bound (q+1)*N; the shared core derives
// it behind its malformed-input guard so nil curve/key/modulus inputs
// return false instead of panicking.
func (pf *ProofBobWC) VerifyLegacy(
	ec elliptic.Curve,
	pk *paillier.PublicKey,
	NTilde, h1, h2, c1, c2 *big.Int,
	X *crypto.ECPoint,
	historicalBobCompat bool,
) bool {
	return pf.verify(ec, pk, NTilde, h1, h2, c1, c2, X, nil, historicalBobCompat)
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
// counterpart of ProveBob.Verify: historicalBobCompat selects the widened
// historical witness-range bound (q+1)*N, which the shared verify core
// derives behind its malformed-input guard. The prover and every other
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
