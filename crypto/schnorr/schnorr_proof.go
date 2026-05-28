// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package schnorr

import (
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/tss"
)

type (
	ZKProof struct {
		Alpha *crypto.ECPoint
		T     *big.Int
	}

	ZKVProof struct {
		Alpha *crypto.ECPoint
		T, U  *big.Int
	}
)

const (
	fsDomainTagZK  = "tss-lib.threshold.schnorr.zk"
	fsDomainTagZKV = "tss-lib.threshold.schnorr.zkv"
)

func fsSessionZK(session []byte) []byte {
	return append([]byte(fsDomainTagZK+"|"), session...)
}

func fsSessionZKV(session []byte) []byte {
	return append([]byte(fsDomainTagZKV+"|"), session...)
}

// NewZKProof constructs a new Schnorr ZK proof of knowledge of the discrete logarithm (GG18Spec Fig. 16)
func NewZKProof(x *big.Int, X *crypto.ECPoint) (*ZKProof, error) {
	return NewZKProofWithSession(nil, x, X)
}

// NewZKProofWithSession constructs a Schnorr proof with the session bound into
// the Fiat-Shamir challenge.
func NewZKProofWithSession(session []byte, x *big.Int, X *crypto.ECPoint) (*ZKProof, error) {
	if x == nil || X == nil || !X.ValidateBasic() {
		return nil, errors.New("ZKProof constructor received nil or invalid value(s)")
	}
	ec := X.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy) // already on the curve.

	a := common.GetRandomPositiveInt(q)
	alpha := crypto.ScalarBaseMult(ec, a)

	cHash := common.SHA512_256i_TAGGED(fsSessionZK(session), X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
	c := common.ModReduceHash(q, cHash)
	t := new(big.Int).Mul(c, x)
	t = common.ModInt(q).Add(a, t)

	return &ZKProof{Alpha: alpha, T: t}, nil
}

// NewZKProof verifies a new Schnorr ZK proof of knowledge of the discrete logarithm (GG18Spec Fig. 16)
func (pf *ZKProof) Verify(X *crypto.ECPoint) bool {
	return pf.VerifyWithSession(nil, X)
}

// VerifyWithSession verifies a Schnorr proof with the session bound into the
// Fiat-Shamir challenge.
func (pf *ZKProof) VerifyWithSession(session []byte, X *crypto.ECPoint) bool {
	if pf == nil || !pf.ValidateBasic() || X == nil || !X.ValidateBasic() {
		return false
	}
	if !tss.SameCurve(X.Curve(), pf.Alpha.Curve()) {
		return false
	}
	ec := X.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	if !isValidScalar(pf.T, q) {
		return false
	}
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	cHash := common.SHA512_256i_TAGGED(fsSessionZK(session), X.X(), X.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
	c := common.ModReduceHash(q, cHash)
	if c.Sign() == 0 {
		return false
	}

	tG := crypto.ScalarBaseMult(ec, pf.T)
	Xc := X.ScalarMult(c)
	if tG == nil || Xc == nil {
		return false
	}
	aXc, err := pf.Alpha.Add(Xc)
	if err != nil {
		return false
	}
	return aXc.X().Cmp(tG.X()) == 0 && aXc.Y().Cmp(tG.Y()) == 0
}

func (pf *ZKProof) ValidateBasic() bool {
	return pf.T != nil && pf.Alpha != nil && pf.Alpha.ValidateBasic()
}

// NewZKProof constructs a new Schnorr ZK proof of knowledge s_i, l_i such that V_i = R^s_i, g^l_i (GG18Spec Fig. 17)
func NewZKVProof(V, R *crypto.ECPoint, s, l *big.Int) (*ZKVProof, error) {
	return NewZKVProofWithSession(nil, V, R, s, l)
}

// NewZKVProofWithSession constructs a Schnorr V proof with the session bound
// into the Fiat-Shamir challenge.
func NewZKVProofWithSession(session []byte, V, R *crypto.ECPoint, s, l *big.Int) (*ZKVProof, error) {
	if V == nil || R == nil || s == nil || l == nil || !V.ValidateBasic() || !R.ValidateBasic() {
		return nil, errors.New("ZKVProof constructor received nil value(s)")
	}
	ec := V.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	a, b := common.GetRandomPositiveInt(q), common.GetRandomPositiveInt(q)
	aR := R.ScalarMult(a)
	bG := crypto.ScalarBaseMult(ec, b)
	alpha, _ := aR.Add(bG) // already on the curve.

	cHash := common.SHA512_256i_TAGGED(fsSessionZKV(session), V.X(), V.Y(), R.X(), R.Y(), g.X(), g.Y(), alpha.X(), alpha.Y())
	c := common.ModReduceHash(q, cHash)

	modQ := common.ModInt(q)
	t := modQ.Add(a, new(big.Int).Mul(c, s))
	u := modQ.Add(b, new(big.Int).Mul(c, l))

	return &ZKVProof{Alpha: alpha, T: t, U: u}, nil
}

func (pf *ZKVProof) Verify(V, R *crypto.ECPoint) bool {
	return pf.VerifyWithSession(nil, V, R)
}

// VerifyWithSession verifies a Schnorr V proof with the session bound into the
// Fiat-Shamir challenge.
func (pf *ZKVProof) VerifyWithSession(session []byte, V, R *crypto.ECPoint) bool {
	if pf == nil || !pf.ValidateBasic() ||
		V == nil || R == nil || !V.ValidateBasic() || !R.ValidateBasic() {
		return false
	}
	if !tss.SameCurve(V.Curve(), R.Curve()) || !tss.SameCurve(V.Curve(), pf.Alpha.Curve()) {
		return false
	}
	ec := V.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	if !isValidScalar(pf.T, q) || !isValidScalar(pf.U, q) {
		return false
	}
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	cHash := common.SHA512_256i_TAGGED(fsSessionZKV(session), V.X(), V.Y(), R.X(), R.Y(), g.X(), g.Y(), pf.Alpha.X(), pf.Alpha.Y())
	c := common.ModReduceHash(q, cHash)
	if c.Sign() == 0 {
		return false
	}

	tR := R.ScalarMult(pf.T)
	uG := crypto.ScalarBaseMult(ec, pf.U)
	if tR == nil || uG == nil {
		return false
	}
	tRuG, err := tR.Add(uG)
	if err != nil {
		return false
	}

	Vc := V.ScalarMult(c)
	if Vc == nil {
		return false
	}
	aVc, err := pf.Alpha.Add(Vc)
	if err != nil {
		return false
	}
	return tRuG.X().Cmp(aVc.X()) == 0 && tRuG.Y().Cmp(aVc.Y()) == 0
}

func (pf *ZKVProof) ValidateBasic() bool {
	return pf.Alpha != nil && pf.T != nil && pf.U != nil && pf.Alpha.ValidateBasic()
}

func isValidScalar(k, q *big.Int) bool {
	return k != nil && k.Sign() > 0 && k.Cmp(q) < 0
}
