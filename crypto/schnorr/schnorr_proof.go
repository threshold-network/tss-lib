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

// NewZKProof constructs a legacy Schnorr ZK proof of knowledge of the discrete
// logarithm (GG18Spec Fig. 16).
//
// Legacy is an exact transcript contract, not merely the absence of a session:
// the challenge is HashToN(q, Xx, Xy, Gx, Gy, AlphaX, AlphaY), in that order,
// matching threshold-network/tss-lib@2e712689cfbe. New protocols should call
// NewZKProofWithSession with a non-empty, ceremony-unique session instead.
func NewZKProof(x *big.Int, X *crypto.ECPoint) (*ZKProof, error) {
	return newZKProof(x, X, legacyZKChallenge)
}

// NewZKProofWithSession constructs a security-v2 Schnorr proof with a non-empty
// session and the ZK domain tag bound into the Fiat-Shamir challenge. A nil or
// empty session is rejected; callers selecting the historical transcript must
// use NewZKProof, so this API can never silently downgrade to legacy.
func NewZKProofWithSession(session []byte, x *big.Int, X *crypto.ECPoint) (*ZKProof, error) {
	if len(session) == 0 {
		return nil, errors.New("schnorr: ZK proof session tag must be non-empty")
	}

	return newZKProof(
		x,
		X,
		func(q *big.Int, X, g, alpha *crypto.ECPoint) *big.Int {
			return sessionBoundZKChallenge(session, q, X, g, alpha)
		},
	)
}

type zkChallenge func(
	q *big.Int,
	X, g, alpha *crypto.ECPoint,
) *big.Int

func newZKProof(
	x *big.Int,
	X *crypto.ECPoint,
	challenge zkChallenge,
) (*ZKProof, error) {
	if x == nil || X == nil || !X.ValidateBasic() {
		return nil, errors.New("ZKProof constructor received nil or invalid value(s)")
	}
	ec := X.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy) // already on the curve.

	a := common.GetRandomPositiveInt(q)
	alpha := crypto.ScalarBaseMult(ec, a)

	c := challenge(q, X, g, alpha)
	t := new(big.Int).Mul(c, x)
	t = common.ModInt(q).Add(a, t)

	return &ZKProof{Alpha: alpha, T: t}, nil
}

// legacyZKChallenge reproduces the historical HashToN input sequence and its
// expand-then-reduce behavior exactly. Keep it separate from the tagged path:
// treating a nil session as a tag would change legacy proof bytes.
func legacyZKChallenge(
	q *big.Int,
	X, g, alpha *crypto.ECPoint,
) *big.Int {
	return common.HashToN(
		q,
		X.X(), X.Y(),
		g.X(), g.Y(),
		alpha.X(), alpha.Y(),
	)
}

// sessionBoundZKChallenge derives the security-v2 ZK challenge. Its callers
// validate that session is non-empty before reaching this function.
func sessionBoundZKChallenge(
	session []byte,
	q *big.Int,
	X, g, alpha *crypto.ECPoint,
) *big.Int {
	cHash := common.SHA512_256i_TAGGED(
		fsSessionZK(session),
		X.X(), X.Y(),
		g.X(), g.Y(),
		alpha.X(), alpha.Y(),
	)
	return common.ModReduceHash(q, cHash)
}

// Verify verifies a ZK proof against the exact historical legacy challenge.
// Session-bound proofs must be verified with VerifyWithSession.
func (pf *ZKProof) Verify(X *crypto.ECPoint) bool {
	return pf.verify(X, legacyZKChallenge)
}

// VerifyWithSession verifies a security-v2 Schnorr proof with a non-empty
// session bound into the challenge. Nil and empty sessions fail closed; use
// Verify for the historical transcript.
func (pf *ZKProof) VerifyWithSession(session []byte, X *crypto.ECPoint) bool {
	if len(session) == 0 {
		return false
	}

	return pf.verify(
		X,
		func(q *big.Int, X, g, alpha *crypto.ECPoint) *big.Int {
			return sessionBoundZKChallenge(session, q, X, g, alpha)
		},
	)
}

func (pf *ZKProof) verify(X *crypto.ECPoint, challenge zkChallenge) bool {
	if pf == nil || !pf.ValidateBasic() || X == nil || !X.ValidateBasic() {
		return false
	}
	if !crypto.SameCurve(X.Curve(), pf.Alpha.Curve()) {
		return false
	}
	ec := X.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	if !isValidScalar(pf.T, q) {
		return false
	}
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	c := challenge(q, X, g, pf.Alpha)
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

// NewZKVProof constructs a legacy Schnorr proof of knowledge of s_i and l_i
// such that V_i = R^s_i g^l_i (GG18Spec Fig. 17).
//
// Its challenge is exactly HashToN(q, Vx, Vy, Rx, Ry, Gx, Gy, AlphaX,
// AlphaY), matching threshold-network/tss-lib@2e712689cfbe. New protocols
// should call NewZKVProofWithSession instead.
func NewZKVProof(V, R *crypto.ECPoint, s, l *big.Int) (*ZKVProof, error) {
	return newZKVProof(V, R, s, l, legacyZKVChallenge)
}

// NewZKVProofWithSession constructs a security-v2 Schnorr V proof with a
// non-empty session and the ZKV domain tag bound into the challenge. A nil or
// empty session is rejected; use NewZKVProof for the historical transcript.
func NewZKVProofWithSession(session []byte, V, R *crypto.ECPoint, s, l *big.Int) (*ZKVProof, error) {
	if len(session) == 0 {
		return nil, errors.New("schnorr: ZKV proof session tag must be non-empty")
	}

	return newZKVProof(
		V,
		R,
		s,
		l,
		func(q *big.Int, V, R, g, alpha *crypto.ECPoint) *big.Int {
			return sessionBoundZKVChallenge(session, q, V, R, g, alpha)
		},
	)
}

type zkvChallenge func(
	q *big.Int,
	V, R, g, alpha *crypto.ECPoint,
) *big.Int

func newZKVProof(
	V, R *crypto.ECPoint,
	s, l *big.Int,
	challenge zkvChallenge,
) (*ZKVProof, error) {
	if V == nil || R == nil || s == nil || l == nil || !V.ValidateBasic() || !R.ValidateBasic() {
		return nil, errors.New("ZKVProof constructor received nil value(s)")
	}
	if !crypto.SameCurve(V.Curve(), R.Curve()) {
		return nil, errors.New("ZKVProof constructor received points on different curves")
	}
	ec := V.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	a, b := common.GetRandomPositiveInt(q), common.GetRandomPositiveInt(q)
	aR := R.ScalarMult(a)
	bG := crypto.ScalarBaseMult(ec, b)
	alpha, _ := aR.Add(bG) // already on the curve.

	c := challenge(q, V, R, g, alpha)

	modQ := common.ModInt(q)
	t := modQ.Add(a, new(big.Int).Mul(c, s))
	u := modQ.Add(b, new(big.Int).Mul(c, l))

	return &ZKVProof{Alpha: alpha, T: t, U: u}, nil
}

// legacyZKVChallenge reproduces the historical HashToN input sequence and
// modular reduction exactly.
func legacyZKVChallenge(
	q *big.Int,
	V, R, g, alpha *crypto.ECPoint,
) *big.Int {
	return common.HashToN(
		q,
		V.X(), V.Y(),
		R.X(), R.Y(),
		g.X(), g.Y(),
		alpha.X(), alpha.Y(),
	)
}

// sessionBoundZKVChallenge derives the security-v2 ZKV challenge. Its callers
// validate that session is non-empty before reaching this function.
func sessionBoundZKVChallenge(
	session []byte,
	q *big.Int,
	V, R, g, alpha *crypto.ECPoint,
) *big.Int {
	cHash := common.SHA512_256i_TAGGED(
		fsSessionZKV(session),
		V.X(), V.Y(),
		R.X(), R.Y(),
		g.X(), g.Y(),
		alpha.X(), alpha.Y(),
	)
	return common.ModReduceHash(q, cHash)
}

// Verify verifies a ZKV proof against the exact historical legacy challenge.
// Session-bound proofs must be verified with VerifyWithSession.
func (pf *ZKVProof) Verify(V, R *crypto.ECPoint) bool {
	return pf.verify(V, R, legacyZKVChallenge)
}

// VerifyWithSession verifies a security-v2 Schnorr V proof with a non-empty
// session bound into the challenge. Nil and empty sessions fail closed; use
// Verify for the historical transcript.
func (pf *ZKVProof) VerifyWithSession(session []byte, V, R *crypto.ECPoint) bool {
	if len(session) == 0 {
		return false
	}

	return pf.verify(
		V,
		R,
		func(q *big.Int, V, R, g, alpha *crypto.ECPoint) *big.Int {
			return sessionBoundZKVChallenge(session, q, V, R, g, alpha)
		},
	)
}

func (pf *ZKVProof) verify(
	V, R *crypto.ECPoint,
	challenge zkvChallenge,
) bool {
	if pf == nil || !pf.ValidateBasic() ||
		V == nil || R == nil || !V.ValidateBasic() || !R.ValidateBasic() {
		return false
	}
	if !crypto.SameCurve(V.Curve(), R.Curve()) || !crypto.SameCurve(V.Curve(), pf.Alpha.Curve()) {
		return false
	}
	ec := V.Curve()
	ecParams := ec.Params()
	q := ecParams.N
	if !isValidScalar(pf.T, q) || !isValidScalar(pf.U, q) {
		return false
	}
	g := crypto.NewECPointNoCurveCheck(ec, ecParams.Gx, ecParams.Gy)

	c := challenge(q, V, R, g, pf.Alpha)
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
