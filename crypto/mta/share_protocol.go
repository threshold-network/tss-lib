// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"crypto/elliptic"
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
)

// ErrRangeProofVerify signals that BobMid/BobMidWC rejected the peer-supplied
// RangeProofAlice. Callers can use errors.Is to preserve peer attribution while
// distinguishing proof rejection from local arithmetic failures.
var ErrRangeProofVerify = errors.New("RangeProofAlice.Verify() returned false")

func AliceInit(
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	a, NTildeB, h1B, h2B *big.Int,
	session ...[]byte,
) (cA *big.Int, pf *RangeProofAlice, err error) {
	cA, rA, err := pkA.EncryptAndReturnRandomness(a)
	if err != nil {
		return nil, nil, err
	}
	pf, err = ProveRangeAlice(ec, pkA, cA, NTildeB, h1B, h2B, a, rA, session...)
	return cA, pf, err
}

func BobMid(
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *RangeProofAlice,
	b, cA, NTildeA, h1A, h2A, NTildeB, h1B, h2B *big.Int,
	session ...[]byte,
) (beta, cB, betaPrm *big.Int, piB *ProofBob, err error) {
	if !pf.Verify(ec, pkA, NTildeB, h1B, h2B, cA, session...) {
		err = ErrRangeProofVerify
		return
	}
	q := ec.Params().N
	q5 := new(big.Int).Mul(q, q)
	q5 = new(big.Int).Mul(q5, q5)
	q5 = new(big.Int).Mul(q5, q)
	betaPrm = common.GetRandomPositiveInt(q5)
	cBetaPrm, cRand, err := pkA.EncryptAndReturnRandomness(betaPrm)
	if err != nil {
		return
	}
	cB, err = pkA.HomoMult(b, cA)
	if err != nil {
		return
	}
	cB, err = pkA.HomoAdd(cB, cBetaPrm)
	if err != nil {
		return
	}
	beta = common.ModInt(q).Sub(zero, betaPrm)
	piB, err = ProveBob(ec, pkA, NTildeA, h1A, h2A, cA, cB, b, betaPrm, cRand, session...)
	return
}

func BobMidWC(
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *RangeProofAlice,
	b, cA, NTildeA, h1A, h2A, NTildeB, h1B, h2B *big.Int,
	B *crypto.ECPoint,
	session ...[]byte,
) (beta, cB, betaPrm *big.Int, piB *ProofBobWC, err error) {
	if !pf.Verify(ec, pkA, NTildeB, h1B, h2B, cA, session...) {
		err = ErrRangeProofVerify
		return
	}
	q := ec.Params().N
	q5 := new(big.Int).Mul(q, q)
	q5 = new(big.Int).Mul(q5, q5)
	q5 = new(big.Int).Mul(q5, q)
	betaPrm = common.GetRandomPositiveInt(q5)
	cBetaPrm, cRand, err := pkA.EncryptAndReturnRandomness(betaPrm)
	if err != nil {
		return
	}
	cB, err = pkA.HomoMult(b, cA)
	if err != nil {
		return
	}
	cB, err = pkA.HomoAdd(cB, cBetaPrm)
	if err != nil {
		return
	}
	beta = common.ModInt(q).Sub(zero, betaPrm)
	piB, err = ProveBobWC(ec, pkA, NTildeA, h1A, h2A, cA, cB, b, betaPrm, cRand, B, session...)
	return
}

func AliceEnd(
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *ProofBob,
	h1A, h2A, cA, cB, NTildeA *big.Int,
	sk *paillier.PrivateKey,
	session ...[]byte,
) (*big.Int, error) {
	if !pf.Verify(ec, pkA, NTildeA, h1A, h2A, cA, cB, session...) {
		return nil, errors.New("ProofBob.Verify() returned false")
	}
	alphaPrm, err := sk.Decrypt(cB)
	if err != nil {
		return nil, err
	}
	q := ec.Params().N
	return new(big.Int).Mod(alphaPrm, q), nil
}

func AliceEndWC(
	ec elliptic.Curve,
	pkA *paillier.PublicKey,
	pf *ProofBobWC,
	B *crypto.ECPoint,
	cA, cB, NTildeA, h1A, h2A *big.Int,
	sk *paillier.PrivateKey,
	session ...[]byte,
) (*big.Int, error) {
	if !pf.Verify(ec, pkA, NTildeA, h1A, h2A, cA, cB, B, session...) {
		return nil, errors.New("ProofBobWC.Verify() returned false")
	}
	alphaPrm, err := sk.Decrypt(cB)
	if err != nil {
		return nil, err
	}
	q := ec.Params().N
	return new(big.Int).Mod(alphaPrm, q), nil
}
