// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Feldman VSS, based on Paul Feldman, 1987., A practical scheme for non-interactive verifiable secret sharing.
// In Foundations of Computer Science, 1987., 28th Annual Symposium on. IEEE, 427–43
//

package vss

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/tss"
)

type (
	Share struct {
		Threshold int
		ID,       // xi
		Share *big.Int // Sigma i
	}

	Vs []*crypto.ECPoint // v0..vt

	Shares []*Share
)

var (
	ErrNumSharesBelowThreshold = fmt.Errorf("not enough shares to satisfy the threshold")

	zero = big.NewInt(0)
	one  = big.NewInt(1)
)

// Check share ids of Shamir's Secret Sharing, return error if duplicate or 0 value found
func CheckIndexes(ec elliptic.Curve, indexes []*big.Int) ([]*big.Int, error) {
	visited := make(map[string]struct{})
	for _, v := range indexes {
		vMod := new(big.Int).Mod(v, ec.Params().N)
		if vMod.Cmp(zero) == 0 {
			return nil, errors.New("party index should not be 0")
		}
		vModStr := vMod.String()
		if _, ok := visited[vModStr]; ok {
			return nil, fmt.Errorf("duplicate indexes %s", vModStr)
		}
		visited[vModStr] = struct{}{}
	}
	return indexes, nil
}

// Returns a new array of secret shares created by Shamir's Secret Sharing Algorithm,
// requiring a minimum number of shares to recreate, of length shares, from the input secret
func Create(ec elliptic.Curve, threshold int, secret *big.Int, indexes []*big.Int) (Vs, Shares, error) {
	if ec == nil {
		return nil, nil, fmt.Errorf("vss ec == nil")
	}
	if secret == nil || indexes == nil {
		return nil, nil, fmt.Errorf("vss secret or indexes == nil: %v %v", secret, indexes)
	}
	if threshold < 1 {
		return nil, nil, errors.New("vss threshold < 1")
	}

	ids, err := CheckIndexes(ec, indexes)
	if err != nil {
		return nil, nil, err
	}

	num := len(indexes)
	if num < threshold+1 {
		return nil, nil, ErrNumSharesBelowThreshold
	}

	poly := samplePolynomial(ec, threshold, secret)
	poly[0] = secret // becomes sigma*G in v
	v := make(Vs, len(poly))
	for i, ai := range poly {
		v[i] = crypto.ScalarBaseMult(ec, ai)
	}

	shares := make(Shares, num)
	for i := 0; i < num; i++ {
		share := evaluatePolynomial(ec, threshold, poly, ids[i])
		shares[i] = &Share{Threshold: threshold, ID: ids[i], Share: share}
	}
	return v, shares, nil
}

func (share *Share) Verify(ec elliptic.Curve, threshold int, vs Vs) bool {
	if share == nil || ec == nil || share.ID == nil || share.Share == nil ||
		share.Threshold != threshold || vs == nil || len(vs) != threshold+1 {
		return false
	}
	q := ec.Params().N
	idModQ := new(big.Int).Mod(share.ID, q)
	if idModQ.Sign() == 0 || share.Share.Sign() <= 0 || share.Share.Cmp(q) >= 0 {
		return false
	}
	var err error
	modQ := common.ModInt(q)
	v, t := vs[0], one // YRO : we need to have our accumulator outside of the loop
	if v == nil || !tss.SameCurve(v.Curve(), ec) || !v.ValidateBasic() {
		return false
	}
	for j := 1; j <= threshold; j++ {
		if vs[j] == nil || !tss.SameCurve(vs[j].Curve(), ec) || !vs[j].ValidateBasic() {
			return false
		}
		// t = k_i^j
		t = modQ.Mul(t, share.ID)
		// v = v * v_j^t
		vjt := vs[j].ScalarMult(t)
		if vjt == nil {
			return false
		}
		v, err = v.Add(vjt)
		if err != nil {
			return false
		}
	}
	sigmaGi := crypto.ScalarBaseMult(ec, share.Share)
	if sigmaGi == nil {
		return false
	}
	return sigmaGi.Equals(v)
}

func (shares Shares) ReConstruct(ec elliptic.Curve) (secret *big.Int, err error) {
	if ec == nil {
		return nil, errors.New("vss reconstruct: ec is nil")
	}
	if len(shares) == 0 {
		return nil, ErrNumSharesBelowThreshold
	}
	if shares[0] == nil {
		return nil, errors.New("vss reconstruct: nil share")
	}
	threshold := shares[0].Threshold
	for idx, share := range shares {
		if share == nil || share.ID == nil || share.Share == nil {
			return nil, fmt.Errorf("vss reconstruct: nil share or share field at index %d", idx)
		}
		if share.Threshold != threshold {
			return nil, fmt.Errorf("vss reconstruct: share %d has threshold %d, want %d", idx, share.Threshold, threshold)
		}
	}
	if threshold+1 > len(shares) {
		return nil, ErrNumSharesBelowThreshold
	}
	q := ec.Params().N
	modN := common.ModInt(q)

	// x coords. Reject zero or duplicate share IDs (mod q) up front: a zero
	// ID encodes the secret directly, and two equal IDs make the Lagrange
	// denominator xs[j]-share.ID zero, which would otherwise propagate into
	// ModInverse(0) → nil → nil-deref in the interpolation loop below.
	xs := make([]*big.Int, 0, len(shares))
	seen := make(map[string]struct{}, len(shares))
	for _, share := range shares {
		if share == nil || share.ID == nil || share.Share == nil {
			return nil, errors.New("vss reconstruct: nil share or share field")
		}
		id := new(big.Int).Mod(share.ID, q)
		if id.Sign() == 0 {
			return nil, errors.New("vss reconstruct: share ID is zero mod q")
		}
		key := id.String()
		if _, dup := seen[key]; dup {
			return nil, fmt.Errorf("vss reconstruct: duplicate share ID %s", key)
		}
		seen[key] = struct{}{}
		xs = append(xs, share.ID)
	}

	secret = zero
	for i, share := range shares {
		times := one
		for j := 0; j < len(xs); j++ {
			if j == i {
				continue
			}
			sub := modN.Sub(xs[j], share.ID)
			subInv := modN.ModInverse(sub)
			div := modN.Mul(xs[j], subInv)
			times = modN.Mul(times, div)
		}

		fTimes := modN.Mul(share.Share, times)
		secret = modN.Add(secret, fTimes)
	}

	return secret, nil
}

func samplePolynomial(ec elliptic.Curve, threshold int, secret *big.Int) []*big.Int {
	q := ec.Params().N
	v := make([]*big.Int, threshold+1)
	v[0] = secret
	for i := 1; i <= threshold; i++ {
		ai := common.GetRandomPositiveInt(q)
		v[i] = ai
	}
	return v
}

// Evauluates a polynomial with coefficients such that:
// evaluatePolynomial([a, b, c, d], x):
//
//	returns a + bx + cx^2 + dx^3
func evaluatePolynomial(ec elliptic.Curve, threshold int, v []*big.Int, id *big.Int) (result *big.Int) {
	q := ec.Params().N
	modQ := common.ModInt(q)
	result = new(big.Int).Set(v[0])
	X := big.NewInt(int64(1))
	for i := 1; i <= threshold; i++ {
		ai := v[i]
		X = modQ.Mul(X, id)
		aiXi := new(big.Int).Mul(ai, X)
		result = modQ.Add(result, aiXi)
	}
	return
}
