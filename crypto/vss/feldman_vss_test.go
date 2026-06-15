// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package vss_test

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	. "github.com/bnb-chain/tss-lib/crypto/vss"
	"github.com/bnb-chain/tss-lib/tss"
)

func TestCheckIndexesDup(t *testing.T) {
	indexes := make([]*big.Int, 0)
	for i := 0; i < 1000; i++ {
		indexes = append(indexes, common.GetRandomPositiveInt(tss.EC().Params().N))
	}
	_, e := CheckIndexes(tss.EC(), indexes)
	assert.NoError(t, e)

	indexes = append(indexes, indexes[99])
	_, e = CheckIndexes(tss.EC(), indexes)
	assert.Error(t, e)
}

func TestCheckIndexesZero(t *testing.T) {
	indexes := make([]*big.Int, 0)
	for i := 0; i < 1000; i++ {
		indexes = append(indexes, common.GetRandomPositiveInt(tss.EC().Params().N))
	}
	_, e := CheckIndexes(tss.EC(), indexes)
	assert.NoError(t, e)

	indexes = append(indexes, tss.EC().Params().N)
	_, e = CheckIndexes(tss.EC(), indexes)
	assert.Error(t, e)
}

func TestCreate(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(tss.EC().Params().N))
	}

	vs, _, err := Create(tss.EC(), threshold, secret, ids)
	assert.Nil(t, err)

	assert.Equal(t, threshold+1, len(vs))
	// assert.Equal(t, num, params.NumShares)

	assert.Equal(t, threshold+1, len(vs))

	// ensure that each vs has two points on the curve
	for i, pg := range vs {
		assert.NotZero(t, pg.X())
		assert.NotZero(t, pg.Y())
		assert.True(t, pg.IsOnCurve())
		assert.NotZero(t, vs[i].X())
		assert.NotZero(t, vs[i].Y())
	}
}

func TestVerify(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(tss.EC().Params().N))
	}

	vs, shares, err := Create(tss.EC(), threshold, secret, ids)
	assert.NoError(t, err)

	for i := 0; i < num; i++ {
		assert.True(t, shares[i].Verify(tss.EC(), threshold, vs))
	}
	assert.False(t, shares[0].Verify(tss.EC(), threshold, vs[:threshold]))
}

func TestVerifyAllowsUnregisteredCurve(t *testing.T) {
	ec := elliptic.P256()
	num, threshold := 5, 3
	secret := common.GetRandomPositiveInt(ec.Params().N)

	ids := make([]*big.Int, 0, num)
	for i := 1; i <= num; i++ {
		ids = append(ids, big.NewInt(int64(i)))
	}

	vs, shares, err := Create(ec, threshold, secret, ids)
	assert.NoError(t, err)
	for i := 0; i < num; i++ {
		assert.True(t, shares[i].Verify(ec, threshold, vs))
	}
}

func TestVerifyRejectsMalformedShare(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(tss.EC().Params().N))
	}

	vs, shares, err := Create(tss.EC(), threshold, secret, ids)
	assert.NoError(t, err)

	cases := []struct {
		name  string
		share *Share
	}{
		{
			name: "zero share",
			share: &Share{
				Threshold: shares[0].Threshold,
				ID:        shares[0].ID,
				Share:     big.NewInt(0),
			},
		},
		{
			name: "overwide share",
			share: &Share{
				Threshold: shares[0].Threshold,
				ID:        shares[0].ID,
				Share:     new(big.Int).Set(tss.EC().Params().N),
			},
		},
		{
			name: "zero id",
			share: &Share{
				Threshold: shares[0].Threshold,
				ID:        big.NewInt(0),
				Share:     shares[0].Share,
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				assert.False(t, test.share.Verify(tss.EC(), threshold, vs))
			})
		})
	}
}

func TestReconstruct(t *testing.T) {
	num, threshold := 5, 3

	secret := common.GetRandomPositiveInt(tss.EC().Params().N)

	ids := make([]*big.Int, 0)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(tss.EC().Params().N))
	}

	_, shares, err := Create(tss.EC(), threshold, secret, ids)
	assert.NoError(t, err)

	secret2, err2 := shares[:threshold].ReConstruct(tss.EC())
	assert.Error(t, err2) // not enough shares to satisfy the threshold
	assert.Nil(t, secret2)

	secret3, err3 := shares[:threshold+1].ReConstruct(tss.EC())
	assert.NoError(t, err3)
	assert.NotZero(t, secret3)
	assert.Zero(t, secret.Cmp(secret3))

	secret4, err4 := shares[:num].ReConstruct(tss.EC())
	assert.NoError(t, err4)
	assert.NotZero(t, secret4)
	assert.Zero(t, secret.Cmp(secret4))
}

// TestReconstructRejectsMalformedShares pins ReConstruct's input validation:
// nil share, nil ID, nil Share, zero-mod-q ID, and duplicate IDs must all be
// rejected up front instead of propagating into ModInverse(0) → nil-deref in
// the Lagrange interpolation loop.
func TestReconstructRejectsMalformedShares(t *testing.T) {
	num, threshold := 5, 3
	q := tss.EC().Params().N

	secret := common.GetRandomPositiveInt(q)
	ids := make([]*big.Int, 0, num)
	for i := 0; i < num; i++ {
		ids = append(ids, common.GetRandomPositiveInt(q))
	}
	_, shares, err := Create(tss.EC(), threshold, secret, ids)
	assert.NoError(t, err)

	cases := []struct {
		name   string
		mutate func(Shares) Shares
	}{
		{
			name: "nil share entry",
			mutate: func(in Shares) Shares {
				out := append(Shares(nil), in...)
				out[1] = nil
				return out
			},
		},
		{
			name: "nil ID",
			mutate: func(in Shares) Shares {
				out := append(Shares(nil), in...)
				bad := *in[1]
				bad.ID = nil
				out[1] = &bad
				return out
			},
		},
		{
			name: "nil Share",
			mutate: func(in Shares) Shares {
				out := append(Shares(nil), in...)
				bad := *in[1]
				bad.Share = nil
				out[1] = &bad
				return out
			},
		},
		{
			name: "zero ID mod q",
			mutate: func(in Shares) Shares {
				out := append(Shares(nil), in...)
				bad := *in[1]
				bad.ID = new(big.Int).Set(q) // q mod q == 0
				out[1] = &bad
				return out
			},
		},
		{
			name: "duplicate ID",
			mutate: func(in Shares) Shares {
				out := append(Shares(nil), in...)
				dup := *in[0]
				dup.ID = new(big.Int).Set(in[1].ID)
				out[0] = &dup
				return out
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mutated := tc.mutate(shares[:threshold+1])
			assert.NotPanics(t, func() {
				got, err := mutated.ReConstruct(tss.EC())
				assert.Error(t, err)
				assert.Nil(t, got)
			})
		})
	}
}
