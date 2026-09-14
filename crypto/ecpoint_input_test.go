// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto_test

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/tss"
)

func TestECPointInputGuards(t *testing.T) {
	g := crypto.ScalarBaseMult(tss.EC(), big.NewInt(1))
	for _, point := range []*crypto.ECPoint{
		nil,
		crypto.NewECPointNoCurveCheck(tss.EC(), nil, g.Y()),
		crypto.NewECPointNoCurveCheck(tss.EC(), g.X(), nil),
	} {
		assert.False(t, point.IsOnCurve())
		assert.False(t, point.Equals(g))
		assert.False(t, g.Equals(point))
		assert.False(t, point.Equals(point))
	}
	assert.False(t, crypto.NewECPointNoCurveCheck(nil, g.X(), g.Y()).IsOnCurve())
	assert.True(t, g.IsOnCurve())
	assert.True(t, g.Equals(crypto.ScalarBaseMult(tss.EC(), big.NewInt(1))))
	assert.False(t, g.Equals(crypto.ScalarBaseMult(tss.EC(), big.NewInt(2))))

	for _, test := range []struct {
		name string
		read func() *big.Int
	}{
		{"ECPoint.X:", (*crypto.ECPoint)(nil).X},
		{"ECPoint.Y:", (*crypto.ECPoint)(nil).Y},
		{"ECPoint.X:", crypto.NewECPointNoCurveCheck(tss.EC(), nil, g.Y()).X},
		{"ECPoint.Y:", crypto.NewECPointNoCurveCheck(tss.EC(), g.X(), nil).Y},
	} {
		func() {
			defer func() {
				value := recover()
				if assert.NotNil(t, value) {
					assert.Contains(t, fmt.Sprint(value), test.name)
				}
			}()
			test.read()
		}()
	}
	x, y := g.X(), g.Y()
	x.SetInt64(0)
	y.SetInt64(0)
	assert.True(t, g.IsOnCurve(), "coordinate accessors return copies")
	_, err := (*crypto.ECPoint)(nil).GobEncode()
	assert.Error(t, err)
}

func TestECPointGobCoordinateLengths(t *testing.T) {
	g := crypto.ScalarBaseMult(tss.EC(), big.NewInt(1))
	encoded, err := g.GobEncode()
	if !assert.NoError(t, err) {
		return
	}
	var decoded crypto.ECPoint
	assert.NoError(t, decoded.GobDecode(encoded))
	assert.True(t, g.Equals(&decoded))
	assert.NoError(t, decoded.GobDecode(append(append([]byte(nil), encoded...), 0)))

	shortX := make([]byte, 6)
	binary.LittleEndian.PutUint32(shortX, 3)
	for _, input := range [][]byte{shortX, encoded[:len(encoded)-1]} {
		err := decoded.GobDecode(input)
		if assert.Error(t, err) {
			assert.Contains(t, err.Error(), "coordinate length exceeds remaining bytes")
		}
	}
}
