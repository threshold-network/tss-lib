// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
)

const (
	randomIntBitLen = 1024
)

func TestGetRandomInt(t *testing.T) {
	rnd := common.MustGetRandomInt(randomIntBitLen)
	assert.NotZero(t, rnd, "rand int should not be zero")
}

func TestGetRandomPositiveInt(t *testing.T) {
	rnd := common.MustGetRandomInt(randomIntBitLen)
	rndPos := common.GetRandomPositiveInt(rnd)
	assert.NotZero(t, rndPos, "rand int should not be zero")
	assert.True(t, rndPos.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
}

func TestGetRandomPositiveIntRejectsNoPositiveRange(t *testing.T) {
	assert.Nil(t, common.GetRandomPositiveInt(nil))
	assert.Nil(t, common.GetRandomPositiveInt(big.NewInt(0)))
	assert.Nil(t, common.GetRandomPositiveInt(big.NewInt(1)))
}

func TestGetRandomIntPreservesZeroInclusiveRange(t *testing.T) {
	assert.Nil(t, common.GetRandomInt(nil))
	assert.Nil(t, common.GetRandomInt(big.NewInt(0)))
	assert.Zero(t, common.GetRandomInt(big.NewInt(1)).Sign())
}

func TestGetRandomPositiveRelativelyPrimeInt(t *testing.T) {
	rnd := common.MustGetRandomInt(randomIntBitLen)
	rndPosRP := common.GetRandomPositiveRelativelyPrimeInt(rnd)
	assert.NotZero(t, rndPosRP, "rand int should not be zero")
	assert.True(t, common.IsNumberInMultiplicativeGroup(rnd, rndPosRP))
	assert.True(t, rndPosRP.Cmp(big.NewInt(0)) == 1, "rand int should be positive")
	// TODO test for relative primeness
}

func TestGetRandomPositiveRelativelyPrimeIntRejectsEmptyDomain(t *testing.T) {
	for _, n := range []*big.Int{nil, big.NewInt(-1), big.NewInt(0), big.NewInt(1)} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			assert.Nil(t, common.GetRandomPositiveRelativelyPrimeInt(n))
			assert.Nil(t, common.GetRandomGeneratorOfTheQuadraticResidue(n))
		})
	}
	assert.Equal(t, big.NewInt(1), common.GetRandomPositiveRelativelyPrimeInt(big.NewInt(2)))
	n := big.NewInt(77)
	assert.True(t, common.IsNumberInMultiplicativeGroup(n, common.GetRandomGeneratorOfTheQuadraticResidue(n)))
}

func TestGetRandomPrimeInt(t *testing.T) {
	prime := common.GetRandomPrimeInt(randomIntBitLen)
	assert.NotZero(t, prime, "rand prime should not be zero")
	assert.True(t, prime.ProbablyPrime(50), "rand prime should be prime")
}

func TestGetRandomPrimeIntRejectsEmptyDomain(t *testing.T) {
	for _, bits := range []int{-1, 0, 1} {
		assert.Nil(t, common.GetRandomPrimeInt(bits))
	}
	prime := common.GetRandomPrimeInt(2)
	if assert.NotNil(t, prime) {
		assert.Equal(t, 2, prime.BitLen())
		assert.True(t, prime.ProbablyPrime(50))
	}
}

// TestSamplersReturnNilAboveCap pins the sampler width contract: a limit
// wider than the 5000-bit MustGetRandomInt cap gives nil instead of a panic,
// so callers that check for nil can return an error to their caller. A
// limit at exactly the cap still samples.
func TestSamplersReturnNilAboveCap(t *testing.T) {
	const capBits = 5000
	atCap := new(big.Int).Lsh(big.NewInt(1), capBits-1)
	atCap.Add(atCap, big.NewInt(1)) // odd, exactly capBits bits
	aboveCap := new(big.Int).Lsh(big.NewInt(1), capBits)
	aboveCap.Add(aboveCap, big.NewInt(1)) // odd, capBits+1 bits

	samplers := map[string]func(*big.Int) *big.Int{
		"GetRandomPositiveInt":                    common.GetRandomPositiveInt,
		"GetRandomPositiveRelativelyPrimeInt":     common.GetRandomPositiveRelativelyPrimeInt,
		"GetRandomGeneratorOfTheQuadraticResidue": common.GetRandomGeneratorOfTheQuadraticResidue,
		"GetRandomInt":                            common.GetRandomInt,
	}
	for name, sample := range samplers {
		t.Run(name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				assert.Nil(t, sample(aboveCap), "limit above the cap must give nil")
			})
		})
	}
	// GetRandomInt samples below 2*limit-1, so its widest usable limit is
	// one bit narrower than the cap.
	assert.Nil(t, common.GetRandomInt(atCap))
	assert.NotNil(t, common.GetRandomInt(new(big.Int).Rsh(atCap, 1)))
	assert.Nil(t, common.GetRandomIntIn2PowerRange(capBits))
	assert.Nil(t, common.GetRandomIntIn2PowerMulRange(capBits-10, big.NewInt(1<<20)))

	assert.NotNil(t, common.GetRandomPositiveInt(atCap))
	assert.NotNil(t, common.GetRandomPositiveRelativelyPrimeInt(atCap))
}
