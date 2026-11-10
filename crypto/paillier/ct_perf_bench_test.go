// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package paillier

import (
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
)

// These benchmarks pin the constant-time hot paths changed here: Encrypt's
// gamma^m now uses the Paillier binomial identity instead of a full modexp,
// and HomoMult/Decrypt pad their secret exponents to the proven N.BitLen()
// bound instead of N2's (roughly double) default width. A regression that
// reintroduces the wider exponentiation should show up as a multi-x
// slowdown here.

func setUpCTPerfBench(b *testing.B) *PublicKey {
	b.Helper()
	previousMode := common.IsConstantTimeEnabled()
	b.Cleanup(func() {
		if previousMode {
			common.EnableConstantTimeOps()
		} else {
			common.DisableConstantTimeOps()
		}
	})
	common.EnableConstantTimeOps()

	_, pk, err := loadFixturePaillierKey(0)
	if err != nil {
		b.Fatal(err)
	}
	return pk
}

// BenchmarkEncryptCT benchmarks Encrypt's constant-time path, where gamma^m
// mod N2 is now the binomial identity 1+m*N (one CT multiply) rather than a
// full-width bigmod.Exp.
func BenchmarkEncryptCT(b *testing.B) {
	pk := setUpCTPerfBench(b)
	m := big.NewInt(123456789)

	for b.Loop() {
		if _, err := pk.Encrypt(m); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkHomoMultCT benchmarks HomoMult's constant-time path with the
// multiplier at N-1, the width boundary that exercises the full N.BitLen()
// exponent padding ExpCTWithBitLen now uses (instead of N2's wider default).
func BenchmarkHomoMultCT(b *testing.B) {
	pk := setUpCTPerfBench(b)
	c1, err := pk.Encrypt(big.NewInt(42))
	if err != nil {
		b.Fatal(err)
	}
	m := new(big.Int).Sub(pk.N, big.NewInt(1))

	for b.Loop() {
		if _, err := pk.HomoMult(m, c1); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDecryptCT benchmarks Decrypt's constant-time path: cExpLambda now
// pads to N.BitLen() instead of N2's default width, and gammaExpLambda uses
// the binomial identity instead of a second full-width bigmod.Exp.
func BenchmarkDecryptCT(b *testing.B) {
	pk := setUpCTPerfBench(b)
	sk, _, err := loadFixturePaillierKey(0)
	if err != nil {
		b.Fatal(err)
	}
	c, err := pk.Encrypt(big.NewInt(42))
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		if _, err := sk.Decrypt(c); err != nil {
			b.Fatal(err)
		}
	}
}
