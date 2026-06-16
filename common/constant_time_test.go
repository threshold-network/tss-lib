// Copyright © 2019-2024 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
	"time"
)

// TestExpCTCorrectness verifies that constant-time exponentiation produces
// correct results by comparing with math/big.Exp
func TestExpCTCorrectness(t *testing.T) {
	// Generate test parameters - use odd modulus for bigmod
	p, _ := rand.Prime(rand.Reader, 512)
	q, _ := rand.Prime(rand.Reader, 512)
	N := new(big.Int).Mul(p, q)

	ctMod := NewCTModInt(N)

	testCases := []struct {
		name    string
		expBits int
	}{
		{"small_exp", 32},
		{"medium_exp", 256},
		{"large_exp", 1024},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			base, _ := rand.Int(rand.Reader, N)
			exp, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(tc.expBits)))

			ctResult := ctMod.ExpCT(base, exp)
			expectedResult := new(big.Int).Exp(base, exp, N)

			if ctResult.Cmp(expectedResult) != 0 {
				t.Errorf("ExpCT result mismatch for %s: got %v, expected %v", tc.name, ctResult, expectedResult)
			}
		})
	}
}

// TestExpCTEdgeCases tests edge cases for constant-time exponentiation
func TestExpCTEdgeCases(t *testing.T) {
	p, _ := rand.Prime(rand.Reader, 512)
	q, _ := rand.Prime(rand.Reader, 512)
	N := new(big.Int).Mul(p, q)
	ctMod := NewCTModInt(N)

	base, _ := rand.Int(rand.Reader, N)

	// Test exp = 0
	result := ctMod.ExpCT(base, big.NewInt(0))
	if result.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("ExpCT(base, 0) should be 1, got %v", result)
	}

	// Test exp = 1
	result = ctMod.ExpCT(base, big.NewInt(1))
	expected := new(big.Int).Mod(base, N)
	if result.Cmp(expected) != 0 {
		t.Errorf("ExpCT(base, 1) should be base mod N, got %v, expected %v", result, expected)
	}

	// Test base = 0
	result = ctMod.ExpCT(big.NewInt(0), big.NewInt(5))
	if result.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("ExpCT(0, exp) should be 0, got %v", result)
	}

	// Test base = 1
	exp, _ := rand.Int(rand.Reader, big.NewInt(1000))
	result = ctMod.ExpCT(big.NewInt(1), exp)
	if result.Cmp(big.NewInt(1)) != 0 {
		t.Errorf("ExpCT(1, exp) should be 1, got %v", result)
	}
}

// TestModInverseCTCorrectness verifies constant-time ModInverse correctness
func TestModInverseCTCorrectness(t *testing.T) {
	p, _ := rand.Prime(rand.Reader, 1024)
	ctMod := NewCTModInt(p)

	for i := 0; i < 10; i++ {
		a, _ := rand.Int(rand.Reader, p)
		if a.Cmp(big.NewInt(0)) == 0 {
			a = big.NewInt(1)
		}

		ctInv := ctMod.ModInverseCT(a)
		stdInv := new(big.Int).ModInverse(a, p)

		if ctInv.Cmp(stdInv) != 0 {
			t.Errorf("ModInverseCT mismatch: got %v, expected %v", ctInv, stdInv)
		}

		product := new(big.Int).Mul(a, ctInv)
		product.Mod(product, p)
		if product.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("Inverse verification failed: a * a^(-1) = %v, expected 1", product)
		}
	}
}

// TestMulCTCorrectness verifies constant-time multiplication correctness
func TestMulCTCorrectness(t *testing.T) {
	p, _ := rand.Prime(rand.Reader, 1024)
	ctMod := NewCTModInt(p)

	for i := 0; i < 10; i++ {
		x, _ := rand.Int(rand.Reader, p)
		y, _ := rand.Int(rand.Reader, p)

		ctResult := ctMod.MulCT(x, y)
		expected := new(big.Int).Mul(x, y)
		expected.Mod(expected, p)

		if ctResult.Cmp(expected) != 0 {
			t.Errorf("MulCT mismatch: got %v, expected %v", ctResult, expected)
		}
	}
}

// TestCTModIntWithPhi verifies ModInverse for composite moduli with known phi
func TestCTModIntWithPhi(t *testing.T) {
	// Generate RSA-like modulus n = p * q
	p, _ := rand.Prime(rand.Reader, 512)
	q, _ := rand.Prime(rand.Reader, 512)
	n := new(big.Int).Mul(p, q)

	// phi(n) = (p-1) * (q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phiN := new(big.Int).Mul(pMinus1, qMinus1)

	ctMod := NewCTModIntWithPhi(n, phiN)

	for i := 0; i < 5; i++ {
		// Generate a coprime to n
		a, _ := rand.Int(rand.Reader, n)
		gcd := new(big.Int).GCD(nil, nil, a, n)
		for gcd.Cmp(big.NewInt(1)) != 0 {
			a, _ = rand.Int(rand.Reader, n)
			gcd = new(big.Int).GCD(nil, nil, a, n)
		}

		ctInv := ctMod.ModInverseCT(a)
		stdInv := new(big.Int).ModInverse(a, n)

		if ctInv.Cmp(stdInv) != 0 {
			t.Errorf("ModInverseCT with phi mismatch: got %v, expected %v", ctInv, stdInv)
		}

		// Verify: a * a^(-1) = 1 mod n
		product := new(big.Int).Mul(a, ctInv)
		product.Mod(product, n)
		if product.Cmp(big.NewInt(1)) != 0 {
			t.Errorf("Inverse verification with phi failed: a * a^(-1) = %v, expected 1", product)
		}
	}
}

// TestModInverseCTNonCoprime: for a base that shares a factor with the modulus there
// is no inverse; ModInverseCT must return nil, matching math/big.ModInverse. Regression
// for the Fermat/Euler-inverse silent-wrong-answer issue.
func TestModInverseCTNonCoprime(t *testing.T) {
	p, _ := rand.Prime(rand.Reader, 256)
	q, _ := rand.Prime(rand.Reader, 256)
	n := new(big.Int).Mul(p, q)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phiN := new(big.Int).Mul(pMinus1, qMinus1)

	ctMod := NewCTModIntWithPhi(n, phiN)

	// a = p shares the factor p with n, so it is not invertible mod n.
	if got := ctMod.ModInverseCT(p); got != nil {
		t.Errorf("ModInverseCT(p) for non-coprime input must be nil, got %v", got)
	}
	if std := new(big.Int).ModInverse(p, n); std != nil {
		t.Errorf("sanity: math/big.ModInverse(p, n) should also be nil, got %v", std)
	}
}

// TestExpCTExponentPadding verifies that padding the exponent to a fixed width (the
// fix that hides the secret exponent's magnitude) does not change the result: leftPad
// zero-extends correctly, and a short exponent still produces the same value as
// math/big.Exp. Regression for the fixed-width exponent padding.
func TestExpCTExponentPadding(t *testing.T) {
	if got := leftPad([]byte{0x12, 0x34}, 5); !bytes.Equal(got, []byte{0, 0, 0, 0x12, 0x34}) {
		t.Errorf("leftPad zero-extension = %v, want [0 0 0 18 52]", got)
	}
	if got := leftPad([]byte{0x12, 0x34}, 1); !bytes.Equal(got, []byte{0x12, 0x34}) {
		t.Errorf("leftPad with width <= len must return input unchanged, got %v", got)
	}

	p, _ := rand.Prime(rand.Reader, 512)
	q, _ := rand.Prime(rand.Reader, 512)
	N := new(big.Int).Mul(p, q)
	ctMod := NewCTModInt(N)
	base, _ := rand.Int(rand.Reader, N)

	// A short exponent is padded to the full modulus width internally; the result must
	// still match math/big.Exp.
	for _, exp := range []*big.Int{big.NewInt(1), big.NewInt(0x010203), big.NewInt(255)} {
		want := new(big.Int).Exp(base, exp, N)
		if got := ctMod.ExpCT(base, exp); got.Cmp(want) != 0 {
			t.Errorf("ExpCT(base, %v) = %v, want %v", exp, got, want)
		}
	}
}

// BenchmarkExpCT benchmarks constant-time exponentiation
func BenchmarkExpCT(b *testing.B) {
	p, _ := rand.Prime(rand.Reader, 1024)
	q, _ := rand.Prime(rand.Reader, 1024)
	N := new(big.Int).Mul(p, q)
	ctMod := NewCTModInt(N)

	base, _ := rand.Int(rand.Reader, N)
	exp, _ := rand.Int(rand.Reader, N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ctMod.ExpCT(base, exp)
	}
}

// BenchmarkExpStandard benchmarks standard math/big exponentiation for comparison
func BenchmarkExpStandard(b *testing.B) {
	p, _ := rand.Prime(rand.Reader, 1024)
	q, _ := rand.Prime(rand.Reader, 1024)
	N := new(big.Int).Mul(p, q)

	base, _ := rand.Int(rand.Reader, N)
	exp, _ := rand.Int(rand.Reader, N)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		new(big.Int).Exp(base, exp, N)
	}
}

// TestExpCTTimingConsistency checks timing consistency
func TestExpCTTimingConsistency(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}

	p, _ := rand.Prime(rand.Reader, 512)
	q, _ := rand.Prime(rand.Reader, 512)
	N := new(big.Int).Mul(p, q)
	ctMod := NewCTModInt(N)

	base, _ := rand.Int(rand.Reader, N)

	expLowHamming := new(big.Int).Lsh(big.NewInt(1), 511)
	expHighHamming := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 512), big.NewInt(1))

	const iterations = 100
	var timesLow, timesHigh []time.Duration

	for i := 0; i < iterations; i++ {
		start := time.Now()
		ctMod.ExpCT(base, expLowHamming)
		timesLow = append(timesLow, time.Since(start))

		start = time.Now()
		ctMod.ExpCT(base, expHighHamming)
		timesHigh = append(timesHigh, time.Since(start))
	}

	var sumLow, sumHigh time.Duration
	for i := 0; i < iterations; i++ {
		sumLow += timesLow[i]
		sumHigh += timesHigh[i]
	}
	meanLow := sumLow / time.Duration(iterations)
	meanHigh := sumHigh / time.Duration(iterations)

	ratio := float64(meanHigh) / float64(meanLow)
	if ratio < 0.5 || ratio > 2.0 {
		t.Logf("Warning: Timing ratio between high and low Hamming weight exponents: %.2f", ratio)
		t.Logf("Low Hamming mean: %v, High Hamming mean: %v", meanLow, meanHigh)
	}
}
