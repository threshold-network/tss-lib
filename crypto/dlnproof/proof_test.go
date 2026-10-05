// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package dlnproof

import (
	"context"
	"errors"
	"math/big"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/common"
)

func TestLegacyChallengeMatchesHistoricalTranscript(t *testing.T) {
	values := []*big.Int{
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(5),
		big.NewInt(7),
	}

	expected := common.SHA512_256i(values...)
	actual := proofChallenge(nil, values...)
	if expected.Cmp(actual) != 0 {
		t.Fatalf("legacy challenge changed: expected %v, got %v", expected, actual)
	}
}

func TestDLNProofRejectsEmptySessionTag(t *testing.T) {
	assertPanics(t, func() {
		_ = NewDLNProof(nil, nil, nil, nil, nil, nil, []byte{})
	})
}

func TestDLNProofVerifyRejectsNilInputs(t *testing.T) {
	// N=23 keeps these as nil-input no-panic checks; the width floor rejects
	// before the nil-input checks run.
	proof := &Proof{}
	for i := range Iterations {
		proof.Alpha[i] = big.NewInt(2)
		proof.T[i] = big.NewInt(2)
	}

	if proof.Verify(nil, big.NewInt(3), big.NewInt(23)) {
		t.Fatal("Verify must reject nil h1")
	}
	if proof.Verify(big.NewInt(2), nil, big.NewInt(23)) {
		t.Fatal("Verify must reject nil h2")
	}
	if proof.Verify(big.NewInt(2), big.NewInt(3), nil) {
		t.Fatal("Verify must reject nil N")
	}
}

func assertNotPanics(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	f()
}

func assertPanics(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	f()
}

// dlnVerifyFixture holds a 2048-bit ring-Pedersen instance and a valid DLN proof
// of the witness alpha, built once per test binary so the expensive 1024-bit
// safe-prime generation runs at most once.
type dlnVerifyFixture struct {
	proof  *Proof
	h1, h2 *big.Int
	N      *big.Int
	factor *big.Int // a prime divisor of N (not in its multiplicative group)
}

var (
	dlnVerifyFixtureOnce sync.Once
	dlnVerifyFixtureVal  *dlnVerifyFixture
	dlnVerifyFixtureErr  error
)

// newDLNVerifyFixture returns the shared 2048-bit DLN instance. The N=23
// moduli used elsewhere cannot exercise the field checks because the width
// floor rejects them first.
func newDLNVerifyFixture(t *testing.T) *dlnVerifyFixture {
	t.Helper()
	dlnVerifyFixtureOnce.Do(func() {
		dlnVerifyFixtureVal, dlnVerifyFixtureErr = buildDLNVerifyFixture()
	})
	if dlnVerifyFixtureErr != nil {
		t.Fatalf("building DLN verify fixture: %v", dlnVerifyFixtureErr)
	}
	return dlnVerifyFixtureVal
}

func buildDLNVerifyFixture() (*dlnVerifyFixture, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	sgps, err := common.GetRandomSafePrimesConcurrent(ctx, 1024, 2, runtime.NumCPU())
	if err != nil {
		return nil, err
	}
	np, nq := sgps[0].SafePrime(), sgps[1].SafePrime()
	N := new(big.Int).Mul(np, nq)
	modN := common.ModInt(N)

	f1 := common.GetRandomPositiveRelativelyPrimeInt(N)
	alpha := common.GetRandomPositiveRelativelyPrimeInt(N)
	h1 := modN.Mul(f1, f1)
	h2 := modN.Exp(h1, alpha)

	proof := NewDLNProof(h1, h2, alpha, sgps[0].Prime(), sgps[1].Prime(), N)
	if !proof.Verify(h1, h2, N) {
		return nil, errors.New("fixture DLN proof did not verify on its own domain")
	}
	if N.BitLen() != common.MinUnknownOrderModulusBitLen {
		return nil, errors.New("fixture modulus is not the minimum width")
	}
	return &dlnVerifyFixture{proof: proof, h1: h1, h2: h2, N: N, factor: sgps[0].Prime()}, nil
}

// TestDLNProofVerifyValidFixture is the positive control for the reject
// tests: the unmutated fixture proof must verify on its own 2048-bit modulus,
// so any reject that asserts false is pinning the check it names rather than
// a broken accept path.
func TestDLNProofVerifyValidFixture(t *testing.T) {
	fx := newDLNVerifyFixture(t)
	if !fx.proof.Verify(fx.h1, fx.h2, fx.N) {
		t.Fatal("a valid DLN proof must verify on its own 2048-bit modulus")
	}
}

// TestDLNProofVerifyRejectsOverwideT rejects T[0] values that fall outside
// the canonical (1, N) range. Without a real modulus width the named check
// is never reached.
func TestDLNProofVerifyRejectsOverwideT(t *testing.T) {
	fx := newDLNVerifyFixture(t)

	for _, tc := range []struct {
		name string
		T    *big.Int
	}{
		{"nil", nil},
		{"one", big.NewInt(1)},
		{"modulus", fx.N},
		{"overwide", new(big.Int).Add(fx.N, big.NewInt(1))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := *fx.proof
			proof.T[0] = tc.T
			assertNotPanics(t, func() {
				if proof.Verify(fx.h1, fx.h2, fx.N) {
					t.Fatalf("Verify must reject T[0] = %v outside (1, N)", tc.T)
				}
			})
		})
	}
}

// TestDLNProofVerifyRejectsOverwideAlpha rejects Alpha[0] values that are
// not canonical generators of the modulus. "non-unit" is a prime factor of
// N, which is outside the multiplicative group mod N.
func TestDLNProofVerifyRejectsOverwideAlpha(t *testing.T) {
	fx := newDLNVerifyFixture(t)

	for _, tc := range []struct {
		name  string
		Alpha *big.Int
	}{
		{"nil", nil},
		{"one", big.NewInt(1)},
		{"modulus", fx.N},
		{"non-unit", fx.factor},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proof := *fx.proof
			proof.Alpha[0] = tc.Alpha
			assertNotPanics(t, func() {
				if proof.Verify(fx.h1, fx.h2, fx.N) {
					t.Fatalf("Verify must reject Alpha[0] = %v outside the canonical generators", tc.Alpha)
				}
			})
		})
	}
}

// TestDLNProofVerifyRejectsInvalidGenerators rejects degenerate generator
// pairs (h1 == h2) and the unit h1 = 1, on a valid 2048-bit domain.
func TestDLNProofVerifyRejectsInvalidGenerators(t *testing.T) {
	fx := newDLNVerifyFixture(t)

	t.Run("h1 equals h2", func(t *testing.T) {
		assertNotPanics(t, func() {
			if fx.proof.Verify(fx.h2, fx.h2, fx.N) {
				t.Fatal("Verify must reject h1 == h2")
			}
		})
	})

	t.Run("h1 is one", func(t *testing.T) {
		assertNotPanics(t, func() {
			if fx.proof.Verify(big.NewInt(1), fx.h2, fx.N) {
				t.Fatal("Verify must reject h1 = 1, which is not a canonical generator")
			}
		})
	})
}

// TestDLNProofVerifyModulusPolicy pins the unknown-order modulus policy on
// a valid 2048-bit domain. The valid proof is reused, only the modulus
// argument changes; each reject comes from a distinct width/parity/ceiling
// predicate.
func TestDLNProofVerifyModulusPolicy(t *testing.T) {
	fx := newDLNVerifyFixture(t)

	underFloor := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), uint(common.MinUnknownOrderModulusBitLen-2)), big.NewInt(1)) // 2^2046 + 1: 2047 bits, odd
	overCeiling := new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), uint(common.MaxUnknownOrderModulusBitLen)), big.NewInt(1))  // 2^65536 + 1: 65537 bits, odd
	evenAtFloor := new(big.Int).Lsh(big.NewInt(1), uint(common.MinUnknownOrderModulusBitLen-1))                                 // 2^2047: 2048 bits, even

	for _, tc := range []struct {
		name string
		N    *big.Int
		want bool
	}{
		{"2048-bit control accepts", fx.N, true},
		{"2047-bit rejects by width floor", underFloor, false},
		{"65537-bit rejects by width ceiling", overCeiling, false},
		{"even rejects by parity", evenAtFloor, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assertNotPanics(t, func() {
				if got := fx.proof.Verify(fx.h1, fx.h2, tc.N); got != tc.want {
					t.Fatalf("Verify with %d-bit modulus = %v, want %v", tc.N.BitLen(), got, tc.want)
				}
			})
		})
	}
}
