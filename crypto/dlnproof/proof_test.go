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

	"github.com/stretchr/testify/assert"

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
	assert.PanicsWithValue(t, "dlnproof: session tag must be non-empty", func() {
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

// dlnVerifyFixture holds a 2048-bit ring-Pedersen instance and a valid DLN proof
// of the witness alpha, built once per test binary so the expensive 1024-bit
// safe-prime generation runs at most once.
type dlnVerifyFixture struct {
	proof  *Proof
	h1, h2 *big.Int
	N      *big.Int
	alpha  *big.Int // the witness: h2 = h1^alpha mod N
	p, q   *big.Int // Germain primes with N = (2p+1)(2q+1); ord(h1) divides p*q
	factor *big.Int // the safe prime 2p+1, a divisor of N and so not a unit mod N
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
	return &dlnVerifyFixture{
		proof:  proof,
		h1:     h1,
		h2:     h2,
		N:      N,
		alpha:  alpha,
		p:      sgps[0].Prime(),
		q:      sgps[1].Prime(),
		factor: np,
	}, nil
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
			assert.NotPanics(t, func() {
				if proof.Verify(fx.h1, fx.h2, fx.N) {
					t.Fatalf("Verify must reject T[0] = %v outside (1, N)", tc.T)
				}
			})
		})
	}
}

// TestDLNProofVerifyRejectsEquationValidOverwideT isolates the T range
// check. h1 is a square mod N, so its order divides p*q, and T[0] + 5*p*q
// gives the same h1^T[0]. N = 4pq + 2p + 2q + 1 < 5pq, so the shifted T[0]
// is at least N. T is not part of the challenge, so every verification
// equation still holds and only the range check can reject the proof.
func TestDLNProofVerifyRejectsEquationValidOverwideT(t *testing.T) {
	fx := newDLNVerifyFixture(t)
	modN := common.ModInt(fx.N)

	shift := new(big.Int).Mul(fx.p, fx.q)
	shift.Mul(shift, big.NewInt(5))
	proof := *fx.proof
	proof.T[0] = new(big.Int).Add(fx.proof.T[0], shift)

	assert.GreaterOrEqual(t, proof.T[0].Cmp(fx.N), 0, "shifted T[0] must be at least N")
	assert.Zero(t, modN.Exp(fx.h1, proof.T[0]).Cmp(modN.Exp(fx.h1, fx.proof.T[0])),
		"the shift must keep h1^T[0], so the equation still holds")
	assert.False(t, proof.Verify(fx.h1, fx.h2, fx.N),
		"Verify must reject T[0] >= N even when the equation holds")
}

// TestDLNProofVerifyRejectsOverwideAlpha rejects Alpha[0] values that are
// not canonical generators of the modulus. "non-unit" is the safe prime
// 2p+1, a divisor of N, so it is outside the multiplicative group mod N.
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
			assert.NotPanics(t, func() {
				if proof.Verify(fx.h1, fx.h2, fx.N) {
					t.Fatalf("Verify must reject Alpha[0] = %v outside the canonical generators", tc.Alpha)
				}
			})
		})
	}
}

// TestDLNProofVerifyRejectsEquationValidNonCanonicalAlpha isolates the
// Alpha canonical-generator check. The proof is built by the honest
// prover steps, except that N is added to Alpha[0] before the challenge is
// computed. The verifier reduces Alpha[0] mod N in the equation, so the
// equation still holds and the challenge matches. Only the
// canonical-generator check on Alpha can reject this proof.
func TestDLNProofVerifyRejectsEquationValidNonCanonicalAlpha(t *testing.T) {
	fx := newDLNVerifyFixture(t)

	// Control: the same steps without the offset give a proof that
	// verifies, so the reject below comes from the offset alone.
	control := proveDLNWithAlpha0Offset(fx, big.NewInt(0))
	assert.True(t, control.Verify(fx.h1, fx.h2, fx.N), "control proof must verify")

	proof := proveDLNWithAlpha0Offset(fx, fx.N)
	assert.False(t, common.IsCanonicalGenerator(fx.N, proof.Alpha[0]), "Alpha[0] must not be canonical")
	assert.False(t, proof.Verify(fx.h1, fx.h2, fx.N),
		"Verify must reject a non-canonical Alpha[0] even when the equation holds")
}

// proveDLNWithAlpha0Offset runs the math/big prover steps of NewDLNProof on
// the fixture witness, but adds offset to Alpha[0] before the challenge is
// computed.
func proveDLNWithAlpha0Offset(fx *dlnVerifyFixture, offset *big.Int) *Proof {
	pq := new(big.Int).Mul(fx.p, fx.q)
	modN, modPQ := common.ModInt(fx.N), common.ModInt(pq)
	var a, alpha, t [Iterations]*big.Int
	for i := range alpha {
		a[i] = common.GetRandomPositiveInt(pq)
		alpha[i] = modN.Exp(fx.h1, a[i])
	}
	alpha[0] = new(big.Int).Add(alpha[0], offset)
	c := proofChallenge(nil, append([]*big.Int{fx.h1, fx.h2, fx.N}, alpha[:]...)...)
	for i := range t {
		t[i] = modPQ.Add(a[i], modPQ.Mul(big.NewInt(int64(c.Bit(i))), fx.alpha))
	}
	return &Proof{Alpha: alpha, T: t}
}

// TestDLNProofVerifyRejectsInvalidGenerators rejects degenerate generator
// pairs (h1 == h2) and the unit h1 = 1, on a valid 2048-bit domain.
func TestDLNProofVerifyRejectsInvalidGenerators(t *testing.T) {
	fx := newDLNVerifyFixture(t)

	// h2 = h1^1, so the honest prover with witness x = 1 gives a proof
	// whose equations all hold for the pair (h1, h1). Only the h1 == h2
	// check can reject it.
	t.Run("h1 equals h2", func(t *testing.T) {
		proof := NewDLNProof(fx.h1, fx.h1, big.NewInt(1), fx.p, fx.q, fx.N)
		assert.NotPanics(t, func() {
			assert.False(t, proof.Verify(fx.h1, fx.h1, fx.N), "Verify must reject h1 == h2")
		})
	})

	t.Run("h1 is one", func(t *testing.T) {
		assert.NotPanics(t, func() {
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
			assert.NotPanics(t, func() {
				if got := fx.proof.Verify(fx.h1, fx.h2, tc.N); got != tc.want {
					t.Fatalf("Verify with %d-bit modulus = %v, want %v", tc.N.BitLen(), got, tc.want)
				}
			})
		})
	}
}
