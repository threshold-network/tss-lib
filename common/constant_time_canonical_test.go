// Copyright © 2019-2024 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math/big"
	"sync"
	"testing"
)

// assertPanics runs fn and fails the test if it returns without panicking.
func assertPanics(t *testing.T, fn func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic, but the call returned normally")
		}
	}()
	fn()
}

// TestExpCTWithBytesMatchesExpCTWithBitLen pins that feeding an
// already-encoded fixed-width exponent to ExpCTWithBytes yields results
// identical to encoding per call via ExpCTWithBitLen and to math/big,
// for bases inside and outside the canonical domain. The out-of-domain
// bases confirm the reducing-base semantics are retained.
func TestExpCTWithBytesMatchesExpCTWithBitLen(t *testing.T) {
	p, _ := rand.Prime(rand.Reader, 512)
	q, _ := rand.Prime(rand.Reader, 512)
	N := new(big.Int).Mul(p, q)
	ct := NewCTModInt(N)
	byteLen := (N.BitLen() + 7) / 8

	exp, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 256))
	expBytes := exp.FillBytes(make([]byte, byteLen))

	for _, base := range []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		new(big.Int).Sub(N, big.NewInt(1)), // N-1: the canonical maximum
		N,                                  // == modulus: reduced to 0
		new(big.Int).Neg(N),                // negative: reduced
	} {
		want := new(big.Int).Exp(new(big.Int).Set(base), new(big.Int).Set(exp), N)
		gotBitLen := ct.ExpCTWithBitLen(new(big.Int).Set(base), new(big.Int).Set(exp), byteLen*8)
		gotBytes := ct.ExpCTWithBytes(new(big.Int).Set(base), expBytes)
		if gotBitLen.Cmp(want) != 0 {
			t.Errorf("ExpCTWithBitLen(base=%v, exp) = %v, want %v", base, gotBitLen, want)
		}
		if gotBytes.Cmp(want) != 0 {
			t.Errorf("ExpCTWithBytes(base=%v, encodedExp) = %v, want %v", base, gotBytes, want)
		}
	}
}

// TestExpCTWithBytesExponentReuse pins the caller-owned exponent
// contract: the same fixed-width bytes may feed any number of
// exponentiations on one context, every result must equal the math/big
// reference, and the helper must leave the caller's bytes untouched.
func TestExpCTWithBytesExponentReuse(t *testing.T) {
	p, _ := rand.Prime(rand.Reader, 512)
	ct := NewCTModInt(p)
	byteLen := (p.BitLen() + 7) / 8

	exp, _ := rand.Int(rand.Reader, p)
	enc := exp.FillBytes(make([]byte, byteLen))
	encCopy := append([]byte(nil), enc...)

	for i := range 3 {
		base, _ := rand.Int(rand.Reader, p)
		want := new(big.Int).Exp(new(big.Int).Set(base), new(big.Int).Set(exp), p)
		if got := ct.ExpCTWithBytes(base, enc); got.Cmp(want) != 0 {
			t.Fatalf("reuse %d: ExpCTWithBytes = %v, want %v", i, got, want)
		}
	}
	if !bytes.Equal(enc, encCopy) {
		t.Fatal("ExpCTWithBytes modified the caller-owned exponent bytes")
	}
}

// TestExpCTCanonicalWithBytesMatchesReference pins the canonical-base
// fast path against the math/big reference at the domain boundaries
// (0, 1, modulus-1) and across the zero and positive exponents.
func TestExpCTCanonicalWithBytesMatchesReference(t *testing.T) {
	modulus := big.NewInt(257)
	ct := NewCTModInt(modulus)

	for _, base := range []int64{0, 1, 256} {
		for _, exp := range []int64{0, 1, 7} {
			expBytes := big.NewInt(exp).FillBytes(make([]byte, 2))
			want := new(big.Int).Exp(big.NewInt(base), big.NewInt(exp), modulus)
			if got := ct.ExpCTCanonicalWithBytes(big.NewInt(base), expBytes); got.Cmp(want) != 0 {
				t.Errorf("ExpCTCanonicalWithBytes(%d, %d) = %v, want %v", base, exp, got, want)
			}
		}
	}
}

// TestExpCTCanonicalWithBytesRejectsNonCanonicalBase pins that a
// programmer-domain violation of the canonical precondition panics
// explicitly instead of truncating, taking the absolute value, or
// silently reducing: base == modulus+1 would differ from base ==
// modulus-1 only by sign, and abs(-1) would silently "work" as 1.
func TestExpCTCanonicalWithBytesRejectsNonCanonicalBase(t *testing.T) {
	modulus := big.NewInt(257)
	ct := NewCTModInt(modulus)
	expBytes := big.NewInt(3).FillBytes(make([]byte, 2))

	assertPanics(t, func() { ct.ExpCTCanonicalWithBytes(modulus, expBytes) })
	assertPanics(t, func() { ct.ExpCTCanonicalWithBytes(big.NewInt(258), expBytes) })
	assertPanics(t, func() { ct.ExpCTCanonicalWithBytes(big.NewInt(-1), expBytes) })
}

// TestExpCTCanonicalWithBitLenMatchesExpCTWithBitLen pins that the
// canonical bit-length form agrees with the reducing form and with
// math/big on a canonical base, at the full public bit bound of the
// modulus.
func TestExpCTCanonicalWithBitLenMatchesExpCTWithBitLen(t *testing.T) {
	p, _ := rand.Prime(rand.Reader, 512)
	ct := NewCTModInt(p)

	base, _ := rand.Int(rand.Reader, p)
	exp, _ := rand.Int(rand.Reader, p) // full width: bounded by p.BitLen()

	want := new(big.Int).Exp(new(big.Int).Set(base), new(big.Int).Set(exp), p)
	gotStd := ct.ExpCTWithBitLen(new(big.Int).Set(base), new(big.Int).Set(exp), p.BitLen())
	gotCanon := ct.ExpCTCanonicalWithBitLen(new(big.Int).Set(base), new(big.Int).Set(exp), p.BitLen())
	if gotStd.Cmp(want) != 0 || gotCanon.Cmp(want) != 0 {
		t.Errorf("reducing/standard/canonical disagree: std=%v canon=%v want=%v", gotStd, gotCanon, want)
	}
}

// TestExpCTCanonicalWithBitLenRejectsNonCanonicalBase pins the same
// explicit-panic contract for the bit-length form, alongside the
// exponent-bound panics the form must retain from ExpCTWithBitLen.
func TestExpCTCanonicalWithBitLenRejectsNonCanonicalBase(t *testing.T) {
	modulus := big.NewInt(257)
	ct := NewCTModInt(modulus)

	assertPanics(t, func() { ct.ExpCTCanonicalWithBitLen(modulus, big.NewInt(3), 16) })
	assertPanics(t, func() { ct.ExpCTCanonicalWithBitLen(big.NewInt(-1), big.NewInt(3), 16) })
	assertPanics(t, func() { ct.ExpCTCanonicalWithBitLen(big.NewInt(1), big.NewInt(-1), 16) })
	assertPanics(t, func() {
		// exponent wider than the public bit bound
		ct.ExpCTCanonicalWithBitLen(big.NewInt(1), new(big.Int).Lsh(big.NewInt(1), 16), 16)
	})
}

// TestMulCTCanonicalMatchesReference pins the canonical-multiplication
// fast path against the math/big reference at the domain boundaries.
func TestMulCTCanonicalMatchesReference(t *testing.T) {
	modulus := big.NewInt(257)
	ct := NewCTModInt(modulus)

	for _, pair := range [][2]int64{{0, 256}, {1, 256}, {256, 256}, {123, 123}} {
		want := new(big.Int).Mul(big.NewInt(pair[0]), big.NewInt(pair[1]))
		want.Mod(want, modulus)
		if got := ct.MulCTCanonical(big.NewInt(pair[0]), big.NewInt(pair[1])); got.Cmp(want) != 0 {
			t.Errorf("MulCTCanonical(%d, %d) = %v, want %v", pair[0], pair[1], got, want)
		}
	}
}

// TestMulCTCanonicalRejectsNonCanonicalOperands pins that a violation
// of either operand's precondition panics explicitly instead of
// silently reducing like MulCT.
func TestMulCTCanonicalRejectsNonCanonicalOperands(t *testing.T) {
	modulus := big.NewInt(257)
	ct := NewCTModInt(modulus)

	assertPanics(t, func() { ct.MulCTCanonical(modulus, big.NewInt(1)) })
	assertPanics(t, func() { ct.MulCTCanonical(big.NewInt(1), big.NewInt(258)) })
	assertPanics(t, func() { ct.MulCTCanonical(big.NewInt(-1), big.NewInt(1)) })
}

// TestCTCanonicalHelpersConcurrentUse pins that one context's pooled
// buffers are safe for concurrent reuse: many goroutines exponentiating
// (with one shared fixed-width exponent encoding reused across all
// calls) and multiplying on the same *CTModInt must each produce the
// math/big reference. A state or pool shared across calls would
// surface here as a wrong result.
func TestCTCanonicalHelpersConcurrentUse(t *testing.T) {
	p, _ := rand.Prime(rand.Reader, 512)
	ct := NewCTModInt(p)
	byteLen := (p.BitLen() + 7) / 8

	exp, _ := rand.Int(rand.Reader, p)
	expBytes := exp.FillBytes(make([]byte, byteLen))

	const workers = 16
	const iters = 50
	var wg sync.WaitGroup
	failures := make(chan error, workers)
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iters {
				base, _ := rand.Int(rand.Reader, p)
				want := new(big.Int).Exp(new(big.Int).Set(base), new(big.Int).Set(exp), p)
				if got := ct.ExpCTCanonicalWithBytes(base, expBytes); got.Cmp(want) != 0 {
					failures <- fmt.Errorf("worker exponentiation: got %v, want %v", got, want)
					return
				}
				a, _ := rand.Int(rand.Reader, p)
				b, _ := rand.Int(rand.Reader, p)
				wantMul := new(big.Int).Mul(a, b)
				wantMul.Mod(wantMul, p)
				if got := ct.MulCTCanonical(a, b); got.Cmp(wantMul) != 0 {
					failures <- fmt.Errorf("worker multiplication: got %v, want %v", got, wantMul)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}
