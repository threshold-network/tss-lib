// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import "math/big"

const (
	primalityRounds = 30
	// MinUnknownOrderModulusBitLen is the width floor of every unknown-order
	// modulus this library's exported verifiers will accept. 2048 bits is
	// the width the wire path pins and the smallest unknown-order modulus
	// this protocol supports.
	MinUnknownOrderModulusBitLen = 2048

	// MaxUnknownOrderModulusBitLen is a resource ceiling on the width of an
	// unknown-order modulus the exported verifiers will accept. Verifier CPU
	// cost with a caller-supplied modulus grows with width -- at least
	// linearly for the width and modexp-style work, superlinearly for the
	// ProbablyPrime call below and for GCD -- so this ceiling caps the
	// worst-case work an untrusted caller can force through an exported
	// verify entry point; it bounds memory and worst-case cost, it does not
	// make that cost linear. The ceiling is 32x the 2048-bit wire-pinned
	// width, so it excludes nothing this library's wire path can produce.
	MaxUnknownOrderModulusBitLen = 65536
)

// ExceedsUnknownOrderModulusCeiling reports whether N is wider than
// MaxUnknownOrderModulusBitLen. It is a constant-time width check (no
// primality work, no modulus-sized allocation) that exported unknown-order
// verifiers use to reject oversized caller-supplied moduli before
// IsUsableUnknownOrderModulus's ProbablyPrime call or any other
// modulus-sized work runs against them.
func ExceedsUnknownOrderModulusCeiling(N *big.Int) bool {
	return N != nil && N.BitLen() > MaxUnknownOrderModulusBitLen
}

// IsUsableUnknownOrderModulus reports whether N is an acceptable
// unknown-order modulus for the exported verifiers: positive, odd, at least
// minBitLen bits, not wider than MaxUnknownOrderModulusBitLen, and composite
// (it fails the probabilistic primality test). The width checks run before
// the ProbablyPrime call so
// oversized inputs are rejected with no modulus-sized work.
func IsUsableUnknownOrderModulus(N *big.Int, minBitLen int) bool {
	if N == nil || N.Sign() != 1 || N.Bit(0) != 1 {
		return false
	}
	if ExceedsUnknownOrderModulusCeiling(N) || N.BitLen() < minBitLen {
		return false
	}
	return !N.ProbablyPrime(primalityRounds)
}

func IsCanonicalGenerator(N, v *big.Int) bool {
	return N != nil &&
		N.Sign() == 1 &&
		v != nil &&
		v.Cmp(one) > 0 &&
		v.Cmp(N) < 0 &&
		IsNumberInMultiplicativeGroup(N, v)
}

func IsCanonicalPaillierCiphertext(c, N *big.Int) bool {
	if c == nil || N == nil || N.Sign() != 1 {
		return false
	}
	NSquared := new(big.Int).Mul(N, N)
	return c.Sign() > 0 &&
		c.Cmp(NSquared) < 0 &&
		new(big.Int).GCD(nil, nil, c, N).Cmp(one) == 0
}
