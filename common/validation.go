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
	// modulus this library's exported verifiers will accept. The wire path
	// pins a peer's modulus to exactly 2048 bits before any proof is
	// verified; below 2048 bits the secp256k1-scale challenge space (2^256)
	// no longer dominates the modulus, and no supported key can have a
	// narrower unknown-order modulus.
	MinUnknownOrderModulusBitLen = 2048

	// MaxUnknownOrderModulusBitLen is a resource ceiling on the width of an
	// unknown-order modulus the exported verifiers will accept. Everything a
	// verifier does with a caller-supplied modulus -- the ProbablyPrime call
	// below, any modular reduction, GCD, sampler and per-candidate
	// exponentiation -- is O(bitLen), so without a ceiling a direct API call
	// allocates and hashes proportional to a caller-controlled width. This
	// ceiling is 32x the 2048-bit wire-pinned width, so it excludes nothing
	// this library's wire path can produce; it only bounds work an
	// untrusted caller can force through an exported verify entry point.
	MaxUnknownOrderModulusBitLen = 65536
)

// ExceedsUnknownOrderModulusCeiling reports whether N is wider than
// MaxUnknownOrderModulusBitLen. It is a standalone O(bitLen) predicate (no
// primality work, no modulus-sized allocation) so exported unknown-order
// verifiers can reject oversized caller-supplied moduli before
// IsUsableUnknownOrderModulus's ProbablyPrime call or any other
// modulus-sized work runs against them.
func ExceedsUnknownOrderModulusCeiling(N *big.Int) bool {
	return N != nil && N.BitLen() > MaxUnknownOrderModulusBitLen
}

func IsUsableUnknownOrderModulus(N *big.Int, minBitLen int) bool {
	return N != nil &&
		N.Sign() == 1 &&
		N.Bit(0) == 1 &&
		N.BitLen() >= minBitLen &&
		!N.ProbablyPrime(primalityRounds)
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
