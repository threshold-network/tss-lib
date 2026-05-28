// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"math/big"
)

// LiterallyJustMod implements the logic for converting a
// SHA512/256 hash to a value between 0-q by taking the number modulo q.
// XXX: this is only safe if used with values of q that are extremely close
// to a power of 2. The order of secp256k1 happens to be one of those values,
// and the bias introduced by the modulus is around 1.27*2^-128.
// The same applies to the order of curve25519.
func LiterallyJustMod(q *big.Int, eHash *big.Int) *big.Int { // e' = eHash
	e := eHash.Mod(eHash, q)
	return e
}

// RejectionSample reduces `eHash` modulo q. The name preserves the upstream
// challenge-derivation function name; this is NOT true rejection sampling
// (no loop with fresh hash material until a candidate falls in [0, q)).
//
// Safe only when q is close to 2^k from below, where k is the hash output
// width in bits (k = 256 for SHA512_256). For secp256k1 the bias is ≈ 2^-128
// — negligible for Fiat-Shamir challenges.
//
// For q that is NOT close to a power of 2, or for moduli larger than 2^k
// (e.g. Paillier N ≈ 2^2048), use HashToN / HashToNTagged: those absorb
// ≥ k + 256 bits of entropy before reduction and bound bias at ≤ 2^-256
// regardless of q. For applications requiring an unbiased uniform sample
// over [0, q), implement true rejection sampling at the call site.
func ModReduceHash(q *big.Int, eHash *big.Int) *big.Int {
	return LiterallyJustMod(q, eHash)
}

// RejectionSample is kept for compatibility with older callers.
//
// Deprecated: use ModReduceHash. This function is modular reduction, not true
// rejection sampling.
func RejectionSample(q *big.Int, eHash *big.Int) *big.Int {
	return ModReduceHash(q, eHash)
}

// Return a big.Int between 0 and N
func HashToN(N *big.Int, in ...*big.Int) *big.Int {
	bitCnt := N.BitLen()
	// Add 256 bits to remove bias from LiterallyJustMod,
	// and another 256 bits to compensate for any remainder from the division.
	blockCnt := (bitCnt / 256) + 2

	dest := big.NewInt(0)
	tmp := make([]*big.Int, 1, 1+len(in))
	tmp = append(tmp, in...)

	for i := 0; i < blockCnt; i++ {
		// dest = h(0, in) | h(1, in) | h(2, in) | ...
		tmp[0] = big.NewInt(int64(i))
		dest.Lsh(dest, 256)
		dest.Or(dest, SHA512_256i(tmp...))
	}

	// dest has at least N.BitLen + 256 bits,
	// thus it is safe to use Mod
	return LiterallyJustMod(N, dest)
}

// HashToNTagged is the tagged-hash analogue of HashToN. It produces a value in
// [0, N) by concatenating ((N.BitLen()/256) + 2) blocks of SHA512_256i_TAGGED
// — one per block-index counter — and reducing modulo N. The total entropy
// before reduction is at least N.BitLen() + 256 bits, so the modular reduction
// has the same bias budget as HashToN (≤ 2^-256).
//
// Use this for Fiat-Shamir challenges over large moduli (e.g. Paillier N ≈ 2^2048)
// when the derivation must be domain-separated by a session tag. Reducing a
// single 256-bit SHA512_256i_TAGGED output modulo N would emit challenges in
// [0, 2^256) instead of [0, N).
func HashToNTagged(tag []byte, N *big.Int, in ...*big.Int) *big.Int {
	bitCnt := N.BitLen()
	blockCnt := (bitCnt / 256) + 2

	dest := big.NewInt(0)
	tmp := make([]*big.Int, 1, 1+len(in))
	tmp = append(tmp, in...)

	for i := 0; i < blockCnt; i++ {
		tmp[0] = big.NewInt(int64(i))
		dest.Lsh(dest, 256)
		dest.Or(dest, SHA512_256i_TAGGED(tag, tmp...))
	}

	return LiterallyJustMod(N, dest)
}
