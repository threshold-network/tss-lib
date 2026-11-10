// Copyright © 2019-2024 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// This file holds the byte-oriented and canonical-operand entry points of
// CTModInt: exponentiations from caller-encoded fixed-width exponent bytes
// and fast paths for operands proven to lie in [0, modulus). They exist so
// a proof that pre-encodes its invariant secret exponents (e.g. the Paillier
// mod-proof context) can reuse one encoding across many iterations instead of
// re-encoding and re-wiping it on every call.

package common

import (
	"math/big"

	"filippo.io/bigmod"
)

// zeroBytes wipes a slice in place.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// expCTFromPaddedBase finishes a bigmod exponentiation from a base that is
// already a pooled bigmod operand, over fixed-width big-endian exponent
// bytes. The exponent slice is read-only; the work is fixed by the byte
// width (leading zeros included), not by the encoded value.
func (ct *CTModInt) expCTFromPaddedBase(baseNat *bigmod.Nat, exponent []byte) *big.Int {
	result := bigmod.NewNat()
	result.Exp(baseNat, exponent, ct.mod)
	return new(big.Int).SetBytes(result.Bytes(ct.mod))
}

// encodeCanonicalOperand encodes a canonical operand, 0 <= val < modulus,
// into a pooled zero-padded byte-width buffer of length ct.byteLen suitable
// for bigmod.Nat.SetBytes. The caller must pass the returned pointer to
// releasePadded (typically via defer) to return the same pooled buffer.
// The precondition is validated explicitly: an out-of-domain or negative
// operand panics rather than being truncated, reduced, or abs()'d. As in
// the reducing path, the operand encoding is not itself constant-time; the
// constant-time property holds in the bigmod core, consistent with the
// other CTModInt methods.
func (ct *CTModInt) encodeCanonicalOperand(val *big.Int) *[]byte {
	if val.Sign() < 0 || val.Cmp(ct.modBigInt) >= 0 {
		panic("CTModInt: canonical operand out of range [0, modulus)")
	}
	bufPtr := ct.bytePool.Get().(*[]byte)
	// The canonical precondition (val < modulus, modulus byte-width
	// ct.byteLen) guarantees val fits in exactly this buffer, so
	// FillBytes is a complete, allocation-free overwrite; releasePadded
	// still wipes the buffer on return.
	val.FillBytes(*bufPtr)
	return bufPtr
}

// ExpCTWithBytes performs constant-time modular exponentiation using
// bigmod, from an already encoded fixed-width big-endian exponent. The
// base keeps the generic reducing semantics of ExpCTWithBitLen: any
// integer is reduced modulo the modulus, so out-of-range and negative
// bases are accepted. The exponent bytes are read-only: this method does
// not retain, modify, or wipe them, so a shared encoding may be reused
// across any number of calls, and a secret encoding must be zeroed by
// its owner when no longer needed. An empty encoding is the zero
// exponent and returns 1. The exponent work is fixed by the byte width,
// including leading zeros. As with all CTModInt methods, only the bigmod
// core is constant-time: operand conversion, reduction, and surrounding
// math/big work remain variable-time.
func (ct *CTModInt) ExpCTWithBytes(base *big.Int, exponent []byte) *big.Int {
	paddedBase := ct.reduceToPaddedBytes(base)
	defer ct.releasePadded(paddedBase)

	baseNat := bigmod.NewNat()
	baseNat.SetBytes(*paddedBase, ct.mod)
	return ct.expCTFromPaddedBase(baseNat, exponent)
}

// ExpCTCanonicalWithBytes is ExpCTWithBytes with the canonical-operand
// precondition 0 <= base < modulus, enforced by an explicit panic instead
// of the generic reduction: the encoding skips the big.Int.Mod
// allocation/reduction entirely. All other semantics -- read-only
// caller-owned exponent bytes, fixed work by byte width, and the
// variable-time encoding caveat -- are the same as ExpCTWithBytes.
func (ct *CTModInt) ExpCTCanonicalWithBytes(base *big.Int, exponent []byte) *big.Int {
	paddedBase := ct.encodeCanonicalOperand(base)
	defer ct.releasePadded(paddedBase)

	baseNat := bigmod.NewNat()
	baseNat.SetBytes(*paddedBase, ct.mod)
	return ct.expCTFromPaddedBase(baseNat, exponent)
}

// ExpCTCanonicalWithBitLen performs constant-time modular exponentiation
// with the canonical-operand precondition 0 <= base < modulus, enforced
// by an explicit panic instead of the generic reduction. The exponent is
// encoded and padded exactly as in ExpCTWithBitLen (public bit bound,
// positive bitLen, nonnegative exp within the bound; violations panic
// without truncation or reduction); the temporary encoding owned by this
// method is wiped before it returns. This method therefore owns and
// wipes a fresh encoding, unlike the WithBytes forms which read
// caller-owned bytes. The arithmetic modulus must be odd.
func (ct *CTModInt) ExpCTCanonicalWithBitLen(base, exp *big.Int, bitLen int) *big.Int {
	expBytes := padExponent(exp, bitLen)
	defer zeroBytes(expBytes)

	paddedBase := ct.encodeCanonicalOperand(base)
	defer ct.releasePadded(paddedBase)

	baseNat := bigmod.NewNat()
	baseNat.SetBytes(*paddedBase, ct.mod)
	return ct.expCTFromPaddedBase(baseNat, expBytes)
}

// MulCTCanonical performs constant-time modular multiplication of two
// canonical operands, 0 <= x, y < modulus, enforced by an explicit panic
// instead of MulCT's generic reduction: no big.Int.Mod
// allocation/reduction is performed for either operand. The result is in
// [0, modulus), as with MulCT. The same variable-time encoding caveat as
// the other methods applies.
func (ct *CTModInt) MulCTCanonical(x, y *big.Int) *big.Int {
	paddedX := ct.encodeCanonicalOperand(x)
	paddedY := ct.encodeCanonicalOperand(y)
	defer ct.releasePadded(paddedX)
	defer ct.releasePadded(paddedY)

	xNat := bigmod.NewNat()
	yNat := bigmod.NewNat()
	xNat.SetBytes(*paddedX, ct.mod)
	yNat.SetBytes(*paddedY, ct.mod)
	xNat.Mul(yNat, ct.mod)

	return new(big.Int).SetBytes(xNat.Bytes(ct.mod))
}
