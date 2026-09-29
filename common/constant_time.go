// Copyright © 2019-2024 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Package common provides constant-time big integer helpers for cryptographic use.
//
// SECURITY NOTE: Go's math/big package is NOT constant-time and should not be used
// with secret values. This module provides constant-time helpers for the
// secret-exponent operations enumerated below, using filippo.io/bigmod (the same
// constant-time core used by Go's crypto/rsa).
//
// COVERAGE: When enabled via EnableConstantTimeOps, the constant-time path is applied
// to modular exponentiations whose EXPONENT is a long-term secret, witness, trapdoor,
// or secret plaintext/scalar: Paillier Decrypt / Encrypt (gamma^m) / HomoMult, the
// Paillier mod- and factor-proofs, the DLN proof, the ring-Pedersen trapdoor setup in
// keygen, and the MtA range and regular proofs.
//
// Deliberately NOT hardened (left on math/big), and the reasons:
//   - Public-exponent operations, where the timing reveals only public data: x^N in
//     Encrypt, r^e, and every verifier-side exponentiation (challenges and proof
//     responses are public).
//   - One-time random per-proof blinds (e.g. h2^rho, h1^alpha in the MtA proofs). These
//     are the same class as the secrets but are fresh, single-use auxiliary randomness;
//     leaving them on math/big is a pragmatic deferral, NOT a safety guarantee.
//   - Exponentiations modulo an even value (e.g. inverses mod phi(N)): bigmod requires
//     an odd modulus, so these stay on math/big.
//
// Reference: https://github.com/golang/go/issues/20654

package common

import (
	"math/big"
	"sync"
	"sync/atomic"

	"filippo.io/bigmod"
)

// constantTimeEnabled controls whether constant-time operations are used.
// Default is false (disabled) for performance. Enable for high-security environments.
var constantTimeEnabled int32 = 0

// EnableConstantTimeOps enables constant-time cryptographic operations.
// Call this at application startup if timing side-channel protection is required.
func EnableConstantTimeOps() {
	atomic.StoreInt32(&constantTimeEnabled, 1)
}

// DisableConstantTimeOps disables constant-time operations (default).
func DisableConstantTimeOps() {
	atomic.StoreInt32(&constantTimeEnabled, 0)
}

// IsConstantTimeEnabled returns true if constant-time operations are enabled.
func IsConstantTimeEnabled() bool {
	return atomic.LoadInt32(&constantTimeEnabled) == 1
}

// CTModInt provides constant-time modular arithmetic backed by filippo.io/bigmod
// (the same constant-time core used by Go's crypto/rsa and crypto/ecdsa).
type CTModInt struct {
	mod        *bigmod.Modulus
	modBigInt  *big.Int
	inverseExp []byte // Exponent for modular inverse: p-2 (prime) or phi(n)-1 (composite)
	byteLen    int
	bytePool   sync.Pool
}

// leftPad returns b left-padded with zero bytes to width; if b is already at least
// width bytes it is returned unchanged. Padding a secret exponent to a fixed width
// keeps bigmod.Nat.Exp's running time independent of the exponent's magnitude (its
// work is proportional to len(e)); leading zero bytes are no-op squarings and do not
// change the result.
func leftPad(b []byte, width int) []byte {
	if len(b) >= width {
		return b
	}
	padded := make([]byte, width)
	copy(padded[width-len(b):], b)
	return padded
}

// NewCTModInt creates a constant-time modular context using bigmod.
// The modulus must be odd (a requirement of bigmod's Exp); this is asserted here so
// the failure surfaces at construction rather than at the first ExpCT call.
func NewCTModInt(mod *big.Int) *CTModInt {
	if mod.Bit(0) == 0 {
		panic("NewCTModInt: modulus must be odd")
	}
	modBytes := mod.Bytes()
	m, err := bigmod.NewModulus(modBytes)
	if err != nil {
		// Fallback: should not happen for valid modulus
		panic(err)
	}

	// Pre-compute mod-2 for Fermat inverse: a^(-1) = a^(mod-2) mod mod
	modMinusTwo := new(big.Int).Sub(mod, big.NewInt(2))

	byteLen := len(modBytes)
	return &CTModInt{
		mod:        m,
		modBigInt:  new(big.Int).Set(mod),
		inverseExp: leftPad(modMinusTwo.Bytes(), byteLen),
		byteLen:    byteLen,
		bytePool: sync.Pool{
			New: func() interface{} {
				return make([]byte, byteLen)
			},
		},
	}
}

// reduceToPaddedBytes reduces val into [0, modulus) and returns a zero-padded
// big-endian byte slice of length ct.byteLen suitable for bigmod.Nat.SetBytes.
// NOTE: big.Int.Mod is not constant-time, but it is applied unconditionally (no
// secret-dependent branch) and the bases reduced here are public or already in range
// at every call site. A caller passing a secret base near the modulus should be aware
// the reduction's timing depends on the value.
func (ct *CTModInt) reduceToPaddedBytes(val *big.Int) []byte {
	reduced := new(big.Int).Mod(val, ct.modBigInt)

	buf := ct.bytePool.Get().([]byte)
	for i := range buf {
		buf[i] = 0
	}
	b := reduced.Bytes()
	copy(buf[ct.byteLen-len(b):], b)
	return buf
}

// ExpCT performs constant-time modular exponentiation using bigmod.
// IMPORTANT: The modulus must be odd. Negative exponents are not supported and will panic.
func (ct *CTModInt) ExpCT(base, exp *big.Int) *big.Int {
	if exp.Sign() == 0 {
		return big.NewInt(1)
	}
	if exp.Sign() < 0 {
		panic("ExpCT: negative exponents are not supported; use ModInverseCT explicitly")
	}

	paddedBase := ct.reduceToPaddedBytes(base)
	defer func() {
		for i := range paddedBase {
			paddedBase[i] = 0
		}
		ct.bytePool.Put(paddedBase)
	}()

	baseNat := bigmod.NewNat()
	baseNat.SetBytes(paddedBase, ct.mod)

	// Pad the exponent to a fixed width so the exponentiation's running time does not
	// leak the secret exponent's magnitude (see leftPad).
	expBytes := leftPad(exp.Bytes(), ct.byteLen)
	defer func() {
		for i := range expBytes {
			expBytes[i] = 0
		}
	}()
	result := bigmod.NewNat()
	result.Exp(baseNat, expBytes, ct.mod)

	return new(big.Int).SetBytes(result.Bytes(ct.mod))
}

// ModInverseCT computes the modular inverse in constant time using Fermat's little theorem.
// For a prime modulus p: a^(-1) = a^(p-2) mod p
// For a non-prime modulus n with known phi(n): a^(-1) = a^(phi(n)-1) mod n
// SECURITY: This uses constant-time Exp, making the entire operation constant-time.
// Note: The modulus should be prime for this to work correctly. For composite moduli,
// use NewCTModIntWithPhi to provide phi(n).
func (ct *CTModInt) ModInverseCT(a *big.Int) *big.Int {
	if a.Sign() == 0 {
		return nil
	}

	paddedA := ct.reduceToPaddedBytes(a)
	defer func() {
		for i := range paddedA {
			paddedA[i] = 0
		}
		ct.bytePool.Put(paddedA)
	}()

	aNat := bigmod.NewNat()
	aNat.SetBytes(paddedA, ct.mod)

	result := bigmod.NewNat()
	result.Exp(aNat, ct.inverseExp, ct.mod)
	inv := new(big.Int).SetBytes(result.Bytes(ct.mod))

	// The Fermat/Euler inverse a^(mod-2) (or a^(phi-1)) is only the true inverse when
	// gcd(a, mod) == 1; for non-coprime a it returns a well-defined but WRONG value
	// rather than failing. Verify a*inv == 1 and return nil otherwise, so this matches
	// math/big.ModInverse's nil-on-no-inverse contract and both code paths agree.
	if ct.MulCT(a, inv).Cmp(big.NewInt(1)) != 0 {
		return nil
	}
	return inv
}

// MulCT performs constant-time modular multiplication using bigmod.
func (ct *CTModInt) MulCT(x, y *big.Int) *big.Int {
	paddedX := ct.reduceToPaddedBytes(x)
	paddedY := ct.reduceToPaddedBytes(y)
	defer func() {
		for i := range paddedX {
			paddedX[i] = 0
		}
		ct.bytePool.Put(paddedX)
	}()
	defer func() {
		for i := range paddedY {
			paddedY[i] = 0
		}
		ct.bytePool.Put(paddedY)
	}()

	xNat := bigmod.NewNat()
	yNat := bigmod.NewNat()
	xNat.SetBytes(paddedX, ct.mod)
	yNat.SetBytes(paddedY, ct.mod)

	xNat.Mul(yNat, ct.mod)

	return new(big.Int).SetBytes(xNat.Bytes(ct.mod))
}

// NewCTModIntWithPhi creates a constant-time modular context for composite moduli.
// This is required for correct ModInverse on composite moduli where phi(n) is known.
// For RSA-like moduli n = p*q, pass phiN = (p-1)*(q-1).
func NewCTModIntWithPhi(mod, phiN *big.Int) *CTModInt {
	if mod.Bit(0) == 0 {
		panic("NewCTModIntWithPhi: modulus must be odd")
	}
	modBytes := mod.Bytes()
	m, err := bigmod.NewModulus(modBytes)
	if err != nil {
		panic(err)
	}

	// For composite modulus: a^(-1) = a^(phi(n)-1) mod n
	phiMinusOne := new(big.Int).Sub(phiN, big.NewInt(1))

	byteLen := len(modBytes)
	return &CTModInt{
		mod:        m,
		modBigInt:  new(big.Int).Set(mod),
		inverseExp: leftPad(phiMinusOne.Bytes(), byteLen), // Use phi(n)-1 instead of n-2
		byteLen:    byteLen,
		bytePool: sync.Pool{
			New: func() interface{} {
				return make([]byte, byteLen)
			},
		},
	}
}
