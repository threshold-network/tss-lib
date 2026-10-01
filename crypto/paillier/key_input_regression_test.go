// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// These regressions pin the malformed-key-input contract of the Paillier
// arithmetic entrypoints: a caller-constructed key with an unusable modulus
// (even, nil, or <= 1) or a malformed LambdaN must surface as an ordinary
// key-validation error in BOTH operation modes, instead of panicking inside
// the constant-time context construction (the original N=2 reproducer) or
// silently producing wrong plaintexts.

package paillier

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// evenModulusKey returns the exact caller-constructed shape that panicked in
// constant-time mode: PublicKey{N: 2} (even modulus) with a minimal private
// key built on it.
func evenModulusKey() (*PrivateKey, *PublicKey) {
	pk := &PublicKey{N: big.NewInt(2)}
	sk := &PrivateKey{PublicKey: *pk, LambdaN: big.NewInt(1)}
	return sk, pk
}

// TestEvenModulusKeyInputErrorsBothModes verifies that every public and
// private arithmetic entrypoint rejects the even modulus 2 with a key
// validation error in both constant-time and variable-time modes.
func TestEvenModulusKeyInputErrorsBothModes(t *testing.T) {
	for _, ct := range []bool{true, false} {
		setPaillierCTTestMode(t, ct)
		sk, pk := evenModulusKey()

		_, _, err := pk.EncryptAndReturnRandomness(big.NewInt(1))
		assert.ErrorIs(t, err, ErrInvalidModulus, "EncryptAndReturnRandomness, ct=%v", ct)
		_, err = pk.Encrypt(big.NewInt(1))
		assert.ErrorIs(t, err, ErrInvalidModulus, "Encrypt, ct=%v", ct)
		_, err = pk.HomoMult(big.NewInt(1), big.NewInt(1))
		assert.ErrorIs(t, err, ErrInvalidModulus, "HomoMult, ct=%v", ct)
		_, err = sk.Decrypt(big.NewInt(1))
		assert.ErrorIs(t, err, ErrInvalidModulus, "Decrypt, ct=%v", ct)
	}
}

// TestNilAndUnitModulusKeyInputErrorsBothModes covers the remaining
// unusable-modulus shapes: nil, zero, and unit N.
func TestNilAndUnitModulusKeyInputErrorsBothModes(t *testing.T) {
	badNs := []*big.Int{nil, big.NewInt(0), big.NewInt(1)}
	for _, ct := range []bool{true, false} {
		setPaillierCTTestMode(t, ct)
		for _, n := range badNs {
			pk := &PublicKey{N: n}
			sk := &PrivateKey{PublicKey: *pk, LambdaN: big.NewInt(1)}

			_, _, err := pk.EncryptAndReturnRandomness(big.NewInt(0))
			assert.ErrorIs(t, err, ErrInvalidModulus, "EncryptAndReturnRandomness, N=%v, ct=%v", n, ct)
			_, err = pk.Encrypt(big.NewInt(0))
			assert.ErrorIs(t, err, ErrInvalidModulus, "Encrypt, N=%v, ct=%v", n, ct)
			_, err = pk.HomoMult(big.NewInt(0), big.NewInt(0))
			assert.ErrorIs(t, err, ErrInvalidModulus, "HomoMult, N=%v, ct=%v", n, ct)
			_, err = sk.Decrypt(big.NewInt(0))
			assert.ErrorIs(t, err, ErrInvalidModulus, "Decrypt, N=%v, ct=%v", n, ct)
		}
	}
}

// TestMalformedLambdaNKeyInputErrorsBothModes verifies that malformed
// private-key material (missing, non-positive, non-invertible, or wider than
// the modulus bit-bound LambdaN) is rejected with the consistent malformed-
// key error in both modes. N=55 (=5*11) with LambdaN=55 yields
// L((N+1)^LambdaN mod N^2) == LambdaN mod N == 0, so the decryption
// coefficient has no inverse; LambdaN=128 does not fit the 6-bit bound of
// N=55 that the fixed-width exponent encoding requires.
func TestMalformedLambdaNKeyInputErrorsBothModes(t *testing.T) {
	badLambdas := []*big.Int{
		nil,
		big.NewInt(0),
		big.NewInt(-7),
		big.NewInt(55),  // non-invertible: coefficient numerator 55 mod 55 == 0
		big.NewInt(128), // wider than N.BitLen() == 6
	}
	for _, ct := range []bool{true, false} {
		setPaillierCTTestMode(t, ct)
		for _, lambda := range badLambdas {
			sk := &PrivateKey{PublicKey: PublicKey{N: big.NewInt(55)}, LambdaN: lambda, PhiN: big.NewInt(40)}
			_, err := sk.Decrypt(big.NewInt(1))
			assert.ErrorIs(t, err, ErrMalformedKey, "Decrypt, LambdaN=%v, ct=%v", lambda, ct)
		}
	}
}

// TestNonInvertibleKeyErrorConsistentAcrossModes verifies that a key whose
// decryption coefficient is not invertible returns the same error value on
// repeated use in both modes (no panic, no silent zero-plaintext).
func TestNonInvertibleKeyErrorConsistentAcrossModes(t *testing.T) {
	sk := &PrivateKey{PublicKey: PublicKey{N: big.NewInt(55)}, LambdaN: big.NewInt(55), PhiN: big.NewInt(40)}
	for _, ct := range []bool{true, false} {
		setPaillierCTTestMode(t, ct)
		for i := range 3 {
			_, err := sk.Decrypt(big.NewInt(1))
			assert.ErrorIs(t, err, ErrMalformedKey, "call %d, ct=%v", i, ct)
		}
	}
}

// TestValidSmallKeyRoundTripBothModes guards against over-rejection: for
// N=33 (=3*11), LambdaN=PhiN=(p-1)(q-1)=20 is a multiple of the Carmichael
// exponent lcm(2,10)=10, so it still annihilates the unit group mod N
// (x^20 = (x^10)^2 = 1), and gcd(20, 33) = 1 makes the decryption
// coefficient invertible. Both modes must still round-trip plaintexts
// through Encrypt, HomoMult, and Decrypt on this usable, non-minimal key.
func TestValidSmallKeyRoundTripBothModes(t *testing.T) {
	sk := &PrivateKey{PublicKey: PublicKey{N: big.NewInt(33)}, LambdaN: big.NewInt(20), PhiN: big.NewInt(20)}
	msg := big.NewInt(7)
	for _, ct := range []bool{true, false} {
		setPaillierCTTestMode(t, ct)

		c, err := sk.Encrypt(msg)
		require.NoError(t, err, "Encrypt, ct=%v", ct)
		dec, err := sk.Decrypt(c)
		require.NoError(t, err, "Decrypt, ct=%v", ct)
		assert.Equal(t, 0, msg.Cmp(dec), "round trip, ct=%v", ct)

		hc, err := sk.HomoMult(big.NewInt(4), c)
		require.NoError(t, err, "HomoMult, ct=%v", ct)
		hdec, err := sk.Decrypt(hc)
		require.NoError(t, err, "Decrypt after HomoMult, ct=%v", ct)
		assert.Equal(t, 0, new(big.Int).Mul(msg, big.NewInt(4)).Cmp(hdec), "homomorphic multiply, ct=%v", ct)
	}
}
