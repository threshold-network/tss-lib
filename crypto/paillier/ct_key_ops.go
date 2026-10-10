// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Key precondition checks shared by the constant-time and variable-time
// Paillier arithmetic. The constant-time core (bigmod) rejects an even or
// degenerate modulus with a panic deep inside context construction; these
// checks surface a malformed caller-constructed key as an ordinary error
// before any constant-time context is built, in both operation modes.

package paillier

import (
	"errors"
	"math/big"
)

var (
	// ErrInvalidModulus is returned when the key modulus N is not a positive
	// odd integer greater than one. N odd and > 1 is required for N^2 to be
	// a usable (odd, > 1) constant-time bigmod modulus; it is also required
	// for the variable-time Paillier group structure to be well-defined.
	ErrInvalidModulus = errors.New("paillier: key modulus N must be odd and greater than one")

	// ErrMalformedKey is returned when the private key material is not a
	// usable decryption trapdoor: LambdaN is missing, non-positive, wider
	// than the modulus bit-bound the fixed-width constant-time exponent
	// encoding requires, or the decryption coefficient (LambdaN mod N) is
	// not invertible modulo N. The error carries no key values.
	ErrMalformedKey = errors.New("paillier: malformed private key material")
)

// checkPaillierModulus verifies that N is a positive odd integer greater
// than one. A nil N is rejected explicitly before any method call on it
// (unlike most big.Int methods, Sign dereferences the receiver and panics
// on nil).
func checkPaillierModulus(N *big.Int) error {
	if N == nil || N.Cmp(one) <= 0 || N.Bit(0) == 0 {
		return ErrInvalidModulus
	}
	return nil
}

// checkPaillierPrivateKey verifies the additional private-key preconditions
// decryption's constant-time context construction requires: a usable
// modulus (see checkPaillierModulus), plus a positive LambdaN that fits the
// modulus's bit-bound. LambdaN = lcm(p-1,q-1) < N always holds for a
// well-formed key, so LambdaN.BitLen() > N.BitLen() only rejects malformed
// key material (the legacy constant-time path would otherwise panic on the
// resulting exponent-padding overflow).
func checkPaillierPrivateKey(key *PrivateKey) error {
	if err := checkPaillierModulus(key.N); err != nil {
		return err
	}
	if key.LambdaN == nil || key.LambdaN.Sign() <= 0 {
		return ErrMalformedKey
	}
	if key.LambdaN.BitLen() > key.N.BitLen() {
		return ErrMalformedKey
	}
	return nil
}
