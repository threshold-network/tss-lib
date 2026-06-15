// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import "math/big"

const primalityRounds = 30

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
