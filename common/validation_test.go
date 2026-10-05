// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common_test

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnb-chain/tss-lib/common"
)

// oddCompositeAtBits builds an odd composite with exactly `bits` bits
// (bits >= 4): 3 * 2^(bits-2) + 3 is odd and divisible by 3, sits above
// 2^(bits-1), and stays below 2^bits, so it is a deterministic odd
// composite of the requested width.
func oddCompositeAtBits(bits int) *big.Int {
	n := new(big.Int).Lsh(big.NewInt(3), uint(bits-2))
	n.Add(n, big.NewInt(3))
	return n
}

// oddPrime2048 returns a 2048-bit prime from crypto/rand with a bounded
// retry, so the suite never spins on a bad entropy draw.
func oddPrime2048(t *testing.T) *big.Int {
	t.Helper()
	for range 25 {
		if p, err := rand.Prime(rand.Reader, 2048); err == nil {
			return p
		}
	}
	t.Fatal("crypto/rand failed to generate a 2048-bit prime")
	return nil
}

func TestIsUsableUnknownOrderModulus(t *testing.T) {
	// A 2048-bit prime passes the width and parity checks but fails the
	// primality test: a known-order modulus is not an unknown-order one.
	// The usable case is the deterministic odd composite at exactly the
	// floor width.
	cases := []struct {
		name string
		N    *big.Int
		want bool
	}{
		{"nil", nil, false},
		{"negative", big.NewInt(-2049), false},
		{"zero", big.NewInt(0), false},
		{"one", big.NewInt(1), false},
		{"small_odd", big.NewInt(2049), false},
		{"even_at_floor_width", new(big.Int).Lsh(big.NewInt(1), common.MinUnknownOrderModulusBitLen-1), false},
		{"odd_composite_below_floor", oddCompositeAtBits(common.MinUnknownOrderModulusBitLen - 1), false},
		{"odd_composite_at_floor", oddCompositeAtBits(common.MinUnknownOrderModulusBitLen), true},
		{"odd_composite_inside_ceiling", oddCompositeAtBits(2060), true},
		{"odd_composite_past_ceiling", oddCompositeAtBits(common.MaxUnknownOrderModulusBitLen + 1), false},
		{"prime_at_floor", oddPrime2048(t), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := common.IsUsableUnknownOrderModulus(tc.N, common.MinUnknownOrderModulusBitLen)
			require.Equal(t, tc.want, got, "IsUsableUnknownOrderModulus")
		})
	}
}

// TestIsUsableUnknownOrderModulusCeilingFirst pins the width-first behavior:
// a modulus wider than the ceiling is rejected by IsUsableUnknownOrderModulus
// on width alone, before any 65537-bit primality work; the same construction
// at exactly the ceiling does not trip the width check.
func TestIsUsableUnknownOrderModulusCeilingFirst(t *testing.T) {
	wide := oddCompositeAtBits(common.MaxUnknownOrderModulusBitLen + 1)
	require.Equal(t, common.MaxUnknownOrderModulusBitLen+1, wide.BitLen())
	require.Equal(t, uint(1), wide.Bit(0))
	require.True(t, common.ExceedsUnknownOrderModulusCeiling(wide))
	// Without the width check this composite would be reported usable; the
	// width rejection is the whole point.
	require.False(t, common.IsUsableUnknownOrderModulus(wide, common.MinUnknownOrderModulusBitLen),
		"65537-bit odd composite must be rejected by the width check")

	atCeiling := oddCompositeAtBits(common.MaxUnknownOrderModulusBitLen)
	require.Equal(t, common.MaxUnknownOrderModulusBitLen, atCeiling.BitLen())
	require.False(t, common.ExceedsUnknownOrderModulusCeiling(atCeiling),
		"a modulus at exactly the ceiling must not exceed it")
	// The width check is inclusive: the 65536-bit composite still passes
	// width and is accepted on its (composite) order.
	require.True(t, common.IsUsableUnknownOrderModulus(atCeiling, common.MinUnknownOrderModulusBitLen),
		"65536-bit odd composite must stay usable")
}

func TestExceedsUnknownOrderModulusCeiling(t *testing.T) {
	max := common.MaxUnknownOrderModulusBitLen
	cases := []struct {
		name string
		N    *big.Int
		want bool
	}{
		{"nil", nil, false},
		{"small_odd", big.NewInt(1025), false},
		{"odd_one_below_ceiling", oddCompositeAtBits(max - 1), false},
		{"odd_at_ceiling", oddCompositeAtBits(max), false},
		{"odd_one_past_ceiling", oddCompositeAtBits(max + 1), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, common.ExceedsUnknownOrderModulusCeiling(tc.N),
				"ExceedsUnknownOrderModulusCeiling")
		})
	}
}

func TestIsCanonicalGenerator(t *testing.T) {
	// Deterministic 2048-bit odd composite modulus: 3 * 2^2046 + 3.
	n := oddCompositeAtBits(common.MinUnknownOrderModulusBitLen)
	require.Equal(t, common.MinUnknownOrderModulusBitLen, n.BitLen())
	require.Equal(t, uint(1), n.Bit(0))

	// 2^1024 is in (1, n) and coprime to the odd modulus n, so it must be
	// accepted as a canonical generator. 3 divides n, so it must not be.
	vValid := new(big.Int).Lsh(big.NewInt(1), 1024)

	cases := []struct {
		name string
		N    *big.Int
		v    *big.Int
		want bool
	}{
		{"nil_N", nil, big.NewInt(5), false},
		{"zero_v", n, big.NewInt(0), false},
		{"one_v", n, big.NewInt(1), false},
		{"v_at_modulus", n, new(big.Int).Set(n), false},
		{"v_above_modulus", n, new(big.Int).Add(n, big.NewInt(1)), false},
		{"negative_v", n, big.NewInt(-5), false},
		{"shares_factor_v", n, big.NewInt(3), false},
		{"valid_generator", n, vValid, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, common.IsCanonicalGenerator(tc.N, tc.v),
				"IsCanonicalGenerator")
		})
	}
}

func TestIsCanonicalPaillierCiphertext(t *testing.T) {
	// Deterministic 2048-bit odd composite modulus; N^2 bounds the range.
	n := oddCompositeAtBits(common.MinUnknownOrderModulusBitLen)
	require.Equal(t, common.MinUnknownOrderModulusBitLen, n.BitLen())
	nSquared := new(big.Int).Mul(n, n)

	// 2^1024 is in (0, N^2) and coprime to the odd modulus n, so it is a
	// canonical ciphertext. 3 divides n, so a ciphertext of 3 is not.
	cValid := new(big.Int).Lsh(big.NewInt(1), 1024)

	cases := []struct {
		name string
		c    *big.Int
		N    *big.Int
		want bool
	}{
		{"nil_c", nil, n, false},
		{"nil_N", cValid, nil, false},
		{"negative_c", big.NewInt(-4097), n, false},
		{"zero_c", big.NewInt(0), n, false},
		{"one_c", big.NewInt(1), n, true},
		{"in_range_coprime", cValid, n, true},
		{"shares_factor", big.NewInt(3), n, false},
		{"at_nsquared", nSquared, n, false},
		{"above_nsquared", new(big.Int).Add(nSquared, big.NewInt(1)), n, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, common.IsCanonicalPaillierCiphertext(tc.c, tc.N),
				"IsCanonicalPaillierCiphertext")
		})
	}
}
