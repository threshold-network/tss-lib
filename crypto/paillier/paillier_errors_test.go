// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// These regressions pin the range and malformed-ciphertext guards of the
// Paillier arithmetic entrypoints: out-of-domain inputs must surface as
// ordinary errors (ErrMessageTooLong / ErrMessageMalFormed) instead of
// panicking inside the constant-time exponentiation, in both operation
// modes. In-domain boundary inputs must keep working, so the guards are
// pinned against silent over-rejection as well.

package paillier

import (
	"errors"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// modeName labels an operation-mode flag in subtest names.
func modeName(ct bool) string {
	if ct {
		return "ct"
	}
	return "var"
}

// TestRangeGuardsRejectOutOfDomainInputs runs every range-guard case in both
// operation modes. setPaillierCTTestMode restores the global flag via
// t.Cleanup, so no mode toggle leaks out of this test.
func TestRangeGuardsRejectOutOfDomainInputs(t *testing.T) {
	sk, pk, err := loadFixturePaillierKey(0)
	require.NoError(t, err)
	N := pk.N
	N2 := pk.NSquare()
	neg := big.NewInt(-1)
	// -N2, a negative ciphertext-domain operand, kept local so N2 itself
	// stays intact for the later cases.
	negN2 := new(big.Int).Neg(N2)
	// A prime factor of N stays inside the canonical ciphertext range
	// [0, N^2) yet shares that factor with N^2, so the gcd check must flag
	// it malformed. GetPQ recovers it deterministically from the fixture
	// key material.
	pFactor, _ := sk.GetPQ()
	// maxMsg = N-1 is the largest in-domain message.
	maxMsg := new(big.Int).Sub(N, one)
	// A valid ciphertext once, shared by every in-domain case below.
	cValid, err := pk.Encrypt(big.NewInt(3))
	require.NoError(t, err)

	type guardCase struct {
		name string
		run  func() error
		want error // nil = expect success and verify the round trip
	}
	cases := []guardCase{
		{
			name: "Encrypt_mNegative",
			run: func() error {
				_, err := pk.Encrypt(neg)
				return err
			},
			want: ErrMessageTooLong,
		},
		{
			name: "Encrypt_mZero",
			run: func() error {
				c, err := pk.Encrypt(zero)
				if err != nil {
					return err
				}
				m, err := sk.Decrypt(c)
				if err != nil {
					return err
				}
				if m.Cmp(zero) != 0 {
					return errors.New("decrypted value mismatch")
				}
				return nil
			},
		},
		{
			name: "Encrypt_mMax",
			run: func() error {
				c, err := pk.Encrypt(maxMsg)
				if err != nil {
					return err
				}
				m, err := sk.Decrypt(c)
				if err != nil {
					return err
				}
				if m.Cmp(maxMsg) != 0 {
					return errors.New("decrypted value mismatch")
				}
				return nil
			},
		},
		{
			name: "Encrypt_mEqualsN",
			run: func() error {
				_, err := pk.Encrypt(N)
				return err
			},
			want: ErrMessageTooLong,
		},
		{
			name: "HomoMult_mNegative",
			run: func() error {
				_, err := pk.HomoMult(neg, cValid)
				return err
			},
			want: ErrMessageTooLong,
		},
		{
			name: "HomoMult_mEqualsN",
			run: func() error {
				_, err := pk.HomoMult(N, cValid)
				return err
			},
			want: ErrMessageTooLong,
		},
		{
			name: "HomoMult_c1EqualsN2",
			run: func() error {
				_, err := pk.HomoMult(big.NewInt(3), N2)
				return err
			},
			want: ErrMessageTooLong,
		},
		{
			name: "HomoMult_c1Negative",
			run: func() error {
				_, err := pk.HomoMult(big.NewInt(3), neg)
				return err
			},
			want: ErrMessageTooLong,
		},
		{
			name: "HomoMult_inDomainRoundTrip",
			run: func() error {
				hc, err := pk.HomoMult(maxMsg, cValid)
				if err != nil {
					return err
				}
				m, err := sk.Decrypt(hc)
				if err != nil {
					return err
				}
				want := new(big.Int).Mul(maxMsg, big.NewInt(3))
				want.Mod(want, N)
				if m.Cmp(want) != 0 {
					return errors.New("decrypted value mismatch")
				}
				return nil
			},
		},
		{
			name: "HomoAdd_c1EqualsN2",
			run: func() error {
				_, err := pk.HomoAdd(N2, cValid)
				return err
			},
			want: ErrMessageTooLong,
		},
		{
			name: "HomoAdd_c2Negative",
			run: func() error {
				_, err := pk.HomoAdd(cValid, neg)
				return err
			},
			want: ErrMessageTooLong,
		},
		{
			name: "HomoAdd_inDomainRoundTrip",
			run: func() error {
				sum, err := pk.HomoAdd(cValid, cValid)
				if err != nil {
					return err
				}
				m, err := sk.Decrypt(sum)
				if err != nil {
					return err
				}
				if m.Cmp(big.NewInt(6)) != 0 {
					return errors.New("decrypted value mismatch")
				}
				return nil
			},
		},
		{
			name: "HomoAdd_degenerateKey",
			// CONTRACT: like Encrypt/HomoMult/Decrypt, HomoAdd validates
			// the key's modulus first and reports it before the ciphertext
			// range checks.
			run: func() error {
				_, err := (&PublicKey{}).HomoAdd(cValid, cValid)
				return err
			},
			want: ErrInvalidModulus,
		},
		{
			name: "HomoAdd_degenerateKeyBeforeRangeCheck",
			// An out-of-range operand on a degenerate key must report the
			// key error, proving the modulus check runs first.
			run: func() error {
				_, err := (&PublicKey{}).HomoAdd(neg, neg)
				return err
			},
			want: ErrInvalidModulus,
		},
		{
			name: "Decrypt_cEqualsN2",
			run: func() error {
				_, err := sk.Decrypt(N2)
				return err
			},
			want: ErrMessageTooLong,
		},
		{
			name: "Decrypt_cNegative",
			run: func() error {
				_, err := sk.Decrypt(neg)
				return err
			},
			want: ErrMessageTooLong,
		},
		{
			name: "Decrypt_cSharesFactorWithN",
			run: func() error {
				_, err := sk.Decrypt(pFactor)
				return err
			},
			want: ErrMessageMalFormed,
		},
		{
			name: "Decrypt_cNegativeN2",
			run: func() error {
				_, err := sk.Decrypt(negN2)
				return err
			},
			want: ErrMessageTooLong,
		},
	}

	for _, ct := range []bool{true, false} {
		setPaillierCTTestMode(t, ct)
		for _, tc := range cases {
			t.Run(tc.name+"/"+modeName(ct), func(t *testing.T) {
				// A panic instead of the expected error means the guard
				// was bypassed and the constant-time code saw the
				// out-of-domain input.
				assert.NotPanics(t, func() {
					err := tc.run()
					if tc.want == nil {
						require.NoError(t, err, "ct=%v", ct)
						return
					}
					assert.ErrorIs(t, err, tc.want, "ct=%v", ct)
				})
			})
		}
	}
}

// TestHomoMultBoundedEnforcesPublicBound pins the HomoMultBounded contract
// MtA relies on: the caller's public bound must be a usable padding target
// (positive and at most N), the secret multiplier must sit in [0, bound), and
// a multiplier at the top of that range gives the same ciphertext with the
// constant-time padding as the variable-time HomoMult.
func TestHomoMultBoundedEnforcesPublicBound(t *testing.T) {
	_, pk, err := loadFixturePaillierKey(0)
	require.NoError(t, err)
	N2 := pk.NSquare()
	// A 256-bit public bound, the shape of a curve order.
	bound := new(big.Int).Sub(new(big.Int).Lsh(one, 256), big.NewInt(189))
	top := new(big.Int).Sub(bound, one)
	cValid, err := pk.Encrypt(big.NewInt(3))
	require.NoError(t, err)

	for _, ct := range []bool{true, false} {
		setPaillierCTTestMode(t, ct)
		t.Run("rejects_"+modeName(ct), func(t *testing.T) {
			for name, b := range map[string]*big.Int{
				"nil":     nil,
				"zero":    big.NewInt(0),
				"neg":     big.NewInt(-1),
				"above_N": new(big.Int).Add(pk.N, one),
			} {
				_, err := pk.HomoMultBounded(big.NewInt(3), cValid, b)
				assert.ErrorIs(t, err, ErrInvalidBound, "bound=%s, ct=%v", name, ct)
			}
			for name, m := range map[string]*big.Int{
				"nil":      nil,
				"neg":      big.NewInt(-1),
				"at_bound": bound,
			} {
				_, err := pk.HomoMultBounded(m, cValid, bound)
				assert.ErrorIs(t, err, ErrMessageTooLong, "m=%s, ct=%v", name, ct)
			}
			// bound = N is the plaintext domain and stays usable.
			_, err := pk.HomoMultBounded(big.NewInt(3), cValid, pk.N)
			require.NoError(t, err, "ct=%v", ct)
		})
	}

	// m = bound-1 has the full padded width; the padded constant-time
	// result must match the unpadded variable-time HomoMult.
	setPaillierCTTestMode(t, false)
	want, err := pk.HomoMult(top, cValid)
	require.NoError(t, err)
	setPaillierCTTestMode(t, true)
	got, err := pk.HomoMultBounded(top, cValid, bound)
	require.NoError(t, err)
	assert.Equal(t, 0, got.Cmp(want), "padded constant-time result must match HomoMult")
	assert.True(t, got.Sign() >= 0 && got.Cmp(N2) < 0, "result must stay in [0, N^2)")
}
