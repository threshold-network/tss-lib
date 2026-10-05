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

// notPanics runs fn and fails the test on panic. The expected error of a
// guard case already proves the bad value was rejected; a panic instead of
// the error proves the guard was bypassed (the pre-guard CT-context
// construction panicked on the out-of-domain input).
func notPanics(t *testing.T, fn func()) {
	t.Helper()
	assert.NotPanics(t, func() { fn() })
}

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
				notPanics(t, func() {
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

// TestHomoMultWithBitLenRejectsWideMessages pins the extra gate of
// HomoMultWithBitLen: a caller-supplied public bit bound below the message
// width is rejected with ErrMessageTooLong even though the message is still
// inside the modulus domain, a non-usable bound width is rejected, and a
// wide enough bound still computes.
func TestHomoMultWithBitLenRejectsWideMessages(t *testing.T) {
	_, pk, err := loadFixturePaillierKey(0)
	require.NoError(t, err)
	N2 := pk.NSquare()
	// A message inside [0, N) but wider than the tight bound below.
	wideMsg := new(big.Int).Lsh(one, uint(pk.N.BitLen()-1))
	// A canonical ciphertext operand for the positive control.
	cValid, err := pk.Encrypt(big.NewInt(3))
	require.NoError(t, err)

	for _, ct := range []bool{true, false} {
		setPaillierCTTestMode(t, ct)
		t.Run("rejects_"+modeName(ct), func(t *testing.T) {
			// A non-usable bound width (<= 0) is rejected before the
			// message is considered.
			for _, bitLen := range []int{0, -1} {
				_, err := pk.HomoMultWithBitLen(big.NewInt(3), cValid, bitLen)
				assert.ErrorIs(t, err, ErrMessageTooLong, "bitLen=%d, ct=%v", bitLen, ct)
			}
			// A bound below the message width is rejected even though the
			// message is still < N.
			_, err := pk.HomoMultWithBitLen(wideMsg, cValid, wideMsg.BitLen()-1)
			assert.ErrorIs(t, err, ErrMessageTooLong, "ct=%v", ct)
			// A public bound at or above the message width is a usable
			// padding target in both modes and must not be rejected.
			_, err = pk.HomoMultWithBitLen(big.NewInt(3), cValid, 400)
			require.NoError(t, err, "ct=%v", ct)
			// And the result agrees with the plain HomoMult for the same
			// operands (CONTRACT: same validation and result), staying in
			// [0, N^2).
			plain, err := pk.HomoMult(big.NewInt(3), cValid)
			require.NoError(t, err)
			got, err := pk.HomoMultWithBitLen(big.NewInt(3), cValid, 400)
			require.NoError(t, err)
			assert.Equal(t, 0, got.Cmp(plain), "results must agree, ct=%v", ct)
			assert.True(t, plain.Sign() >= 0 && plain.Cmp(N2) < 0, "result must stay in [0, N^2), ct=%v", ct)
		})
	}
}
