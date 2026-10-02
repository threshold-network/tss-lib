// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// These regressions pin the per-key constant-time state reuse contract:
// concurrent operations on one unchanged key must stay correct, a key object
// whose exported N/LambdaN values are sequentially replaced or mutated must
// pick up the new values (not stale cached state), and a by-value copy of a
// key must behave independently of the original.

package paillier

import (
	"math/big"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConcurrentSameKeyOperationsDecryptCorrectMessages runs concurrent
// Encrypt, HomoMult, and Decrypt calls against one unchanged fixture key and
// verifies every recovered plaintext is correct.
func TestConcurrentSameKeyOperationsDecryptCorrectMessages(t *testing.T) {
	setPaillierCTTestMode(t, true)
	sk, pk, err := loadFixturePaillierKey(0)
	require.NoError(t, err)

	const workers = 8
	msg := big.NewInt(3)
	want := new(big.Int).Lsh(msg, 1) // 2*msg, the HomoMult(2, ...) target

	var wg sync.WaitGroup
	errs := make([]error, workers)
	for i := range workers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c, err := pk.Encrypt(msg)
			if err != nil {
				errs[i] = err
				return
			}
			hc, err := pk.HomoMult(big.NewInt(2), c)
			if err != nil {
				errs[i] = err
				return
			}
			dec, err := sk.Decrypt(c)
			if err != nil {
				errs[i] = err
				return
			}
			if dec.Cmp(msg) != 0 {
				errs[i] = assert.AnError
				return
			}
			decH, err := sk.Decrypt(hc)
			if err != nil {
				errs[i] = err
				return
			}
			if decH.Cmp(want) != 0 {
				errs[i] = assert.AnError
			}
		}(i)
	}
	wg.Wait()
	for i, e := range errs {
		assert.NoError(t, e, "worker %d", i)
	}
}

// TestKeyReuseAfterKeyValuesReplaced verifies that after a private key
// object's exported N and LambdaN are sequentially replaced (or mutated in
// place) with a second valid fixture key's values, the same reused object
// correctly decrypts ciphertexts produced under that second key.
func TestKeyReuseAfterKeyValuesReplaced(t *testing.T) {
	setPaillierCTTestMode(t, true)
	sk, pk, err := loadFixturePaillierKey(0)
	require.NoError(t, err)
	sk2, pk2, err := loadFixturePaillierKey(1)
	require.NoError(t, err)

	// Warm the cached state on the original key's values.
	c0, err := pk.Encrypt(big.NewInt(5))
	require.NoError(t, err)
	m0, err := sk.Decrypt(c0)
	require.NoError(t, err)
	require.Equal(t, 0, m0.Cmp(big.NewInt(5)))

	// Preserve the original values so we can mutate back and forth.
	origN := new(big.Int).Set(sk.N)
	origLambda := new(big.Int).Set(sk.LambdaN)
	origPhi := new(big.Int).Set(sk.PhiN)

	// In-place value mutation of the exported fields to the second key's
	// values; the cache must detect the value change, not just reuse a
	// stale context by pointer identity.
	sk.N.Set(sk2.N)
	sk.LambdaN.Set(sk2.LambdaN)
	sk.PhiN.Set(sk2.PhiN)
	c1, err := pk2.Encrypt(big.NewInt(9))
	require.NoError(t, err)
	m1, err := sk.Decrypt(c1)
	require.NoError(t, err)
	assert.Equal(t, 0, m1.Cmp(big.NewInt(9)), "in-place mutated key must decrypt the second key's ciphertext")

	// Field reassignment (pointer replacement) back to the original values.
	sk.N = origN
	sk.LambdaN = origLambda
	sk.PhiN = origPhi
	m2, err := sk.Decrypt(c0)
	require.NoError(t, err)
	assert.Equal(t, 0, m2.Cmp(big.NewInt(5)), "reassigned key must decrypt the original key's ciphertext again")
}

// TestByValueKeyCopyIsIndependent verifies that a by-value copy of a private
// key keeps correct, independent behavior: mutating the original's exported
// fields must not disturb the copy's own cached state or decryption result.
func TestByValueKeyCopyIsIndependent(t *testing.T) {
	setPaillierCTTestMode(t, true)
	sk, pk, err := loadFixturePaillierKey(0)
	require.NoError(t, err)
	sk2, pk2, err := loadFixturePaillierKey(1)
	require.NoError(t, err)

	skCopy := *sk
	pkCopy := *pk

	// Mutate the original to the second key's values (pointer replacement).
	sk.N = sk2.N
	sk.LambdaN = sk2.LambdaN
	sk.PhiN = sk2.PhiN

	// The copy must still operate under the original key's values.
	c0, err := pkCopy.Encrypt(big.NewInt(11))
	require.NoError(t, err)
	m0, err := skCopy.Decrypt(c0)
	require.NoError(t, err)
	assert.Equal(t, 0, m0.Cmp(big.NewInt(11)), "by-value copy must retain the original key's behavior")

	// The mutated original must now operate under the second key's values.
	c1, err := pk2.Encrypt(big.NewInt(13))
	require.NoError(t, err)
	m1, err := sk.Decrypt(c1)
	require.NoError(t, err)
	assert.Equal(t, 0, m1.Cmp(big.NewInt(13)), "mutated original must decrypt the second key's ciphertext")
}
