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

	"github.com/bnb-chain/tss-lib/common"
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
// correctly decrypts ciphertexts produced under that second key and its
// cache-dependent public-key arithmetic (Encrypt, HomoMult) tracks the
// new values instead of stale cached state.
func TestKeyReuseAfterKeyValuesReplaced(t *testing.T) {
	setPaillierCTTestMode(t, true)
	sk, pk, err := loadFixturePaillierKey(0)
	require.NoError(t, err)
	key2Sk, key2Pk, err := loadFixturePaillierKey(1)
	require.NoError(t, err)

	// Warm the cached state on the original key's values.
	c0, err := pk.Encrypt(big.NewInt(5))
	require.NoError(t, err)
	m0, err := sk.Decrypt(c0)
	require.NoError(t, err)
	require.Equal(t, 0, m0.Cmp(big.NewInt(5)))
	hc0, err := pk.HomoMult(big.NewInt(2), c0)
	require.NoError(t, err)
	// Decrypt the warmed-up HomoMult result to prove the cached path
	// produced a valid ciphertext of 2*5=10.
	mh0, err := sk.Decrypt(hc0)
	require.NoError(t, err)
	require.Equal(t, 0, mh0.Cmp(big.NewInt(10)), "warmed key must decrypt its own HomoMult result")

	// Preserve the original values so we can mutate back and forth.
	origN := new(big.Int).Set(sk.N)
	origLambda := new(big.Int).Set(sk.LambdaN)
	origPhi := new(big.Int).Set(sk.PhiN)

	// In-place value mutation of the exported fields to the second key's
	// values; the cache must detect the value change, not just reuse a
	// stale context by pointer identity.
	sk.N.Set(key2Sk.N)
	sk.LambdaN.Set(key2Sk.LambdaN)
	sk.PhiN.Set(key2Sk.PhiN)
	c1, err := key2Pk.Encrypt(big.NewInt(9))
	require.NoError(t, err)
	m1, err := sk.Decrypt(c1)
	require.NoError(t, err)
	assert.Equal(t, 0, m1.Cmp(big.NewInt(9)), "in-place mutated key must decrypt the second key's ciphertext")
	// The public-key arithmetic path (cache-using) must also operate under
	// the second key's modulus after the in-place mutation: encrypt a fresh
	// message with the mutated key's N and verify the ciphertext is valid
	// under the second key, and that HomoMult matches the math/big
	// reference.
	mutatedPk := &sk.PublicKey
	cmut, err := mutatedPk.Encrypt(big.NewInt(7))
	require.NoError(t, err)
	mmut, err := key2Sk.Decrypt(cmut)
	require.NoError(t, err)
	assert.Equal(t, 0, mmut.Cmp(big.NewInt(7)), "cache-dependent Encrypt on mutated key must decrypt under the second key")
	hmut, err := mutatedPk.HomoMult(big.NewInt(3), cmut)
	require.NoError(t, err)
	N2 := key2Pk.NSquare()
	wantH := common.ModInt(N2).Exp(cmut, big.NewInt(3))
	assert.Equal(t, 0, hmut.Cmp(wantH), "HomoMult on mutated key must match the math/big reference")
	// Restore the in-place mutation to the original values.
	sk.N.Set(origN)
	sk.LambdaN.Set(origLambda)
	sk.PhiN.Set(origPhi)

	// Field reassignment (pointer replacement) to the second key's values.
	sk.N = key2Sk.N
	sk.LambdaN = key2Sk.LambdaN
	sk.PhiN = key2Sk.PhiN
	c2, err := key2Pk.Encrypt(big.NewInt(11))
	require.NoError(t, err)
	m2, err := sk.Decrypt(c2)
	require.NoError(t, err)
	assert.Equal(t, 0, m2.Cmp(big.NewInt(11)), "reassigned key must decrypt the second key's ciphertext")
	// The cache-dependent public-key path must also track the reassignment:
	// encrypt under the reassigned key and verify decryption.
	reassignedPk := &sk.PublicKey
	cra, err := reassignedPk.Encrypt(big.NewInt(13))
	require.NoError(t, err)
	mra, err := key2Sk.Decrypt(cra)
	require.NoError(t, err)
	assert.Equal(t, 0, mra.Cmp(big.NewInt(13)), "cache-dependent Encrypt on reassigned key must decrypt under the second key")
	hra, err := reassignedPk.HomoMult(big.NewInt(5), cra)
	require.NoError(t, err)
	wantHr := common.ModInt(N2).Exp(cra, big.NewInt(5))
	assert.Equal(t, 0, hra.Cmp(wantHr), "HomoMult on reassigned key must match the math/big reference")
	// Restore pointer reassignment back to the original values.
	sk.N = origN
	sk.LambdaN = origLambda
	sk.PhiN = origPhi
	m3, err := sk.Decrypt(c0)
	require.NoError(t, err)
	assert.Equal(t, 0, m3.Cmp(big.NewInt(5)), "restored key must decrypt the original key's ciphertext again")
}

// TestByValueKeyCopyIsIndependent verifies that a by-value copy of a private
// key keeps correct, independent behavior: re-pointing the original's
// exported fields to a second key's values must not disturb the copy's
// cached public-key state or its decryption under the original key, while
// the original's own cache-dependent arithmetic must pick up the new values.
func TestByValueKeyCopyIsIndependent(t *testing.T) {
	setPaillierCTTestMode(t, true)
	sk, pk, err := loadFixturePaillierKey(0)
	require.NoError(t, err)
	key2Sk, key2Pk, err := loadFixturePaillierKey(1)
	require.NoError(t, err)

	// The copy's embedded public key is a distinct cache owner from the
	// original's.
	skCopy := *sk
	pkCopy := *pk

	// Warm both cache entries under the original key's values before any
	// mutation, so the later assertions cannot be satisfied by a first-use
	// build.
	cw, err := pk.Encrypt(big.NewInt(5))
	require.NoError(t, err)
	hw, err := pk.HomoMult(big.NewInt(2), cw)
	require.NoError(t, err)
	mw, err := sk.Decrypt(hw)
	require.NoError(t, err)
	require.Equal(t, 0, mw.Cmp(big.NewInt(10)), "warmed original must decrypt its own HomoMult result")
	cCopy, err := pkCopy.Encrypt(big.NewInt(7))
	require.NoError(t, err)
	hCopy, err := pkCopy.HomoMult(big.NewInt(3), cCopy)
	require.NoError(t, err)
	mCopy, err := skCopy.Decrypt(hCopy)
	require.NoError(t, err)
	require.Equal(t, 0, mCopy.Cmp(big.NewInt(21)), "warmed copy must decrypt its own HomoMult result")

	// Re-point the original's fields to the second key's values. The copy
	// holds its own field pointers, so this cannot reach it.
	sk.N = key2Sk.N
	sk.LambdaN = key2Sk.LambdaN
	sk.PhiN = key2Sk.PhiN

	// The original's cache-dependent path must now operate under the second
	// key's values.
	cOrig, err := sk.Encrypt(big.NewInt(11))
	require.NoError(t, err)
	mOrig, err := key2Sk.Decrypt(cOrig)
	require.NoError(t, err)
	assert.Equal(t, 0, mOrig.Cmp(big.NewInt(11)), "re-pointed original must encrypt under the second key")
	hOrig, err := sk.HomoMult(big.NewInt(4), cOrig)
	require.NoError(t, err)
	wantOrig := new(big.Int).Exp(cOrig, big.NewInt(4), key2Pk.NSquare())
	assert.Equal(t, 0, hOrig.Cmp(wantOrig), "HomoMult on the re-pointed original must match the math/big reference")
	mDirect, err := sk.Decrypt(cOrig)
	require.NoError(t, err)
	assert.Equal(t, 0, mDirect.Cmp(big.NewInt(11)), "re-pointed original must decrypt under the second key")

	// The copy must still operate under the original key's values.
	cKeep, err := pkCopy.Encrypt(big.NewInt(13))
	require.NoError(t, err)
	mKeep, err := skCopy.Decrypt(cKeep)
	require.NoError(t, err)
	assert.Equal(t, 0, mKeep.Cmp(big.NewInt(13)), "by-value copy must retain the original key's behavior")
	hKeep, err := pkCopy.HomoMult(big.NewInt(5), cKeep)
	require.NoError(t, err)
	mhKeep, err := skCopy.Decrypt(hKeep)
	require.NoError(t, err)
	assert.Equal(t, 0, mhKeep.Cmp(big.NewInt(65)), "by-value copy must keep HomoMult under the original key")
}
