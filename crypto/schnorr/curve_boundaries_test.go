// Copyright © 2019-2026 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package schnorr_test

import (
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bnb-chain/tss-lib/crypto"
	. "github.com/bnb-chain/tss-lib/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/tss"
)

// TestZKVProofConstructorRejectsMixedCurves tests the invariant that V and R
// are valid points on the same curve group: both NewZKVProof and
// NewZKVProofWithSession must reject a cross-curve mix in either argument
// role. The secp256k1 control is a consistent witness (V = sR + lG with
// R = kG); if it fails, the rejections below are indistinguishable from
// broken fixtures, so it guards that the negative cases are specifically
// about the curve mix.
func TestZKVProofConstructorRejectsMixedCurves(t *testing.T) {
	// Control: secp256k1 witness, legacy and session-bound.
	k := big.NewInt(3)
	s := big.NewInt(5)
	l := big.NewInt(7)
	R := crypto.ScalarBaseMult(tss.S256(), k) // k * G
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(tss.S256(), l)
	V, err := Rs.Add(lG) // V = sR + lG
	require.NoError(t, err)

	proof, err := NewZKVProof(V, R, s, l)
	require.NoError(t, err)
	assert.True(t, proof.Verify(V, R), "consistent same-curve witness must verify")

	session := []byte("schnorr-v-curve-boundary-control")
	proof, err = NewZKVProofWithSession(session, V, R, s, l)
	require.NoError(t, err)
	assert.True(t, proof.VerifyWithSession(session, V, R), "consistent same-curve witness must verify with its session")

	// Direction 1: V plays the secp256k1 role, R plays the P256 role.
	R256 := crypto.ScalarBaseMult(elliptic.P256(), big.NewInt(11))

	_, err = NewZKVProof(V, R256, s, l)
	assert.Error(t, err, "V on secp256k1 with R on P256 must be rejected")
	_, err = NewZKVProofWithSession([]byte("schnorr-v-curve-boundary-a"), V, R256, s, l)
	assert.Error(t, err, "mixed-curve inputs must be rejected even with a non-empty session")

	// Direction 2: V plays the P256 role, R plays the secp256k1 role, so
	// neither constructor can accept a valid point for just one argument.
	s256 := big.NewInt(13)
	l256 := big.NewInt(17)
	V256, err := R256.ScalarMult(s256).Add(crypto.ScalarBaseMult(elliptic.P256(), l256)) // V256 = sR + lG on P256
	require.NoError(t, err)

	_, err = NewZKVProof(V256, R, s256, l256)
	assert.Error(t, err, "V on P256 with R on secp256k1 must be rejected")
	_, err = NewZKVProofWithSession([]byte("schnorr-v-curve-boundary-b"), V256, R, s256, l256)
	assert.Error(t, err, "mixed-curve inputs must be rejected in both argument roles")
}
