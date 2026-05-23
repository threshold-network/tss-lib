// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/crypto/commitments"
)

func TestDecommitFour(t *testing.T) {
	secrets := func(n int) []*big.Int {
		out := make([]*big.Int, n)
		for i := range out {
			out[i] = big.NewInt(int64(i + 1))
		}
		return out
	}

	t.Run("accepts exactly four secrets", func(t *testing.T) {
		cmt := commitments.NewHashCommitment(secrets(4)...)
		values, ok := decommitFour(commitments.HashCommitDecommit{C: cmt.C, D: cmt.D})
		assert.True(t, ok)
		assert.Len(t, values, 4)
	})

	// Without the length guard, an attacker can send a commitment binding to
	// more (or fewer) than four secrets and have round 9 silently take
	// values[0..3] as their attacker-chosen Uj/Tj coordinates, bypassing the
	// U==T integrity check without breaking any hash.
	t.Run("rejects three secrets", func(t *testing.T) {
		cmt := commitments.NewHashCommitment(secrets(3)...)
		_, ok := decommitFour(commitments.HashCommitDecommit{C: cmt.C, D: cmt.D})
		assert.False(t, ok)
	})

	t.Run("rejects six secrets", func(t *testing.T) {
		cmt := commitments.NewHashCommitment(secrets(6)...)
		_, ok := decommitFour(commitments.HashCommitDecommit{C: cmt.C, D: cmt.D})
		assert.False(t, ok)
	})

	t.Run("rejects mismatched commitment", func(t *testing.T) {
		cmt := commitments.NewHashCommitment(secrets(4)...)
		corrupted := new(big.Int).Add(cmt.C, big.NewInt(1))
		_, ok := decommitFour(commitments.HashCommitDecommit{C: corrupted, D: cmt.D})
		assert.False(t, ok)
	})
}
