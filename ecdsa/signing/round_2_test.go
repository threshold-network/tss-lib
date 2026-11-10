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
	"github.com/stretchr/testify/require"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// TestSigningRound2_LocalWitnessErrorHasNoCulprits pins that a bad local MtA
// input (gamma or w outside [0, q)) fails round 2 without blaming any peer.
// Without the local check, each per-peer BobMid call would fail on it and the
// round would name every peer as a culprit.
func TestSigningRound2_LocalWitnessErrorHasNoCulprits(t *testing.T) {
	fixtures, pIDs, err := keygen.LoadKeygenTestFixtures(2)
	require.NoError(t, err)
	ec := tss.S256()
	q := ec.Params().N

	for name, setBad := range map[string]func(*localTempData){
		"gamma=q":  func(temp *localTempData) { temp.gamma = new(big.Int).Set(q) },
		"gamma=-1": func(temp *localTempData) { temp.gamma = big.NewInt(-1) },
		"w=q":      func(temp *localTempData) { temp.w = new(big.Int).Set(q) },
		"w=nil":    func(temp *localTempData) { temp.w = nil },
	} {
		t.Run(name, func(t *testing.T) {
			params := tss.NewParameters(ec, tss.NewPeerContext(pIDs), pIDs[0], len(pIDs), 1)
			keys := fixtures[0]
			temp := localTempData{}
			temp.gamma = big.NewInt(13)
			temp.w = big.NewInt(17)
			setBad(&temp)
			out := make(chan tss.Message, len(pIDs))
			data := common.SignatureData{}
			rnd := &round2{&round1{
				&base{params, &keys, &data, &temp, out, nil, make([]bool, len(pIDs)), false, 2},
			}}

			tssErr := rnd.Start()
			require.NotNil(t, tssErr, "a bad local witness must fail round 2")
			assert.Empty(t, tssErr.Culprits(), "a local witness error must not blame peers")
			assert.Empty(t, out, "no round 2 message may be sent on failure")
		})
	}
}
