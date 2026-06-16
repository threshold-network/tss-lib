// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/test"
	"github.com/bnb-chain/tss-lib/tss"
)

// TestE2EConcurrentConstantTime runs the full distributed key generation protocol with
// constant-time cryptographic operations enabled, using pre-generated preparams from the
// test fixtures. This exercises the CT-wired keygen-path provers (DLN proof, Paillier
// FactorProof / ModProof / square-free Proof) in-protocol and asserts every party converges
// on the same ECDSA public key, confirming the CT path is functionally equivalent in the
// integrated keygen flow that keep-core runs.
func TestE2EConcurrentConstantTime(t *testing.T) {
	setUp("info")

	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()
	assert.True(t, common.IsConstantTimeEnabled(), "constant-time ops must be enabled for this test")

	threshold := testThreshold

	fixtures, pIDs, err := LoadKeygenTestFixtures(testParticipants)
	if err != nil {
		t.Skip("keygen test fixtures are required for the constant-time keygen E2E (avoids safe-prime generation)")
	}
	assert.Equal(t, testParticipants, len(fixtures))

	p2pCtx := tss.NewPeerContext(pIDs)
	parties := make([]*LocalParty, 0, len(pIDs))

	errCh := make(chan *tss.Error, len(pIDs))
	outCh := make(chan tss.Message, len(pIDs))
	endCh := make(chan LocalPartySaveData, len(pIDs))

	updater := test.SharedPartyUpdater

	for i := 0; i < len(pIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, pIDs[i], len(pIDs), threshold)
		P := NewLocalParty(params, outCh, endCh, fixtures[i].LocalPreParams).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
	saves := make([]LocalPartySaveData, 0, len(pIDs))
keygen:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break keygen

		case msg := <-outCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(P, msg, errCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					t.Fatalf("party %d tried to send a message to itself (%d)", dest[0].Index, msg.GetFrom().Index)
				}
				go updater(parties[dest[0].Index], msg, errCh)
			}

		case save := <-endCh:
			saves = append(saves, save)
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(pIDs)) {
				// Every party must converge on the same group ECDSA public key.
				pk0 := saves[0].ECDSAPub
				for i, s := range saves {
					assert.True(t, pk0.Equals(s.ECDSAPub),
						"party %d ECDSA public key must match party 0 (constant-time keygen)", i)
				}
				t.Log("Constant-time keygen E2E done; all parties agree on the public key.")
				break keygen
			}
		}
	}
}
