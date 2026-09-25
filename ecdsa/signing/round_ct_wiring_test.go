// Copyright © 2019-2026 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/test"
	"github.com/bnb-chain/tss-lib/tss"
)

// TestRounds3to5CTWiring is the -short-safe integration gate for the round 3/4/5
// constant-time if/else branches (branch selection + modulus N). It complements
// the primitive equivalence tests (constant_time_equiv_test.go) and the heavier
// concurrent TestE2EConcurrentConstantTime by asserting the CT-produced temp
// fields after round 5 has started on all parties.
func TestRounds3to5CTWiring(t *testing.T) {
	setUp("info")

	previousMode := common.IsConstantTimeEnabled()
	t.Cleanup(func() {
		if previousMode {
			common.EnableConstantTimeOps()
		} else {
			common.DisableConstantTimeOps()
		}
	})
	common.EnableConstantTimeOps()
	assert.True(t, common.IsConstantTimeEnabled(), "constant-time ops must be enabled for this test")

	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[i], len(signPIDs), testThreshold)
		params.SetSessionNonce(big.NewInt(1))

		P := NewLocalParty(big.NewInt(42), params, keys[i], outCh, endCh, 32).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	// Track which parties have emitted a SignRound5Message (i.e. round 5 has started)
	seenR5 := make(map[int]bool)
	var ended int32

signing:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

		case msg := <-outCh:
			// Detect round-5 entry by message type
			if parsed, ok := msg.(tss.ParsedMessage); ok {
				if _, ok := parsed.Content().(*SignRound5Message); ok {
					seenR5[msg.GetFrom().Index] = true
					if len(seenR5) == len(signPIDs) {
						break signing
					}
				}
			}

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

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				break signing
			}
		}
	}

	// Assert the CT-produced temp fields on parties[0] (any single party suffices)
	P := parties[0]

	// Round 3: thelta = k*gamma mod N, sigma = k*w mod N (CT MulCT branch, round_3.go:108-112)
	assert.NotNil(t, P.temp.theta, "round 3 CT branch: temp.theta must be populated")
	assert.NotNil(t, P.temp.sigma, "round 3 CT branch: temp.sigma must be populated")

	// Round 4: thetaInverse = theta^-1 mod N (CT ModInverseCT branch, round_4.go:43-48)
	assert.NotNil(t, P.temp.thetaInverse, "round 4 CT branch: temp.thetaInverse must be populated")

	// Round 5: si = m*k + rx*sigma mod N, rx = R.X() (CT MulCT branch, round_5.go:67-73)
	assert.NotNil(t, P.temp.si, "round 5 CT branch: temp.si must be populated")
	assert.NotNil(t, P.temp.rx, "round 5 CT branch: temp.rx must be populated")

	// thetaInverse must be in [1, N-1], proving the CT branch reduced mod N (not raw math/big)
	N := tss.EC().Params().N
	assert.True(t, P.temp.thetaInverse.Sign() > 0 && P.temp.thetaInverse.Cmp(N) < 0,
		"thetaInverse must be in [1, N-1], proving CT ModInverseCT with modulus N executed")
}
