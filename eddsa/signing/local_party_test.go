// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/agl/ed25519/edwards25519"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/ipfs/go-log"
	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/test"
	"github.com/bnb-chain/tss-lib/tss"
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel("tss-lib", level); err != nil {
		panic(err)
	}

	// only for test
	tss.SetCurve(tss.Edwards())
}

func TestE2EConcurrent(t *testing.T) {
	setUp("info")

	threshold := testThreshold

	// PHASE: load keygen fixtures
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(signPIDs))

	// PHASE: signing

	p2pCtx := tss.NewPeerContext(signPIDs)
	parties := make([]*LocalParty, 0, len(signPIDs))

	errCh := make(chan *tss.Error, len(signPIDs))
	outCh := make(chan tss.Message, len(signPIDs))
	endCh := make(chan common.SignatureData, len(signPIDs))

	updater := test.SharedPartyUpdater

	msgData, err := hex.DecodeString("00f163ee51bcaeff9cdff5e0e3c1a646abd19885fffbab0b3b4236e0cf95c9f5")
	assert.NoError(t, err)
	msg := new(big.Int).SetBytes(msgData)
	// init the parties
	for i := 0; i < len(signPIDs); i++ {
		params := tss.NewParameters(tss.Edwards(), p2pCtx, signPIDs[i], len(signPIDs), threshold)

		P := NewLocalParty(msg, params, keys[i], outCh, endCh, len(msgData)).(*LocalParty)
		parties = append(parties, P)
		go func(P *LocalParty) {
			if err := P.Start(); err != nil {
				errCh <- err
			}
		}(P)
	}

	var ended int32
signing:
	for {
		select {
		case err := <-errCh:
			common.Logger.Errorf("Error: %s", err)
			assert.FailNow(t, err.Error())
			break signing

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

		case <-endCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(signPIDs)) {
				t.Logf("Done. Received signature data from %d participants", ended)
				R := parties[0].temp.r

				// BEGIN check s correctness
				sumS := parties[0].temp.si
				for i, p := range parties {
					if i == 0 {
						continue
					}

					var tmpSumS [32]byte
					edwards25519.ScMulAdd(&tmpSumS, sumS, bigIntToEncodedBytes(big.NewInt(1)), p.temp.si)
					sumS = &tmpSumS
				}
				fmt.Printf("S: %s\n", encodedBytesToBigInt(sumS).String())
				fmt.Printf("R: %s\n", R.String())
				// END check s correctness

				// BEGIN EDDSA verify
				pkX, pkY := keys[0].EDDSAPub.X(), keys[0].EDDSAPub.Y()
				pk := edwards.PublicKey{
					Curve: tss.Edwards(),
					X:     pkX,
					Y:     pkY,
				}

				newSig, err := edwards.ParseSignature(parties[0].data.Signature)
				if err != nil {
					println("new sig error, ", err.Error())
				}

				ok := edwards.Verify(&pk, msgData, newSig.R, newSig.S)
				assert.True(t, ok, "eddsa verify must pass")
				assert.Equal(t, msgData, parties[0].data.M)
				t.Log("EDDSA signing test done.")
				// END EDDSA verify

				break signing
			}
		}
	}
}

// TestNewLocalParty_FullBytesLen_Negative pins constructor-side validation
// for fullBytesLen. Previously, a negative fullBytesLen propagated to the
// round-1/round-3 code path where `make([]byte, fullBytesLen)` panicked
// inside a protocol goroutine, bypassing tss.Error reporting. The
// constructor now panics synchronously at the caller's call site.
func TestNewLocalParty_FullBytesLen_Negative(t *testing.T) {
	msg := big.NewInt(1)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for negative fullBytesLen")
		}
		err, ok := r.(error)
		if !ok {
			t.Fatalf("panic value must be an error, got %T: %v", r, r)
		}
		if !strings.Contains(err.Error(), "fullBytesLen must be non-negative") {
			t.Fatalf("unexpected panic message: %v", err)
		}
	}()
	_ = NewLocalParty(msg, nil, keygen.LocalPartySaveData{}, nil, nil, -1)
}

// TestNewLocalParty_FullBytesLen_TooSmall pins that a fullBytesLen smaller
// than the message's byte width is rejected at the constructor rather than
// later inside (*big.Int).FillBytes (which would panic inside a goroutine).
func TestNewLocalParty_FullBytesLen_TooSmall(t *testing.T) {
	msg := big.NewInt(0xABCD) // 16-bit, needs at least 2 bytes
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("expected panic for fullBytesLen smaller than msg byte width")
		}
		err, ok := r.(error)
		if !ok {
			t.Fatalf("panic value must be an error, got %T: %v", r, r)
		}
		if !strings.Contains(err.Error(), "fullBytesLen=1 is too small") {
			t.Fatalf("unexpected panic message: %v", err)
		}
	}()
	_ = NewLocalParty(msg, nil, keygen.LocalPartySaveData{}, nil, nil, 1)
}
