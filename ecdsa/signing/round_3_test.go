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

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/mta"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// round3Fixture builds a two-party round 3 for this party (index 0) holding a
// historical-witness round-2 message from the peer: both the Bob and BobWC
// proofs carry y = N - 1 (the historical BobMid witness range), whose honest
// T1 = e*y + gamma exceeds the default tight legacy bound N + q^6. The returned
// round and the peer's PartyID let the caller drive Start() and inspect the
// round-3 result.
func round3Fixture(t *testing.T, historicalBobCompat bool) (*round3, *tss.PartyID) {
	t.Helper()

	fixtures, pIDs, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil {
		t.Fatal(err)
	}
	owner := fixtures[0]
	ec := tss.S256()
	pk := &owner.PaillierSK.PublicKey

	params := tss.NewParameters(ec, tss.NewPeerContext(pIDs), pIDs[0], len(pIDs), 1)
	params.SetProtocolMode(tss.ProtocolModeLegacy)
	if historicalBobCompat {
		params.SetLegacyHistoricalBobCompatibility(true)
	}

	// This party's MtA inputs and ciphertexts.
	const aliceMsg = 5
	bobBlind := big.NewInt(7)                            // Bob's b (the Bob-proof x-witness)
	wcBlind := big.NewInt(3)                             // Bob's w (the BobWC-proof x-witness)
	historicalY := new(big.Int).Sub(pk.N, big.NewInt(1)) // y = N - 1

	cA, err := pk.Encrypt(big.NewInt(aliceMsg))
	if err != nil {
		t.Fatal(err)
	}
	cB, err := pk.HomoMult(bobBlind, cA)
	if err != nil {
		t.Fatal(err)
	}
	cBeta, cRand, err := pk.EncryptAndReturnRandomness(historicalY)
	if err != nil {
		t.Fatal(err)
	}
	cB, err = pk.HomoAdd(cB, cBeta)
	if err != nil {
		t.Fatal(err)
	}

	c2, err := pk.HomoMult(wcBlind, cA)
	if err != nil {
		t.Fatal(err)
	}
	cBetaWC, cRandWC, err := pk.EncryptAndReturnRandomness(historicalY)
	if err != nil {
		t.Fatal(err)
	}
	c2, err = pk.HomoAdd(c2, cBetaWC)
	if err != nil {
		t.Fatal(err)
	}

	// Historical-witness proofs from the restored legacy (session-less) prover:
	// Bob (no check) and BobWC (with check, B = g^w).
	proofBob, err := mta.ProveBob(ec, pk, owner.NTildei, owner.H1i, owner.H2i, cA, cB, bobBlind, historicalY, cRand)
	if err != nil {
		t.Fatal(err)
	}
	B := crypto.ScalarBaseMult(ec, wcBlind)
	proofBobWC, err := mta.ProveBobWC(ec, pk, owner.NTildei, owner.H1i, owner.H2i, cA, c2, wcBlind, historicalY, cRandWC, B)
	if err != nil {
		t.Fatal(err)
	}
	// Guard: the fixture must actually place T1 above the default tight bound,
	// otherwise the default path could not be distinguished from the opt-in one.
	tightMaxT1 := new(big.Int).Add(pk.N, new(big.Int).Exp(ec.Params().N, big.NewInt(6), nil))
	if proofBob.T1.Cmp(tightMaxT1) < 0 || proofBobWC.T1.Cmp(tightMaxT1) < 0 {
		t.Fatal("fixture witness y = N - 1 did not place T1 above the tight bound")
	}

	keys := owner
	temp := localTempData{}
	temp.k = big.NewInt(11)
	temp.gamma = big.NewInt(13)
	temp.w = big.NewInt(17)
	temp.cis = []*big.Int{nil, cA}
	temp.bigWs = []*crypto.ECPoint{nil, B}
	// Start() folds the peer's beta/v contributions into theta/sigma after
	// the verification stage, so the success path needs them populated.
	temp.betas = []*big.Int{nil, big.NewInt(1)}
	temp.vs = []*big.Int{nil, big.NewInt(1)}
	temp.signRound2Messages = make([]tss.ParsedMessage, len(pIDs))
	temp.signRound3Messages = make([]tss.ParsedMessage, len(pIDs))
	temp.signRound2Messages[1] = NewSignRound2Message(
		pIDs[0],
		pIDs[1],
		cB,
		proofBob,
		c2,
		proofBobWC,
	)

	out := make(chan tss.Message, len(pIDs))
	data := common.SignatureData{}
	rnd := &round3{&round2{&round1{
		&base{params, &keys, &data, &temp, out, nil, make([]bool, len(pIDs)), false, 3},
	}}}
	return rnd, pIDs[1]
}

// TestSigningRound3_LegacyHistoricalBobCompatibilityPlumbing proves that the
// tss.Parameters opt-in flag reaches both round-3 checks: the same
// historical-witness (y = N - 1) round-2 message is rejected by the default
// tight legacy verifier (Alice_end and Alice_end_wc both fail, attributed to
// the peer) and accepted when
// SetLegacyHistoricalBobCompatibility(true) is selected before party
// construction.
func TestSigningRound3_LegacyHistoricalBobCompatibilityPlumbing(t *testing.T) {
	t.Run("default-tight-rejects-historical-witness", func(t *testing.T) {
		rnd, peerID := round3Fixture(t, false)
		err := rnd.Start()
		if assert.NotNil(t, err, "default legacy round 3 must reject historical-witness proofs") {
			assert.Contains(t, err.Error(), "failed to calculate Alice_end or Alice_end_wc")
			// Both the Bob and BobWC verifications failed, so the peer is the
			// attributed culprit.
			assert.Contains(t, err.Culprits(), peerID)
			assert.Empty(t, rnd.temp.signRound3Messages[rnd.PartyID().Index], "no round 3 message may be emitted on failure")
		}
	})

	t.Run("opt-in-widened-bounds-accept-historical-witness", func(t *testing.T) {
		rnd, _ := round3Fixture(t, true)
		err := rnd.Start()
		if assert.Nil(t, err, "opt-in legacy historical Bob compatibility must admit the historical-witness proofs") {
			assert.NotNil(t, rnd.temp.signRound3Messages[rnd.PartyID().Index], "round 3 message must be produced")
		}
	})
}
