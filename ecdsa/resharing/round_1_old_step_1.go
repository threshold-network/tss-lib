// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package resharing

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/crypto/vss"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
)

// round 1 represents round 1 of the keygen part of the GG18 ECDSA TSS spec (Gennaro, Goldfeder; 2018)
func newRound1(params *tss.ReSharingParameters, input, save *keygen.LocalPartySaveData, temp *localTempData, out chan<- tss.Message, end chan<- keygen.LocalPartySaveData) tss.Round {
	return &round1{
		&base{params, temp, input, save, out, end, make([]bool, len(params.OldParties().IDs())), make([]bool, len(params.NewParties().IDs())), false, 1}}
}

func (round *round1) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 1
	round.started = true
	round.resetOK() // resets both round.oldOK and round.newOK
	round.allNewOK()

	// Derive SSID for both committees so the old committee can broadcast it
	// in DGRound1Message and the new committee can cross-check that every
	// old-committee party agrees. Both committees can derive locally from
	// public inputs (party IDs, curve, round number, ssidNonce); broadcasting
	// adds early detection of a corrupted old-committee party who would
	// otherwise emit divergent SSIDs across new-committee members.
	//
	// Resharing fails closed if no SessionNonce is set. The previous zero
	// fallback neutralised the SSID binding for any caller that forgot
	// SetSessionNonce — two resharing ceremonies over identical committees
	// would derive the same SSID, breaking session binding.
	nonce := round.Params().SessionNonce()
	if nonce == nil {
		return round.WrapError(errors.New("resharing requires tss.Parameters.SetSessionNonce(<unique per-ceremony nonce>) before Start"))
	}
	round.temp.ssidNonce = new(big.Int).Set(nonce)
	round.temp.ssid = round.getSSID()

	if !round.ReSharingParams().IsOldCommittee() {
		return nil
	}
	round.allOldOK()

	Pi := round.PartyID()
	i := Pi.Index

	// 1. PrepareForSigning() -> w_i
	xi, ks, bigXj := round.input.Xi, round.input.Ks, round.input.BigXj
	if round.Threshold()+1 > len(ks) {
		return round.WrapError(fmt.Errorf("t+1=%d is not satisfied by the key count of %d", round.Threshold()+1, len(ks)), round.PartyID())
	}
	newKs := round.NewParties().IDs().Keys()
	wi, _ := signing.PrepareForSigning(round.Params().EC(), i, len(round.OldParties().IDs()), xi, ks, bigXj)

	// 2.
	vi, shares, err := vss.Create(round.Params().EC(), round.NewThreshold(), wi, newKs)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}

	// 3.
	flatVis, err := crypto.FlattenECPoints(vi)
	if err != nil {
		return round.WrapError(err, round.PartyID())
	}
	vCmt := commitments.NewHashCommitment(flatVis...)

	// 4. populate temp data
	round.temp.VD = vCmt.D
	round.temp.NewShares = shares

	// 5. "broadcast" C_i to members of the NEW committee, including this
	// party's locally-derived SSID so the new committee can cross-verify.
	r1msg := NewDGRound1Message(
		round.NewParties().IDs().Exclude(round.PartyID()), round.PartyID(),
		round.input.ECDSAPub, vCmt.C, round.temp.ssid)
	round.temp.dgRound1Messages[i] = r1msg
	round.out <- r1msg

	return nil
}

func (round *round1) CanAccept(msg tss.ParsedMessage) bool {
	// accept messages from old -> new committee
	if _, ok := msg.Content().(*DGRound1Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round1) Update() (bool, *tss.Error) {
	// only the new committee receive in this round
	if !round.ReSharingParameters.IsNewCommittee() {
		return true, nil
	}
	ret := true
	// accept messages from old -> new committee
	for j, msg := range round.temp.dgRound1Messages {
		if round.oldOK[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.oldOK[j] = true

		if round.temp.dgRound1Messages[0] == nil {
			ret = false
			continue
		}
		// Verify the sender's broadcast SSID matches our locally-derived SSID
		// before consuming any field of the message. A mismatch means either
		// (a) this old-committee party is corrupted and broadcasting an
		// inconsistent SSID across new-committee members, or (b) the parties
		// disagree on the protocol context (party IDs, curve, session
		// nonce). Either way the protocol must abort and identify the
		// culprit before downstream proof verification could mask the cause.
		senderMsg := round.temp.dgRound1Messages[j].Content().(*DGRound1Message)
		if !bytes.Equal(senderMsg.GetSsid(), round.temp.ssid) {
			return false, round.WrapError(errors.New("DGRound1Message ssid does not match locally-derived ssid — old-committee party broadcast inconsistent SSID"), msg.GetFrom())
		}

		// save the ecdsa pub received from the old committee
		r1msg := round.temp.dgRound1Messages[0].Content().(*DGRound1Message)
		candidate, err := r1msg.UnmarshalECDSAPub(round.Params().EC())
		if err != nil {
			return false, round.WrapError(errors.New("unable to unmarshal the ecdsa pub key"), msg.GetFrom())
		}
		if round.save.ECDSAPub != nil &&
			!candidate.Equals(round.save.ECDSAPub) {
			// uh oh - anomaly!
			return false, round.WrapError(errors.New("ecdsa pub key did not match what we received previously"), msg.GetFrom())
		}
		round.save.ECDSAPub = candidate
	}
	return ret, nil
}

func (round *round1) NextRound() tss.Round {
	round.started = false
	return &round2{round}
}
