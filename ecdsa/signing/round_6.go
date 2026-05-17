// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"

	errors2 "github.com/pkg/errors"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/tss"
)

func (round *round6) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 6
	round.started = true
	round.resetOK()

	i := round.PartyID().Index
	contextI := common.AppendUint64ToBytesSlice(round.temp.ssid, uint64(i))
	piAi, err := schnorr.NewZKProofWithSession(contextI, round.temp.roi, round.temp.bigAi)
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "NewZKProof(roi, bigAi)"))
	}
	piV, err := schnorr.NewZKVProofWithSession(contextI, round.temp.bigVi, round.temp.bigR, round.temp.si, round.temp.li)
	if err != nil {
		return round.WrapError(errors2.Wrapf(err, "NewZKVProof(bigVi, bigR, si, li)"))
	}

	r6msg := NewSignRound6Message(round.PartyID(), round.temp.DPower, piAi, piV)
	round.temp.signRound6Messages[round.PartyID().Index] = r6msg
	round.out <- r6msg
	return nil
}

func (round *round6) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound6Messages {
		if round.ok[j] {
			continue
		}
		if msg == nil || !round.CanAccept(msg) {
			ret = false
			continue
		}
		round.ok[j] = true
	}
	return ret, nil
}

func (round *round6) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound6Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round6) NextRound() tss.Round {
	round.started = false
	return &round7{round}
}
