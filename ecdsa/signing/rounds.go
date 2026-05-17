// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

const (
	TaskName = "signing"
)

type (
	base struct {
		*tss.Parameters
		key     *keygen.LocalPartySaveData
		data    *common.SignatureData
		temp    *localTempData
		out     chan<- tss.Message
		end     chan<- common.SignatureData
		ok      []bool // `ok` tracks parties which have been verified by Update()
		started bool
		number  int
	}
	round1 struct {
		*base
	}
	round2 struct {
		*round1
	}
	round3 struct {
		*round2
	}
	round4 struct {
		*round3
	}
	round5 struct {
		*round4
	}
	round6 struct {
		*round5
	}
	round7 struct {
		*round6
	}
	round8 struct {
		*round7
	}
	round9 struct {
		*round8
	}
	finalization struct {
		*round9
	}
)

var (
	_ tss.Round = (*round1)(nil)
	_ tss.Round = (*round2)(nil)
	_ tss.Round = (*round3)(nil)
	_ tss.Round = (*round4)(nil)
	_ tss.Round = (*round5)(nil)
	_ tss.Round = (*round6)(nil)
	_ tss.Round = (*round7)(nil)
	_ tss.Round = (*round8)(nil)
	_ tss.Round = (*round9)(nil)
	_ tss.Round = (*finalization)(nil)
)

// ----- //

func (round *base) Params() *tss.Parameters {
	return round.Parameters
}

func (round *base) RoundNumber() int {
	return round.number
}

// CanProceed is inherited by other rounds
func (round *base) CanProceed() bool {
	if !round.started {
		return false
	}
	for _, ok := range round.ok {
		if !ok {
			return false
		}
	}
	return true
}

// WaitingFor is called by a Party for reporting back to the caller
func (round *base) WaitingFor() []*tss.PartyID {
	Ps := round.Parties().IDs()
	ids := make([]*tss.PartyID, 0, len(round.ok))
	for j, ok := range round.ok {
		if ok {
			continue
		}
		ids = append(ids, Ps[j])
	}
	return ids
}

func (round *base) WrapError(err error, culprits ...*tss.PartyID) *tss.Error {
	return tss.NewError(err, TaskName, round.number, round.PartyID(), culprits...)
}

// ----- //

// `ok` tracks parties which have been verified by Update()
func (round *base) resetOK() {
	for j := range round.ok {
		round.ok[j] = false
	}
}

func (round *base) getSSID() ([]byte, error) {
	ssidList := []*big.Int{
		round.EC().Params().P,
		round.EC().Params().N,
		round.EC().Params().B,
		round.EC().Params().Gx,
		round.EC().Params().Gy,
	}
	ssidList = append(ssidList, round.Parties().IDs().Keys()...)
	bigXjList, err := crypto.FlattenECPoints(round.key.BigXj)
	if err != nil {
		return nil, err
	}
	ssidList = append(ssidList, bigXjList...)
	ssidList = append(ssidList, round.key.NTildej...)
	ssidList = append(ssidList, round.key.H1j...)
	ssidList = append(ssidList, round.key.H2j...)
	ssidList = append(ssidList, big.NewInt(int64(round.number)))
	ssidList = append(ssidList, round.temp.ssidNonce)
	return common.SHA512_256i(ssidList...).Bytes(), nil
}
