// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"

	"github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/tss"
)

// decommitFour verifies cmt and returns its four secret values. It rejects
// any commitment whose DeCommit reports failure OR whose length differs from
// four; both conditions must hold because an attacker controls both C and D
// in their own messages and could otherwise commit to a longer payload, then
// have round 9 silently read values[0..3] as attacker-chosen point coordinates.
func decommitFour(cmt commitments.HashCommitDecommit) ([]*big.Int, bool) {
	ok, values := cmt.DeCommit()
	if !ok || len(values) != 4 {
		return nil, false
	}
	return values, true
}

func (round *round9) Start() *tss.Error {
	if round.started {
		return round.WrapError(errors.New("round already started"))
	}
	round.number = 9
	round.started = true
	round.resetOK()

	UX, UY := round.temp.Ui.X(), round.temp.Ui.Y()
	TX, TY := round.temp.Ti.X(), round.temp.Ti.Y()
	for j, Pj := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}

		r7msg := round.temp.signRound7Messages[j].Content().(*SignRound7Message)
		r8msg := round.temp.signRound8Messages[j].Content().(*SignRound8Message)
		cj, dj := r7msg.UnmarshalCommitment(), r8msg.UnmarshalDeCommitment()
		values, ok := decommitFour(commitments.HashCommitDecommit{C: cj, D: dj})
		if !ok {
			return round.WrapError(errors.New("de-commitment for bigVj and bigAj failed"), Pj)
		}
		UjX, UjY, TjX, TjY := values[0], values[1], values[2], values[3]
		UX, UY = round.Params().EC().Add(UX, UY, UjX, UjY)
		TX, TY = round.Params().EC().Add(TX, TY, TjX, TjY)
	}
	if UX.Cmp(TX) != 0 || UY.Cmp(TY) != 0 {
		return round.WrapError(errors.New("U doesn't equal T"), round.PartyID())
	}

	r9msg := NewSignRound9Message(round.PartyID(), round.temp.si)
	round.temp.signRound9Messages[round.PartyID().Index] = r9msg
	round.out <- r9msg
	return nil
}

func (round *round9) Update() (bool, *tss.Error) {
	ret := true
	for j, msg := range round.temp.signRound9Messages {
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

func (round *round9) CanAccept(msg tss.ParsedMessage) bool {
	if _, ok := msg.Content().(*SignRound9Message); ok {
		return msg.IsBroadcast()
	}
	return false
}

func (round *round9) NextRound() tss.Round {
	round.started = false
	return &finalization{round}
}
