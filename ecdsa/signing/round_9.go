// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"math/big"

	errors2 "github.com/pkg/errors"

	"github.com/bnb-chain/tss-lib/crypto"
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

	U := round.temp.Ui
	T := round.temp.Ti
	for j, Pj := range round.Parties().IDs() {
		if j == round.PartyID().Index {
			continue
		}

		r7msg := round.temp.signRound7Messages[j].Content().(*SignRound7Message)
		r8msg := round.temp.signRound8Messages[j].Content().(*SignRound8Message)
		cj, dj := r7msg.UnmarshalCommitment(), r8msg.UnmarshalDeCommitment()
		values, ok := decommitFour(commitments.HashCommitDecommit{C: cj, D: dj})
		if !ok {
			return round.WrapError(errors.New("de-commitment for bigUj and bigTj failed"), Pj)
		}
		// The decommitted coordinates are adversarial wire data; validate them
		// as canonical curve points before any group operation. Go's stdlib
		// curves panic on off-curve inputs to Add, and btcec returns undefined
		// coordinates, which would have turned a malformed decommitment into a
		// crash or an unattributed U != T abort.
		bigUj, err := crypto.NewECPoint(round.Params().EC(), values[0], values[1])
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "NewECPoint(bigUj)"), Pj)
		}
		bigTj, err := crypto.NewECPoint(round.Params().EC(), values[2], values[3])
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "NewECPoint(bigTj)"), Pj)
		}
		U, err = U.Add(bigUj)
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "U.Add(bigUj)"), Pj)
		}
		T, err = T.Add(bigTj)
		if err != nil {
			return round.WrapError(errors2.Wrapf(err, "T.Add(bigTj)"), Pj)
		}
	}
	// A mismatch here proves some party misbehaved in phase 5 but does not
	// identify which one, so no culprit is attributed. The previous behaviour
	// blamed the honest reporting party itself, which would misdirect any
	// orchestration layer that acts on culprits.
	if !U.Equals(T) {
		return round.WrapError(errors.New("U doesn't equal T"))
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
