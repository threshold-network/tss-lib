// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	cmt "github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/crypto/mta"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// Implements Party
// Implements Stringer
var _ tss.Party = (*LocalParty)(nil)
var _ fmt.Stringer = (*LocalParty)(nil)

type (
	LocalParty struct {
		*tss.BaseParty
		params *tss.Parameters

		keys keygen.LocalPartySaveData
		temp localTempData
		data common.SignatureData

		// outbound messaging
		out chan<- tss.Message
		end chan<- common.SignatureData
	}

	localMessageStore struct {
		signRound1Message1s,
		signRound1Message2s,
		signRound2Messages,
		signRound3Messages,
		signRound4Messages,
		signRound5Messages,
		signRound6Messages,
		signRound7Messages,
		signRound8Messages,
		signRound9Messages []tss.ParsedMessage
	}

	localTempData struct {
		localMessageStore

		// temp data (thrown away after sign) / round 1
		w,
		m,
		k,
		theta,
		thetaInverse,
		sigma,
		keyDerivationDelta,
		gamma *big.Int
		fullBytesLen int
		cis          []*big.Int
		bigWs        []*crypto.ECPoint
		pointGamma   *crypto.ECPoint
		deCommit     cmt.HashDeCommitment

		// round 2
		betas, // return value of Bob_mid
		c1jis,
		c2jis,
		vs []*big.Int // return value of Bob_mid_wc
		pi1jis []*mta.ProofBob
		pi2jis []*mta.ProofBobWC

		// round 5
		li,
		si,
		rx,
		ry,
		roi *big.Int
		bigR,
		bigAi,
		bigVi *crypto.ECPoint
		DPower cmt.HashDeCommitment

		// round 7
		Ui,
		Ti *crypto.ECPoint
		DTelda cmt.HashDeCommitment

		ssid      []byte
		ssidNonce *big.Int
	}
)

func NewLocalParty(
	msg *big.Int,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	out chan<- tss.Message,
	end chan<- common.SignatureData,
	fullBytesLen ...int,
) tss.Party {
	return NewLocalPartyWithKDD(msg, params, key, nil, out, end, fullBytesLen...)
}

// NewLocalPartyWithKDD returns a party with key derivation delta for HD support.
//
// fullBytesLen fixes the byte width used to encode the message for the final
// ECDSA verification/output path (preserving leading zero bytes). Every signer
// in a ceremony must pass the same value. It must be positive, no larger than
// the curve order byte length, and at least ceil(msg.BitLen()/8); violating
// these constraints is a caller bug and the constructor panics at the call site
// rather than later inside a protocol goroutine.
func NewLocalPartyWithKDD(
	msg *big.Int,
	params *tss.Parameters,
	key keygen.LocalPartySaveData,
	keyDerivationDelta *big.Int,
	out chan<- tss.Message,
	end chan<- common.SignatureData,
	fullBytesLen ...int,
) tss.Party {
	validatedFullBytesLen := validateFullBytesLen("NewLocalPartyWithKDD", msg, params, fullBytesLen)

	partyCount := len(params.Parties().IDs())
	p := &LocalParty{
		BaseParty: new(tss.BaseParty),
		params:    params,
		keys:      keygen.BuildLocalSaveDataSubset(key, params.Parties().IDs()),
		temp:      localTempData{},
		data:      common.SignatureData{},
		out:       out,
		end:       end,
	}
	// msgs init
	p.temp.signRound1Message1s = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound1Message2s = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound2Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound3Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound4Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound5Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound6Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound7Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound8Messages = make([]tss.ParsedMessage, partyCount)
	p.temp.signRound9Messages = make([]tss.ParsedMessage, partyCount)
	// temp data init
	p.temp.keyDerivationDelta = keyDerivationDelta
	p.temp.m = msg
	p.temp.fullBytesLen = validatedFullBytesLen
	p.temp.cis = make([]*big.Int, partyCount)
	p.temp.bigWs = make([]*crypto.ECPoint, partyCount)
	p.temp.betas = make([]*big.Int, partyCount)
	p.temp.c1jis = make([]*big.Int, partyCount)
	p.temp.c2jis = make([]*big.Int, partyCount)
	p.temp.pi1jis = make([]*mta.ProofBob, partyCount)
	p.temp.pi2jis = make([]*mta.ProofBobWC, partyCount)
	p.temp.vs = make([]*big.Int, partyCount)
	return p
}

func validateFullBytesLen(caller string, msg *big.Int, params *tss.Parameters, fullBytesLen []int) int {
	if len(fullBytesLen) != 1 {
		panic(fmt.Errorf("%s: fullBytesLen is required and must match all signing parties", caller))
	}
	length := fullBytesLen[0]
	if length <= 0 {
		panic(fmt.Errorf("%s: fullBytesLen must be positive, got %d", caller, length))
	}
	if msg != nil && msg.BitLen() > 8*length {
		panic(fmt.Errorf("%s: fullBytesLen=%d is too small for a %d-bit message (need at least %d bytes)",
			caller, length, msg.BitLen(), (msg.BitLen()+7)/8))
	}
	if params == nil || params.EC() == nil || params.EC().Params() == nil || params.EC().Params().N == nil {
		panic(fmt.Errorf("%s: params with a curve order is required to validate fullBytesLen", caller))
	}
	orderBytes := (params.EC().Params().N.BitLen() + 7) / 8
	if length > orderBytes {
		panic(fmt.Errorf("%s: fullBytesLen=%d exceeds curve order byte length %d", caller, length, orderBytes))
	}
	return length
}

func (p *LocalParty) FirstRound() tss.Round {
	return newRound1(p.params, &p.keys, &p.data, &p.temp, p.out, p.end)
}

func (p *LocalParty) Start() *tss.Error {
	return tss.BaseStart(p, TaskName, func(round tss.Round) *tss.Error {
		round1, ok := round.(*round1)
		if !ok {
			return round.WrapError(errors.New("unable to Start(). party is in an unexpected round"))
		}
		if err := round1.prepare(); err != nil {
			return round.WrapError(err)
		}
		return nil
	})
}

func (p *LocalParty) Update(msg tss.ParsedMessage) (ok bool, err *tss.Error) {
	return tss.BaseUpdate(p, msg, TaskName)
}

func (p *LocalParty) UpdateFromBytes(wireBytes []byte, from *tss.PartyID, isBroadcast bool) (bool, *tss.Error) {
	msg, err := tss.ParseWireMessage(wireBytes, from, isBroadcast)
	if err != nil {
		return false, p.WrapError(err)
	}
	return p.Update(msg)
}

func (p *LocalParty) ValidateMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	if ok, err := p.BaseParty.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	// check that the message's "from index" will fit into the array
	if maxFromIdx := len(p.params.Parties().IDs()) - 1; maxFromIdx < msg.GetFrom().Index {
		return false, p.WrapError(fmt.Errorf("received msg with a sender index too great (%d <= %d)",
			maxFromIdx, msg.GetFrom().Index), msg.GetFrom())
	}
	return true, nil
}

func (p *LocalParty) StoreMessage(msg tss.ParsedMessage) (bool, *tss.Error) {
	// ValidateBasic is cheap; double-check the message here in case the public StoreMessage was called externally
	if ok, err := p.ValidateMessage(msg); !ok || err != nil {
		return ok, err
	}
	fromPIdx := msg.GetFrom().Index

	// switch/case is necessary to store any messages beyond current round
	// Identical redelivery is idempotent; content-different replacement from
	// a peer is rejected so commit-reveal state cannot be silently overwritten.
	isDup := fromPIdx != p.PartyID().Index
	dupErr := func() (bool, *tss.Error) {
		return false, p.WrapError(
			fmt.Errorf("%w: %T from party %d", tss.ErrDuplicateMessage, msg.Content(), fromPIdx),
			msg.GetFrom())
	}
	switch msg.Content().(type) {
	case *SignRound1Message1:
		if isDup && p.temp.signRound1Message1s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.signRound1Message1s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.signRound1Message1s[fromPIdx] = msg
	case *SignRound1Message2:
		if isDup && p.temp.signRound1Message2s[fromPIdx] != nil && !tss.IsSameMessage(p.temp.signRound1Message2s[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.signRound1Message2s[fromPIdx] = msg
	case *SignRound2Message:
		if isDup && p.temp.signRound2Messages[fromPIdx] != nil && !tss.IsSameMessage(p.temp.signRound2Messages[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.signRound2Messages[fromPIdx] = msg
	case *SignRound3Message:
		if isDup && p.temp.signRound3Messages[fromPIdx] != nil && !tss.IsSameMessage(p.temp.signRound3Messages[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.signRound3Messages[fromPIdx] = msg
	case *SignRound4Message:
		if isDup && p.temp.signRound4Messages[fromPIdx] != nil && !tss.IsSameMessage(p.temp.signRound4Messages[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.signRound4Messages[fromPIdx] = msg
	case *SignRound5Message:
		if isDup && p.temp.signRound5Messages[fromPIdx] != nil && !tss.IsSameMessage(p.temp.signRound5Messages[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.signRound5Messages[fromPIdx] = msg
	case *SignRound6Message:
		if isDup && p.temp.signRound6Messages[fromPIdx] != nil && !tss.IsSameMessage(p.temp.signRound6Messages[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.signRound6Messages[fromPIdx] = msg
	case *SignRound7Message:
		if isDup && p.temp.signRound7Messages[fromPIdx] != nil && !tss.IsSameMessage(p.temp.signRound7Messages[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.signRound7Messages[fromPIdx] = msg
	case *SignRound8Message:
		if isDup && p.temp.signRound8Messages[fromPIdx] != nil && !tss.IsSameMessage(p.temp.signRound8Messages[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.signRound8Messages[fromPIdx] = msg
	case *SignRound9Message:
		if isDup && p.temp.signRound9Messages[fromPIdx] != nil && !tss.IsSameMessage(p.temp.signRound9Messages[fromPIdx], msg) {
			return dupErr()
		}
		p.temp.signRound9Messages[fromPIdx] = msg
	default: // unrecognised message, just ignore!
		common.Logger.Warningf("unrecognised message ignored: %v", msg)
		return false, nil
	}
	return true, nil
}

func (p *LocalParty) PartyID() *tss.PartyID {
	return p.params.PartyID()
}

func (p *LocalParty) String() string {
	return fmt.Sprintf("id: %s, %s", p.PartyID(), p.BaseParty.String())
}
