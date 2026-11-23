// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// Round 4 sums every peer's round-3 theta and inverts the total. These tests
// pin that a peer theta is accepted only in its canonical form: a value in
// [0, q) encoded in at most the curve order's byte length. Adapted from the
// upstream regression tests in BNB e47faf8.

// round4ThetaModes runs each case under both proof-transcript modes: the
// check sits before the mode-specific Schnorr proof and must behave the same
// in either.
var round4ThetaModes = []struct {
	name string
	mode tss.ProtocolMode
}{
	{"legacy", tss.ProtocolModeLegacy},
	{"security-v2", tss.ProtocolModeSecurityV2},
}

// newRound4ForThetaTest builds a two-party round 4 on honest local state and
// stores rawPeerTheta as the round-3 broadcast of the peer at index 1. Only
// the state round 4 reads is populated; this is not a full signing session.
func newRound4ForThetaTest(t *testing.T, mode tss.ProtocolMode, rawPeerTheta []byte) (*round4, tss.SortedPartyIDs) {
	t.Helper()

	pIDs := tss.GenerateTestPartyIDs(2)
	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(pIDs), pIDs[0], len(pIDs), 1)
	params.SetProtocolMode(mode)
	keys := keygen.NewLocalPartySaveData(len(pIDs))
	data := common.SignatureData{}

	q := params.EC().Params().N
	temp := localTempData{}
	temp.signRound3Messages = make([]tss.ParsedMessage, len(pIDs))
	temp.signRound4Messages = make([]tss.ParsedMessage, len(pIDs))
	temp.theta = big.NewInt(7)
	temp.gamma = common.GetRandomPositiveInt(q)
	temp.pointGamma = crypto.ScalarBaseMult(params.EC(), temp.gamma)
	temp.deCommit = commitments.NewHashCommitment(temp.pointGamma.X(), temp.pointGamma.Y()).D
	temp.ssid = []byte("round-4-theta-canonical-test")

	// Build the peer message from raw bytes so a test can supply an encoding
	// big.Int.Bytes never produces, such as a zero-padded one.
	meta := tss.MessageRouting{From: pIDs[1], IsBroadcast: true}
	content := &SignRound3Message{Theta: rawPeerTheta}
	temp.signRound3Messages[1] = tss.NewMessage(meta, content, tss.NewMessageWrapper(meta, content))

	out := make(chan tss.Message, len(pIDs))
	end := make(chan *common.SignatureData, len(pIDs))
	rnd := &round4{&round3{&round2{&round1{
		&base{params, &keys, &data, &temp, out, end, make([]bool, len(pIDs)), false, 3},
	}}}}
	return rnd, pIDs
}

// TestRound4AcceptsCanonicalTheta is the negative control: the check must be
// invisible to an honest round, including at both ends of the accepted range.
func TestRound4AcceptsCanonicalTheta(t *testing.T) {
	q := tss.S256().Params().N
	cases := []struct {
		name  string
		theta *big.Int
	}{
		{"small value", big.NewInt(5)},
		{"largest scalar q-1", new(big.Int).Sub(q, big.NewInt(1))},
	}
	for _, m := range round4ThetaModes {
		for _, c := range cases {
			t.Run(m.name+"/"+c.name, func(t *testing.T) {
				rnd, _ := newRound4ForThetaTest(t, m.mode, c.theta.Bytes())

				tssErr := rnd.Start()
				require.Nil(t, tssErr, "a canonical theta must be accepted, got %v", tssErr)

				q := rnd.Params().EC().Params().N
				sum := new(big.Int).Mod(new(big.Int).Add(big.NewInt(7), c.theta), q)
				want := new(big.Int).ModInverse(sum, q)
				require.NotNil(t, rnd.temp.thetaInverse, "the round must store an inverse")
				assert.Zero(t, rnd.temp.thetaInverse.Cmp(want), "stored inverse must be (theta_i + theta_j)^-1 mod q")
			})
		}
	}
}

// TestRound4RefusesNonCanonicalTheta pins each refused shape, with the sender
// named and no inverse stored.
func TestRound4RefusesNonCanonicalTheta(t *testing.T) {
	q := tss.S256().Params().N
	qBytes := (q.BitLen() + 7) / 8
	five := big.NewInt(5)

	cases := []struct {
		name    string
		raw     []byte
		wantErr string
	}{
		{
			// Congruent to zero, but not reduced.
			name:    "value equal to the curve order",
			raw:     q.Bytes(),
			wantErr: "theta is not a canonical scalar",
		},
		{
			// Congruent to 5: a second encoding of a scalar an honest peer
			// would send as a single byte.
			name:    "value above the curve order",
			raw:     new(big.Int).Add(q, five).Bytes(),
			wantErr: "theta is not a canonical scalar",
		},
		{
			name:    "513-byte value",
			raw:     new(big.Int).Lsh(big.NewInt(1), 4096).Bytes(),
			wantErr: "theta is longer than the curve order",
		},
		{
			// A canonical value in a longer-than-needed encoding.
			name:    "zero-padded encoding of a canonical value",
			raw:     append(bytes.Repeat([]byte{0}, qBytes), five.Bytes()...),
			wantErr: "theta is longer than the curve order",
		},
	}
	for _, m := range round4ThetaModes {
		for _, c := range cases {
			t.Run(m.name+"/"+c.name, func(t *testing.T) {
				rnd, pIDs := newRound4ForThetaTest(t, m.mode, c.raw)

				tssErr := rnd.Start()
				require.NotNil(t, tssErr, "a non-canonical theta must be refused")
				assert.Contains(t, tssErr.Cause().Error(), c.wantErr)
				require.Len(t, tssErr.Culprits(), 1, "exactly the sender must be named, got %v", tssErr.Culprits())
				assert.Equal(t, pIDs[1].Id, tssErr.Culprits()[0].Id, "the sender of the non-canonical theta must be named")
				assert.Nil(t, rnd.temp.thetaInverse, "no inverse may be stored once the round refuses")
				assert.Nil(t, rnd.temp.signRound4Messages[0], "no round-4 message may be produced once the round refuses")
			})
		}
	}
}
