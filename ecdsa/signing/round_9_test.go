// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

func TestDecommitFour(t *testing.T) {
	secrets := func(n int) []*big.Int {
		out := make([]*big.Int, n)
		for i := range out {
			out[i] = big.NewInt(int64(i + 1))
		}
		return out
	}

	t.Run("accepts exactly four secrets", func(t *testing.T) {
		cmt := commitments.NewHashCommitment(secrets(4)...)
		values, ok := decommitFour(commitments.HashCommitDecommit{C: cmt.C, D: cmt.D})
		assert.True(t, ok)
		assert.Len(t, values, 4)
	})

	// Without the length guard, an attacker can send a commitment binding to
	// more (or fewer) than four secrets and have round 9 silently take
	// values[0..3] as their attacker-chosen Uj/Tj coordinates, bypassing the
	// U==T integrity check without breaking any hash.
	t.Run("rejects three secrets", func(t *testing.T) {
		cmt := commitments.NewHashCommitment(secrets(3)...)
		_, ok := decommitFour(commitments.HashCommitDecommit{C: cmt.C, D: cmt.D})
		assert.False(t, ok)
	})

	t.Run("rejects six secrets", func(t *testing.T) {
		cmt := commitments.NewHashCommitment(secrets(6)...)
		_, ok := decommitFour(commitments.HashCommitDecommit{C: cmt.C, D: cmt.D})
		assert.False(t, ok)
	})

	t.Run("rejects mismatched commitment", func(t *testing.T) {
		cmt := commitments.NewHashCommitment(secrets(4)...)
		corrupted := new(big.Int).Add(cmt.C, big.NewInt(1))
		_, ok := decommitFour(commitments.HashCommitDecommit{C: corrupted, D: cmt.D})
		assert.False(t, ok)
	})
}

// newRound9ForTest builds a two-party round 9 with this party's contribution
// fixed to Ui = Ti = G, ready to consume a crafted commit/decommit pair from
// the peer at index 1.
func newRound9ForTest(t *testing.T) (*round9, tss.SortedPartyIDs) {
	t.Helper()

	pIDs := tss.GenerateTestPartyIDs(2)
	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(pIDs), pIDs[0], len(pIDs), 1)
	keys := keygen.NewLocalPartySaveData(len(pIDs))
	data := common.SignatureData{}
	temp := localTempData{}
	temp.signRound7Messages = make([]tss.ParsedMessage, len(pIDs))
	temp.signRound8Messages = make([]tss.ParsedMessage, len(pIDs))
	temp.signRound9Messages = make([]tss.ParsedMessage, len(pIDs))
	out := make(chan tss.Message, len(pIDs))
	end := make(chan common.SignatureData, len(pIDs))

	g := crypto.ScalarBaseMult(params.EC(), big.NewInt(1))
	temp.Ui = g
	temp.Ti = g
	temp.si = big.NewInt(1)

	rnd := &round9{&round8{&round7{&round6{&round5{&round4{&round3{&round2{&round1{
		&base{params, &keys, &data, &temp, out, end, make([]bool, len(pIDs)), false, 8},
	}}}}}}}}}
	return rnd, pIDs
}

// storePeerDecommitment commits to the four given coordinates as the peer's
// (Uj, Tj) decommitment for round 9.
func storePeerDecommitment(rnd *round9, from *tss.PartyID, values ...*big.Int) {
	cmt := commitments.NewHashCommitment(values...)
	rnd.temp.signRound7Messages[1] = NewSignRound7Message(from, cmt.C)
	rnd.temp.signRound8Messages[1] = NewSignRound8Message(from, cmt.D)
}

// TestRound9_RejectsMalformedDecommitments pins that decommitted U_j/T_j
// coordinates are validated as canonical curve points before any group
// operation, with the failure attributed to the sending party. Previously the
// raw coordinates went straight into elliptic.Curve.Add, which panics on
// off-curve points for Go's stdlib curves and yields undefined coordinates for
// btcec — and the resulting U != T abort blamed the honest reporting party.
func TestRound9_RejectsMalformedDecommitments(t *testing.T) {
	g2 := crypto.ScalarBaseMult(tss.S256(), big.NewInt(2))
	gNeg := crypto.ScalarBaseMult(tss.S256(), new(big.Int).Sub(tss.S256().Params().N, big.NewInt(1)))

	tests := []struct {
		name    string
		values  func() []*big.Int
		wantErr string
	}{
		{
			name: "off-curve Uj",
			values: func() []*big.Int {
				return []*big.Int{big.NewInt(1), big.NewInt(2), g2.X(), g2.Y()}
			},
			wantErr: "NewECPoint(bigUj)",
		},
		{
			name: "off-curve Tj",
			values: func() []*big.Int {
				return []*big.Int{g2.X(), g2.Y(), big.NewInt(3), big.NewInt(4)}
			},
			wantErr: "NewECPoint(bigTj)",
		},
		{
			// Uj = -G cancels this party's Ui = G; the sum is the point at
			// infinity, which has no affine encoding and must be rejected.
			name: "Uj sums to identity",
			values: func() []*big.Int {
				return []*big.Int{gNeg.X(), gNeg.Y(), g2.X(), g2.Y()}
			},
			wantErr: "U.Add(bigUj)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rnd, pIDs := newRound9ForTest(t)
			storePeerDecommitment(rnd, pIDs[1], tt.values()...)

			err := rnd.Start()
			if assert.NotNil(t, err, "round 9 must reject the malformed decommitment") {
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Equal(t, []*tss.PartyID{pIDs[1]}, err.Culprits(), "the sender must be attributed")
			}
		})
	}
}

// TestRound9_UTMismatchHasNoCulprit pins that a U != T abort carries no
// culprit: the mismatch proves some party misbehaved in phase 5 but does not
// identify which one, and the previous self-attribution would have misdirected
// orchestration layers that act on culprits.
func TestRound9_UTMismatchHasNoCulprit(t *testing.T) {
	rnd, pIDs := newRound9ForTest(t)
	g2 := crypto.ScalarBaseMult(tss.S256(), big.NewInt(2))
	g3 := crypto.ScalarBaseMult(tss.S256(), big.NewInt(3))
	// U = G + 2G = 3G but T = G + 3G = 4G
	storePeerDecommitment(rnd, pIDs[1], g2.X(), g2.Y(), g3.X(), g3.Y())

	err := rnd.Start()
	if assert.NotNil(t, err, "round 9 must abort on U != T") {
		assert.Contains(t, err.Error(), "U doesn't equal T")
		assert.Empty(t, err.Culprits(), "an unattributable abort must not name a culprit")
	}
}

func TestRound9_ConsistentDecommitmentsSucceed(t *testing.T) {
	rnd, pIDs := newRound9ForTest(t)
	g2 := crypto.ScalarBaseMult(tss.S256(), big.NewInt(2))
	// U = G + 2G = T
	storePeerDecommitment(rnd, pIDs[1], g2.X(), g2.Y(), g2.X(), g2.Y())

	err := rnd.Start()
	assert.Nil(t, err)
	assert.NotNil(t, rnd.temp.signRound9Messages[0], "round 9 message must be produced")
}

// TestSigning_Start_RejectsInvalidMessage pins the round-1 message validity
// check: a nil message must fail cleanly instead of panicking on Cmp, and a
// negative message must fail at Start instead of surfacing as an unattributed
// signature-verification failure in finalize.
func TestSigning_Start_RejectsInvalidMessage(t *testing.T) {
	setUp("info")
	keys, signPIDs, err := keygen.LoadKeygenTestFixturesRandomSet(testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")

	for _, msg := range []*big.Int{nil, big.NewInt(-42)} {
		p2pCtx := tss.NewPeerContext(signPIDs)
		outCh := make(chan tss.Message, len(signPIDs))
		endCh := make(chan common.SignatureData, len(signPIDs))

		params := tss.NewParameters(tss.S256(), p2pCtx, signPIDs[0], len(signPIDs), testThreshold)
		params.SetSessionNonce(big.NewInt(1))

		P := NewLocalParty(msg, params, keys[0], outCh, endCh, 32).(*LocalParty)
		tssErr := P.Start()
		if tssErr == nil {
			t.Fatalf("Start must return an error for message %v", msg)
		}
		if !strings.Contains(tssErr.Error(), "hashed message is not valid") {
			t.Fatalf("error must reject the message, got: %v", tssErr)
		}
	}
}
