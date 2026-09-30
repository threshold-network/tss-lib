// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/crypto/vss"
	"github.com/bnb-chain/tss-lib/tss"
)

// ----- Deterministic out-of-order readiness accumulation for round.ok -----

// keygenRound1ReadinessFixture constructs a round1 with temp arrays pre-allocated
// and ok[0]=true (self). Returns the round and party IDs.
func keygenRound1ReadinessFixture(t *testing.T, n int) (*round1, tss.SortedPartyIDs) {
	t.Helper()

	keys, pIDs, err := LoadKeygenTestFixtures(n)
	require.NoError(t, err)

	threshold := n - 1
	params := tss.NewParameters(tss.S256(), tss.NewPeerContext(pIDs), pIDs[0], n, threshold)
	params.SetProtocolMode(tss.ProtocolModeLegacy)

	// Initialize localTempData with the embedded localMessageStore
	temp := &localTempData{
		localMessageStore: localMessageStore{
			kgRound1Messages: make([]tss.ParsedMessage, n),
		},
	}
	base := &base{
		Parameters: params,
		save:       &keys[0],
		temp:       temp,
		out:        make(chan tss.Message, n),
		end:        nil,
		ok:         make([]bool, n),
		started:    true,
		number:     1,
	}
	// Mark self as ready (as round1.Start does)
	base.ok[0] = true

	return &round1{base}, pIDs
}

// buildMinimalKGRound1Message constructs a valid KGRound1Message for testing.
// Uses real fixture pre-params for cryptographic correctness.
func buildMinimalKGRound1Message(t *testing.T, from *tss.PartyID, fixtureIdx int) tss.ParsedMessage {
	t.Helper()

	// Load enough fixtures to satisfy the threshold (which is 3 for n=4)
	fixtureCount := 4 // threshold = 3, need 4 parties for VSS
	keys, pIDs, err := LoadKeygenTestFixtures(fixtureCount)
	require.NoError(t, err)
	fixture := keys[fixtureIdx]

	preParams := fixture.LocalPreParams
	require.True(t, preParams.ValidateWithProof(), "fixture must have pre-params with proof")

	// Commitment: need at least threshold+1 parties for VSS
	ec := tss.S256()
	vs, _, err := vss.Create(ec, fixtureCount-1, common.GetRandomPositiveInt(ec.Params().N), pIDs.Keys())
	require.NoError(t, err)
	pGFlat, err := crypto.FlattenECPoints(vs)
	require.NoError(t, err)
	cmt := commitments.NewHashCommitment(pGFlat...)

	// DLN proofs (legacy, no session)
	h1i, h2i, alpha, beta, p, q, NTildei :=
		preParams.H1i,
		preParams.H2i,
		preParams.Alpha,
		preParams.Beta,
		preParams.P,
		preParams.Q,
		preParams.NTildei

	dlnProof1 := dlnproof.NewDLNProof(
		h1i, h2i, alpha, p, q, NTildei,
	)
	dlnProof2 := dlnproof.NewDLNProof(
		h2i, h1i, beta, p, q, NTildei,
	)

	// Mod proofs (legacy, no session)
	modProof := preParams.PaillierSK.ModProof()
	pp := new(big.Int).Add(p, p)
	qq := new(big.Int).Add(q, q)
	phiNTilde := new(big.Int).Mul(pp, qq)
	gcdTilde := new(big.Int).GCD(nil, nil, pp, qq)
	lambdaNTilde := new(big.Int).Div(phiNTilde, gcdTilde)
	pkTilde := &paillier.PublicKey{N: NTildei}
	skTilde := &paillier.PrivateKey{PublicKey: *pkTilde, LambdaN: lambdaNTilde, PhiN: phiNTilde}
	modProofTilde := skTilde.ModProof()

	msg, err := NewKGRound1Message(
		from,
		cmt.C,
		&preParams.PaillierSK.PublicKey,
		NTildei,
		h1i,
		h2i,
		dlnProof1,
		dlnProof2,
		modProof,
		modProofTilde,
	)
	require.NoError(t, err)
	return msg
}

func TestKeygenRound1OutOfOrderReadinessAccumulation(t *testing.T) {
	n := 3 // self + 2 peers (indices 0,1,2) (need later-ready peer after earlier-incomplete)
	rnd, pIDs := keygenRound1ReadinessFixture(t, n)

	// Build real KGRound1Messages from fixtures for peers 1 and 2
	msgPeer1 := buildMinimalKGRound1Message(t, pIDs[1], 1)
	msgPeer2 := buildMinimalKGRound1Message(t, pIDs[2], 2)

	// First delivery: peer 2 (later index) complete, peer 1 (earlier index) incomplete
	rnd.temp.kgRound1Messages[2] = msgPeer2

	ret, err := rnd.Update()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	require.False(t, ret, "not all peers ready")
	require.False(t, rnd.ok[1], "peer 1 must not be ready")
	require.True(t, rnd.ok[2], "peer 2 must be recorded as ready despite peer 1 being incomplete")

	// Second delivery: now complete peer 1
	rnd.temp.kgRound1Messages[1] = msgPeer1

	ret, err = rnd.Update()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	require.True(t, ret, "all peers now ready")
	require.True(t, rnd.ok[1])
	require.True(t, rnd.ok[2])
	require.True(t, rnd.CanProceed())
}