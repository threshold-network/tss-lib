// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss_test

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/bnb-chain/tss-lib/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// capParseWireFuzz bounds the fuzz input before the protobuf runtime grows
// its repeated-field allocations, so CI fuzzing cannot amplify a blob into
// oversized arrays.
const capParseWireFuzz = 8192

// fuzzParty is the fixed deterministic sender: the fuzzed bytes are the
// untrusted boundary, the PartyID content is a trusted fixed seed.
var fuzzParty = tss.NewPartyID("fuzz", "fuzz-party", big.NewInt(1))

// validWireSeed builds a fully valid KGRound1Message wire encoding:
// deterministic 2048-bit modulus widths, exact-arity sub-proofs, no key
// generation.
func validWireSeed() ([]byte, error) {
	largeModulus := new(big.Int).Lsh(big.NewInt(1), 2047).Bytes() // 2048-bit
	dln := &keygen.KGRound1Message_DLNProof{
		Alpha: make([][]byte, dlnproof.Iterations),
		T:     make([][]byte, dlnproof.Iterations),
	}
	for i := range dln.Alpha {
		dln.Alpha[i] = []byte{1}
		dln.T[i] = []byte{1}
	}
	mod := &keygen.KGRound1Message_ModProof{
		W: []byte{1},
		X: make([][]byte, paillier.PARAM_M),
		A: make([]bool, paillier.PARAM_M),
		B: make([]bool, paillier.PARAM_M),
		Z: make([][]byte, paillier.PARAM_M),
	}
	for i := range mod.X {
		mod.X[i] = []byte{1}
		mod.Z[i] = []byte{1}
	}
	content := &keygen.KGRound1Message{
		Commitment:    []byte{7},
		PaillierN:     largeModulus,
		NTilde:        largeModulus,
		H1:            []byte{2},
		H2:            []byte{3},
		Dlnproof_1:    dln,
		Dlnproof_2:    dln,
		Modproof:      mod,
		ModproofTilde: mod,
	}
	if !content.ValidateBasic() {
		return nil, assert.AnError
	}
	meta := tss.MessageRouting{From: fuzzParty, IsBroadcast: true}
	wire := tss.NewMessageWrapper(meta, content)
	msg := tss.NewMessage(meta, content, wire)
	bz, _, err := msg.WireBytes()
	if err != nil {
		return nil, err
	}
	return bz, nil
}

// unknownTypeWireSeed builds a well-formed Any whose type URL does not
// resolve in the protobuf registry.
func unknownTypeWireSeed() ([]byte, error) {
	return (&anypb.Any{
		TypeUrl: "type.googleapis.com/tss.fuzz.unknown",
		Value:   []byte{1, 2, 3},
	}).Marshal()
}

// FuzzParseWireMessage fuzzes tss.ParseWireMessage, the untrusted wire
// boundary where arbitrary bytes are decoded into a typed ParsedMessage.
//
// Contract asserted:
//   - rejection: bytes that cannot form a registered, resolvable inner
//     message (truncated, typeless, or unknown type URL) must error —
//     category pinned, wording not;
//   - success invariants on any byte string that does parse:
//     a) the resolved type name is a registered content type (Type()
//        non-empty),
//     b) re-marshal + re-parse is stable: parsing the re-marshaled wire
//        bytes yields content that is proto-equal to the first parse
//        (semantic content preservation through the unmarshal path),
//     c) routing round-trips: the sender PartyID and the broadcast flag
//        survive the decode.
//
// The routing flag under test is derived from the input length so both
// branches are exercised without a second fuzz dimension. No key generation
// or randomness; the target is deterministic and safe under parallel fuzz
// workers.
func FuzzParseWireMessage(f *testing.F) {
	bz, err := validWireSeed()
	if err != nil {
		f.Fatalf("failed to build wire seed: %v", err)
	}
	f.Add(bz)
	// Truncated Any payload.
	f.Add(bz[:len(bz)/2])
	// Length-delimited inner value with no resolvable type URL.
	f.Add([]byte{0x0a, 0x01, 0x33})
	// Well-formed Any wrapping a type the registry does not resolve: must
	// fail on the unknown inner type, not on Any framing.
	unknownWire, err := unknownTypeWireSeed()
	if err != nil {
		f.Fatalf("failed to build unknown-type seed: %v", err)
	}
	f.Add(unknownWire)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > capParseWireFuzz {
			return
		}
		// Derive the routing flag from the input so both branches are
		// exercised without a second fuzz dimension.
		isBroadcast := len(data)%2 == 1
		parsed, err := tss.ParseWireMessage(data, fuzzParty, isBroadcast)
		if err != nil {
			return // rejection category exercised
		}
		// Type invariant: a successful parse resolved a registered
		// content type name.
		if parsed.Type() == "" {
			t.Fatalf("parsed message must expose a resolved proto type name")
		}
		// Re-parse stability: the re-marshaled wire bytes must parse again
		// with proto-equal content (field order inside the untrusted
		// input is not asserted byte-wise; semantic content is the
		// invariant).
		rebz, _, err := parsed.WireBytes()
		require.NoError(t, err, "parsed message must re-marshal for the wire")
		reparsed, err := tss.ParseWireMessage(rebz, fuzzParty, isBroadcast)
		require.NoError(t, err, "re-marshaled wire bytes must parse")
		if !proto.Equal(parsed.Content(), reparsed.Content()) {
			t.Fatalf("content must be stable across parse -> re-marshal -> parse")
		}
		// Routing invariants: sender and broadcast flag survive the decode.
		if parsed.GetFrom() != fuzzParty {
			t.Fatalf("parsed message lost its sender routing")
		}
		if parsed.IsBroadcast() != isBroadcast {
			t.Fatalf("parsed message broadcast flag must round-trip")
		}
	})
}

// TestParseWireMessageSeeds pins the success invariants and rejection
// categories on deterministic seeds (no fuzz corpus needed).
func TestParseWireMessageSeeds(t *testing.T) {
	bz, err := validWireSeed()
	require.NoError(t, err, "wire seed must build")

	parsed, err := tss.ParseWireMessage(bz, fuzzParty, true)
	require.NoError(t, err, "valid wire bytes must parse")
	assert.Equal(t, "binance.tsslib.ecdsa.keygen.KGRound1Message", parsed.Type())
	assert.Equal(t, fuzzParty, parsed.GetFrom())
	assert.True(t, parsed.IsBroadcast())
	assert.True(t, parsed.ValidateBasic(), "seed content must still validate after the round-trip")
	// Re-parse stability on the canonical seed.
	rebz, _, err := parsed.WireBytes()
	require.NoError(t, err)
	reparsed, err := tss.ParseWireMessage(rebz, fuzzParty, true)
	require.NoError(t, err)
	assert.True(t, proto.Equal(parsed.Content(), reparsed.Content()),
		"content must be stable across parse -> re-marshal -> parse")

	// Rejection: truncated Any payload.
	if _, err := tss.ParseWireMessage(bz[:len(bz)/2], fuzzParty, true); err == nil {
		t.Fatal("expected truncated wire bytes to be rejected")
	}
	// Rejection: length-delimited inner value without a resolvable type.
	if _, err := tss.ParseWireMessage([]byte{0x0a, 0x01, 0x33}, fuzzParty, false); err == nil {
		t.Fatal("expected typeless wire bytes to be rejected")
	}
	// Rejection: well-formed Any with an unregistered type URL.
	unknownWire, err := unknownTypeWireSeed()
	require.NoError(t, err)
	if _, err := tss.ParseWireMessage(unknownWire, fuzzParty, true); err == nil {
		t.Fatal("expected unregistered type URL to be rejected")
	}
}
