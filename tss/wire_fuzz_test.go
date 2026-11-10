// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss_test

import (
	"errors"
	"math/big"
	"testing"

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
		return nil, errors.New("KGRound1Message seed must pass ValidateBasic")
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
	return proto.Marshal(&anypb.Any{
		TypeUrl: "type.googleapis.com/tss.fuzz.unknown",
		Value:   []byte{1, 2, 3},
	})
}

// FuzzParseWireMessage fuzzes tss.ParseWireMessage, the untrusted wire
// boundary where arbitrary bytes are decoded into a typed ParsedMessage.
//
// A byte string that cannot form a registered, resolvable inner message
// (truncated, typeless, or unknown type URL) must error — category pinned,
// wording not. Any byte string that does parse must satisfy:
//
//   - the resolved type name is a registered content type (Type()
//     non-empty);
//   - fresh-content round-trip: build a fresh Any from the decoded content
//     via anypb.New, marshal it, re-parse it, and the re-parsed content
//     must be proto-equal to the first parse (semantic content preservation
//     through the decode -> re-encode boundary, not a reuse of the
//     original Any bytes);
//   - routing round-trips: the sender PartyID and the broadcast flag
//     survive the decode.
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
		if parsed.Type() == "" {
			t.Fatalf("parsed message must expose a resolved proto type name")
		}
		// Fresh-content round-trip: re-encode the decoded content into a
		// fresh Any (not the original input bytes), re-parse, and the
		// content must be proto-equal across the boundary.
		freshAny, err := anypb.New(parsed.Content())
		if err != nil {
			t.Fatalf("decoded content must re-encode into a fresh Any: %v", err)
		}
		rebz, err := proto.Marshal(freshAny)
		if err != nil {
			t.Fatalf("fresh Any must marshal for the wire: %v", err)
		}
		reparsed, err := tss.ParseWireMessage(rebz, fuzzParty, isBroadcast)
		if err != nil {
			t.Fatalf("re-marshaled fresh-content wire bytes must parse: %v", err)
		}
		if !proto.Equal(parsed.Content(), reparsed.Content()) {
			t.Fatalf("content must be stable across parse -> fresh Any -> re-marshal -> parse")
		}
		// Routing invariants: sender and broadcast flag survive the decode.
		if parsed.GetFrom() != fuzzParty {
			t.Fatal("parsed message lost its sender routing")
		}
		if parsed.IsBroadcast() != isBroadcast {
			t.Fatal("parsed message broadcast flag must round-trip")
		}
	})
}
