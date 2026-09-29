// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package tss_test

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
	"google.golang.org/protobuf/proto"
)

// These bytes were captured with protobuf v1.27.1 on commit 86bd1a3. Cover
// each generated schema so runtime upgrades preserve the existing encoding.
func TestProtobufBinaryCompatibility(t *testing.T) {
	sender := tss.NewPartyID("alice", "A", big.NewInt(1))
	message := signing.NewSignRound3Message(sender, big.NewInt(42))
	for _, tc := range []struct {
		name    string
		message proto.Message
		encoded string
	}{
		{"signature", &common.SignatureData{Signature: []byte{1, 2}, SignatureRecovery: []byte{0}, R: []byte{3}, S: []byte{4}, M: []byte{0, 5}}, "0a0201021201001a01032201042a020005"},
		{"keygen", &keygen.KGRound2Message2{DeCommitment: [][]byte{{1}, {2, 3}}}, "0a01010a020203"},
		{"signing", message.Content(), "0a012a"},
		{"wrapper", message.WireMsg(), "08011a0d0a05616c6963651201411a010152490a42747970652e676f6f676c65617069732e636f6d2f62696e616e63652e7473736c69622e65636473612e7369676e696e672e5369676e526f756e64334d65737361676512030a012a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			want, err := hex.DecodeString(tc.encoded)
			if err != nil {
				t.Fatal(err)
			}
			got, err := (proto.MarshalOptions{Deterministic: true}).Marshal(tc.message)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("encoding changed: got %x, want %x", got, want)
			}
			decoded := tc.message.ProtoReflect().Type().New().Interface()
			if err := proto.Unmarshal(want, decoded); err != nil {
				t.Fatal(err)
			}
			if !proto.Equal(decoded, tc.message) {
				t.Fatal("historical bytes decoded to a different message")
			}
		})
	}
}

func TestProtobufWireCompatibility(t *testing.T) {
	// The actual transport carries the inner Any, including its type URL.
	want, err := hex.DecodeString("0a42747970652e676f6f676c65617069732e636f6d2f62696e616e63652e7473736c69622e65636473612e7369676e696e672e5369676e526f756e64334d65737361676512030a012a")
	if err != nil {
		t.Fatal(err)
	}
	sender := tss.NewPartyID("alice", "A", big.NewInt(1))
	sender.Index = 0
	message := signing.NewSignRound3Message(sender, big.NewInt(42))
	wire, routing, err := message.WireBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, want) || routing.From != sender || !routing.IsBroadcast {
		t.Fatal("wire encoding or routing changed")
	}
	parsed, err := tss.ParseWireMessage(want, sender, true)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.ValidateBasic() || !tss.IsSameMessage(message, parsed) {
		t.Fatal("historical wire message did not retain its content and routing")
	}
	roundtrip, _, err := parsed.WireBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(roundtrip, want) {
		t.Fatal("historical wire bytes changed after parsing")
	}
}
