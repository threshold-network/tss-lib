//go:build ignore

// Command generate emits the checked-in Schnorr transcript vectors in the
// parent testdata directory. It deliberately derives challenges from the
// documented formulas instead of calling schnorr's private challenge helpers,
// so the fixture remains an independent oracle for those helpers.
//
// Run from the module root with:
//
//	go run ./crypto/schnorr/testdata/generate/main.go > /tmp/schnorr-vectors.json
//
// Compare the output with ../legacy_transcript_vectors.json and update that
// file only when the historical or security-v2 transcript contract changes
// intentionally. The fixed private values below are test material only.
package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
)

const (
	zkDomain  = "tss-lib.threshold.schnorr.zk|"
	zkvDomain = "tss-lib.threshold.schnorr.zkv|"
)

type point struct {
	X string `json:"x"`
	Y string `json:"y"`
}

type proof struct {
	Alpha point  `json:"alpha"`
	T     string `json:"t"`
	U     string `json:"u,omitempty"`
}

type zkVector struct {
	PrivateScalar       string `json:"private_scalar"`
	Nonce               string `json:"nonce"`
	PublicPoint         point  `json:"public_point"`
	LegacyChallenge     string `json:"legacy_challenge"`
	LegacyProof         proof  `json:"legacy_proof"`
	SecurityV2Challenge string `json:"security_v2_challenge"`
	SecurityV2Proof     proof  `json:"security_v2_proof"`
	LegacyRound4Wire    string `json:"legacy_round4_wire"`
}

type zkvVector struct {
	RScalar             string `json:"r_scalar"`
	S                   string `json:"s"`
	L                   string `json:"l"`
	NonceA              string `json:"nonce_a"`
	NonceB              string `json:"nonce_b"`
	R                   point  `json:"r"`
	V                   point  `json:"v"`
	LegacyChallenge     string `json:"legacy_challenge"`
	LegacyProof         proof  `json:"legacy_proof"`
	SecurityV2Challenge string `json:"security_v2_challenge"`
	SecurityV2Proof     proof  `json:"security_v2_proof"`
	LegacyRound6Wire    string `json:"legacy_round6_wire"`
}

type vectors struct {
	SchemaVersion int `json:"schema_version"`
	Provenance    struct {
		HistoricalModule              string `json:"historical_module"`
		HistoricalSchnorrSourceSHA256 string `json:"historical_schnorr_source_sha256"`
		RegressionBase                string `json:"regression_base"`
		RegressionSourceSHA256        string `json:"regression_source_sha256"`
		Curve                         string `json:"curve"`
		Encoding                      string `json:"encoding"`
	} `json:"provenance"`
	Session string    `json:"security_v2_session"`
	ZK      zkVector  `json:"zk"`
	ZKV     zkvVector `json:"zkv"`
}

func mustHex(value string) *big.Int {
	result, ok := new(big.Int).SetString(value, 16)
	if !ok {
		panic("invalid fixture integer: " + value)
	}
	return result
}

func hexInt(value *big.Int) string {
	return fmt.Sprintf("%064x", value)
}

func vectorPoint(value *crypto.ECPoint) point {
	return point{X: hexInt(value.X()), Y: hexInt(value.Y())}
}

func taggedChallenge(tag string, session []byte, q *big.Int, values ...*big.Int) *big.Int {
	domain := append([]byte(tag), session...)
	return common.ModReduceHash(q, common.SHA512_256i_TAGGED(domain, values...))
}

func wireHex(message tss.ParsedMessage) string {
	encoded, _, err := message.WireBytes()
	if err != nil {
		panic(err)
	}
	return hex.EncodeToString(encoded)
}

func main() {
	ec := tss.EC()
	q := ec.Params().N
	g := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)
	session := []byte("R01/security-v2/schnorr/vector/01")

	x := mustHex("1dce8d2ec6184cca4af42b3a1f62f4fe7b6dc5455c9f95e4d92cfdc2f2497a1")
	a := mustHex("5a17c9e1b4d27f86a529134976cab0d3ed21f6634bd64a4789c25f3aeb80122")
	X := crypto.ScalarBaseMult(ec, x)
	alpha := crypto.ScalarBaseMult(ec, a)
	legacyZKChallenge := common.HashToN(
		q,
		X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y(),
	)
	securityZKChallenge := taggedChallenge(
		zkDomain,
		session,
		q,
		X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y(),
	)
	legacyZKT := common.ModInt(q).Add(a, new(big.Int).Mul(legacyZKChallenge, x))
	securityZKT := common.ModInt(q).Add(a, new(big.Int).Mul(securityZKChallenge, x))
	legacyZKProof := &schnorr.ZKProof{Alpha: alpha, T: legacyZKT}

	rScalar := mustHex("3c4f5a6b7c8d9eaf102132435465768798a9bacbdcedfe0f1122334455667788")
	s := mustHex("21765a43f18ce04277b894abcdeffedcba49876543210123456789abcdef0123")
	l := mustHex("6e2c4b8a0d13579b2468ace02468ace13579bdf1029384756aabbccddeeff001")
	va := mustHex("4a4b4c4d4e4f50515253545556575859606162636465666768696a6b6c6d6e6f")
	vb := mustHex("7f6e5d4c3b2a190817263544536271809faebdccdbeaf9081726354453627180")
	R := crypto.ScalarBaseMult(ec, rScalar)
	sR := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(ec, l)
	V, err := sR.Add(lG)
	if err != nil {
		panic(err)
	}
	aR := R.ScalarMult(va)
	bG := crypto.ScalarBaseMult(ec, vb)
	vAlpha, err := aR.Add(bG)
	if err != nil {
		panic(err)
	}
	legacyZKVChallenge := common.HashToN(
		q,
		V.X(), V.Y(), R.X(), R.Y(), g.X(), g.Y(), vAlpha.X(), vAlpha.Y(),
	)
	securityZKVChallenge := taggedChallenge(
		zkvDomain,
		session,
		q,
		V.X(), V.Y(), R.X(), R.Y(), g.X(), g.Y(), vAlpha.X(), vAlpha.Y(),
	)
	legacyZKVT := common.ModInt(q).Add(va, new(big.Int).Mul(legacyZKVChallenge, s))
	legacyZKVU := common.ModInt(q).Add(vb, new(big.Int).Mul(legacyZKVChallenge, l))
	securityZKVT := common.ModInt(q).Add(va, new(big.Int).Mul(securityZKVChallenge, s))
	securityZKVU := common.ModInt(q).Add(vb, new(big.Int).Mul(securityZKVChallenge, l))
	legacyZKVProof := &schnorr.ZKVProof{Alpha: vAlpha, T: legacyZKVT, U: legacyZKVU}

	party := tss.NewPartyID("r01-vector", "r01-vector", big.NewInt(42))
	round4 := signing.NewSignRound4Message(
		party,
		commitments.HashDeCommitment{big.NewInt(11), big.NewInt(12), big.NewInt(13)},
		legacyZKProof,
	)
	round6 := signing.NewSignRound6Message(
		party,
		commitments.HashDeCommitment{
			big.NewInt(21), big.NewInt(22), big.NewInt(23), big.NewInt(24), big.NewInt(25),
		},
		legacyZKProof,
		legacyZKVProof,
	)

	fixture := vectors{SchemaVersion: 1, Session: hex.EncodeToString(session)}
	fixture.Provenance.HistoricalModule = "github.com/threshold-network/tss-lib@2e712689cfbeefede15f95a0ec7112227d86f702"
	fixture.Provenance.HistoricalSchnorrSourceSHA256 = "e96a7c9cacf18b684e1f88bc5e7c6673cd341c224ae460abe7dd77db88dd05aa"
	fixture.Provenance.RegressionBase = "github.com/threshold-network/tss-lib@d847ce0030193ccf5dbec0097571dcce5a2a5cf6"
	fixture.Provenance.RegressionSourceSHA256 = "0d1c6f095abf2e8ad8e393b7b00705f72ddd03eb1fb23aedbba1987857d2cf6d"
	fixture.Provenance.Curve = "secp256k1"
	fixture.Provenance.Encoding = "lowercase fixed-width 32-byte hexadecimal integers; deterministic protobuf Any wire bytes"
	fixture.ZK = zkVector{
		PrivateScalar:       hexInt(x),
		Nonce:               hexInt(a),
		PublicPoint:         vectorPoint(X),
		LegacyChallenge:     hexInt(legacyZKChallenge),
		LegacyProof:         proof{Alpha: vectorPoint(alpha), T: hexInt(legacyZKT)},
		SecurityV2Challenge: hexInt(securityZKChallenge),
		SecurityV2Proof:     proof{Alpha: vectorPoint(alpha), T: hexInt(securityZKT)},
		LegacyRound4Wire:    wireHex(round4),
	}
	fixture.ZKV = zkvVector{
		RScalar:             hexInt(rScalar),
		S:                   hexInt(s),
		L:                   hexInt(l),
		NonceA:              hexInt(va),
		NonceB:              hexInt(vb),
		R:                   vectorPoint(R),
		V:                   vectorPoint(V),
		LegacyChallenge:     hexInt(legacyZKVChallenge),
		LegacyProof:         proof{Alpha: vectorPoint(vAlpha), T: hexInt(legacyZKVT), U: hexInt(legacyZKVU)},
		SecurityV2Challenge: hexInt(securityZKVChallenge),
		SecurityV2Proof:     proof{Alpha: vectorPoint(vAlpha), T: hexInt(securityZKVT), U: hexInt(securityZKVU)},
		LegacyRound6Wire:    wireHex(round6),
	}

	encoder := json.NewEncoder(fmtWriter{})
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(fixture); err != nil {
		panic(err)
	}
}

// fmtWriter keeps the generator free of filesystem writes: callers decide
// where its deterministic stdout belongs.
type fmtWriter struct{}

func (fmtWriter) Write(value []byte) (int, error) {
	return fmt.Print(string(value))
}
