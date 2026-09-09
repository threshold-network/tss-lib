package schnorr_test

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/commitments"
	"github.com/bnb-chain/tss-lib/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
)

const (
	legacyVectorPath   = "testdata/legacy_transcript_vectors.json"
	legacyVectorSHA256 = "2dec0490c875396c8161b4b5c522f8f451d6a987174194e22f6883741f6acffb"
	zkDomain           = "tss-lib.threshold.schnorr.zk|"
	zkvDomain          = "tss-lib.threshold.schnorr.zkv|"
)

type vectorPoint struct {
	X string `json:"x"`
	Y string `json:"y"`
}

type vectorProof struct {
	Alpha vectorPoint `json:"alpha"`
	T     string      `json:"t"`
	U     string      `json:"u"`
}

type legacyTranscriptVectors struct {
	SchemaVersion int `json:"schema_version"`
	Provenance    struct {
		HistoricalModule              string `json:"historical_module"`
		HistoricalSchnorrSourceSHA256 string `json:"historical_schnorr_source_sha256"`
		RegressionBase                string `json:"regression_base"`
		RegressionSourceSHA256        string `json:"regression_source_sha256"`
		Curve                         string `json:"curve"`
		Encoding                      string `json:"encoding"`
	} `json:"provenance"`
	SecurityV2Session string `json:"security_v2_session"`
	ZK                struct {
		PrivateScalar       string      `json:"private_scalar"`
		Nonce               string      `json:"nonce"`
		PublicPoint         vectorPoint `json:"public_point"`
		LegacyChallenge     string      `json:"legacy_challenge"`
		LegacyProof         vectorProof `json:"legacy_proof"`
		SecurityV2Challenge string      `json:"security_v2_challenge"`
		SecurityV2Proof     vectorProof `json:"security_v2_proof"`
		LegacyRound4Wire    string      `json:"legacy_round4_wire"`
	} `json:"zk"`
	ZKV struct {
		RScalar             string      `json:"r_scalar"`
		S                   string      `json:"s"`
		L                   string      `json:"l"`
		NonceA              string      `json:"nonce_a"`
		NonceB              string      `json:"nonce_b"`
		R                   vectorPoint `json:"r"`
		V                   vectorPoint `json:"v"`
		LegacyChallenge     string      `json:"legacy_challenge"`
		LegacyProof         vectorProof `json:"legacy_proof"`
		SecurityV2Challenge string      `json:"security_v2_challenge"`
		SecurityV2Proof     vectorProof `json:"security_v2_proof"`
		LegacyRound6Wire    string      `json:"legacy_round6_wire"`
	} `json:"zkv"`
}

func loadLegacyTranscriptVectors(t *testing.T) legacyTranscriptVectors {
	t.Helper()

	raw, err := os.ReadFile(legacyVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if got := hex.EncodeToString(digest[:]); got != legacyVectorSHA256 {
		t.Fatalf("fixture digest = %s, want %s", got, legacyVectorSHA256)
	}

	var fixture legacyTranscriptVectors
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.SchemaVersion != 1 {
		t.Fatalf("fixture schema = %d, want 1", fixture.SchemaVersion)
	}
	if fixture.Provenance.HistoricalModule !=
		"github.com/threshold-network/tss-lib@2e712689cfbeefede15f95a0ec7112227d86f702" {
		t.Fatalf("unexpected historical provenance: %s", fixture.Provenance.HistoricalModule)
	}
	if fixture.Provenance.HistoricalSchnorrSourceSHA256 !=
		"e96a7c9cacf18b684e1f88bc5e7c6673cd341c224ae460abe7dd77db88dd05aa" {
		t.Fatalf("unexpected historical source digest: %s", fixture.Provenance.HistoricalSchnorrSourceSHA256)
	}
	if fixture.Provenance.RegressionBase !=
		"github.com/threshold-network/tss-lib@d847ce0030193ccf5dbec0097571dcce5a2a5cf6" {
		t.Fatalf("unexpected regression provenance: %s", fixture.Provenance.RegressionBase)
	}
	if fixture.Provenance.RegressionSourceSHA256 !=
		"0d1c6f095abf2e8ad8e393b7b00705f72ddd03eb1fb23aedbba1987857d2cf6d" {
		t.Fatalf("unexpected regression source digest: %s", fixture.Provenance.RegressionSourceSHA256)
	}

	return fixture
}

func vectorInt(t *testing.T, value string) *big.Int {
	t.Helper()
	result, ok := new(big.Int).SetString(value, 16)
	if !ok {
		t.Fatalf("invalid vector integer %q", value)
	}
	return result
}

func pointFromVector(t *testing.T, value vectorPoint) *crypto.ECPoint {
	t.Helper()
	point, err := crypto.NewECPoint(
		tss.EC(),
		vectorInt(t, value.X),
		vectorInt(t, value.Y),
	)
	if err != nil {
		t.Fatal(err)
	}
	return point
}

func taggedChallenge(tag string, session []byte, values ...*big.Int) *big.Int {
	q := tss.EC().Params().N
	domain := append([]byte(tag), session...)
	return common.ModReduceHash(q, common.SHA512_256i_TAGGED(domain, values...))
}

// TestLegacyZKCrossVerification pins both directions against the historical
// formula. The fixture is a PRIOR-style proof built from fixed test-only x/a;
// the generated half calls the R1 public legacy API and verifies it with an
// independent copy of PRIOR's verifier formula. Running the package with
// -count=20 repeats both directions rather than using two homogeneous R1
// parties as the legacy oracle.
func TestLegacyZKCrossVerification(t *testing.T) {
	fixture := loadLegacyTranscriptVectors(t)
	ec := tss.EC()
	q := ec.Params().N
	g := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)
	x := vectorInt(t, fixture.ZK.PrivateScalar)
	X := pointFromVector(t, fixture.ZK.PublicPoint)
	alpha := pointFromVector(t, fixture.ZK.LegacyProof.Alpha)
	proof := &schnorr.ZKProof{Alpha: alpha, T: vectorInt(t, fixture.ZK.LegacyProof.T)}

	challenge := common.HashToN(
		q,
		X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y(),
	)
	if challenge.Cmp(vectorInt(t, fixture.ZK.LegacyChallenge)) != 0 {
		t.Fatalf("historical ZK challenge = %x, want %s", challenge, fixture.ZK.LegacyChallenge)
	}
	if !proof.Verify(X) {
		t.Fatal("PRIOR-generated ZK fixture did not verify with the R1 legacy API")
	}

	for i := 0; i < 20; i++ {
		generated, err := schnorr.NewZKProof(x, X)
		if err != nil {
			t.Fatal(err)
		}
		if !historicalVerifyZK(generated, X) {
			t.Fatalf("R1 legacy ZK proof %d did not verify with the historical formula", i)
		}
	}
}

func historicalVerifyZK(proof *schnorr.ZKProof, X *crypto.ECPoint) bool {
	ec := X.Curve()
	q := ec.Params().N
	g := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)
	c := common.HashToN(
		q,
		X.X(), X.Y(), g.X(), g.Y(), proof.Alpha.X(), proof.Alpha.Y(),
	)
	tG := crypto.ScalarBaseMult(ec, proof.T)
	Xc := X.ScalarMult(c)
	right, err := proof.Alpha.Add(Xc)
	return err == nil && right.Equals(tG)
}

// TestLegacyZKVCrossVerification is the ZKV counterpart of the ZK oracle
// above, including a PRIOR fixture and R1-generated proofs checked by the
// historical verifier formula.
func TestLegacyZKVCrossVerification(t *testing.T) {
	fixture := loadLegacyTranscriptVectors(t)
	ec := tss.EC()
	q := ec.Params().N
	g := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)
	R := pointFromVector(t, fixture.ZKV.R)
	V := pointFromVector(t, fixture.ZKV.V)
	s := vectorInt(t, fixture.ZKV.S)
	l := vectorInt(t, fixture.ZKV.L)
	alpha := pointFromVector(t, fixture.ZKV.LegacyProof.Alpha)
	proof := &schnorr.ZKVProof{
		Alpha: alpha,
		T:     vectorInt(t, fixture.ZKV.LegacyProof.T),
		U:     vectorInt(t, fixture.ZKV.LegacyProof.U),
	}

	challenge := common.HashToN(
		q,
		V.X(), V.Y(), R.X(), R.Y(),
		g.X(), g.Y(), alpha.X(), alpha.Y(),
	)
	if challenge.Cmp(vectorInt(t, fixture.ZKV.LegacyChallenge)) != 0 {
		t.Fatalf("historical ZKV challenge = %x, want %s", challenge, fixture.ZKV.LegacyChallenge)
	}
	if !proof.Verify(V, R) {
		t.Fatal("PRIOR-generated ZKV fixture did not verify with the R1 legacy API")
	}

	for i := 0; i < 20; i++ {
		generated, err := schnorr.NewZKVProof(V, R, s, l)
		if err != nil {
			t.Fatal(err)
		}
		if !historicalVerifyZKV(generated, V, R) {
			t.Fatalf("R1 legacy ZKV proof %d did not verify with the historical formula", i)
		}
	}
}

func historicalVerifyZKV(
	proof *schnorr.ZKVProof,
	V, R *crypto.ECPoint,
) bool {
	ec := V.Curve()
	q := ec.Params().N
	g := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)
	c := common.HashToN(
		q,
		V.X(), V.Y(), R.X(), R.Y(),
		g.X(), g.Y(), proof.Alpha.X(), proof.Alpha.Y(),
	)
	tR := R.ScalarMult(proof.T)
	uG := crypto.ScalarBaseMult(ec, proof.U)
	left, err := tR.Add(uG)
	if err != nil {
		return false
	}
	Vc := V.ScalarMult(c)
	right, err := proof.Alpha.Add(Vc)
	return err == nil && left.Equals(right)
}

// TestSecurityV2SchnorrVectorsFailClosed pins session/domain/input mutation,
// empty-session rejection, and legacy/security-v2 cross-mode rejection for
// both proof systems.
func TestSecurityV2SchnorrVectorsFailClosed(t *testing.T) {
	fixture := loadLegacyTranscriptVectors(t)
	session, err := hex.DecodeString(fixture.SecurityV2Session)
	if err != nil {
		t.Fatal(err)
	}
	ec := tss.EC()
	q := ec.Params().N
	g := crypto.NewECPointNoCurveCheck(ec, ec.Params().Gx, ec.Params().Gy)

	x := vectorInt(t, fixture.ZK.PrivateScalar)
	a := vectorInt(t, fixture.ZK.Nonce)
	X := pointFromVector(t, fixture.ZK.PublicPoint)
	alpha := pointFromVector(t, fixture.ZK.SecurityV2Proof.Alpha)
	securityZK := &schnorr.ZKProof{
		Alpha: alpha,
		T:     vectorInt(t, fixture.ZK.SecurityV2Proof.T),
	}
	legacyZK := &schnorr.ZKProof{
		Alpha: alpha,
		T:     vectorInt(t, fixture.ZK.LegacyProof.T),
	}
	zkChallenge := taggedChallenge(
		zkDomain,
		session,
		X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y(),
	)
	if zkChallenge.Cmp(vectorInt(t, fixture.ZK.SecurityV2Challenge)) != 0 {
		t.Fatalf("security-v2 ZK challenge = %x, want %s", zkChallenge, fixture.ZK.SecurityV2Challenge)
	}
	if !securityZK.VerifyWithSession(session, X) {
		t.Fatal("security-v2 ZK fixture did not verify")
	}
	if securityZK.Verify(X) || legacyZK.VerifyWithSession(session, X) {
		t.Fatal("ZK proof crossed the legacy/security-v2 mode boundary")
	}
	if _, err := schnorr.NewZKProofWithSession(nil, x, X); err == nil {
		t.Fatal("nil ZK session was accepted")
	}
	if _, err := schnorr.NewZKProofWithSession([]byte{}, x, X); err == nil {
		t.Fatal("non-nil empty ZK session was accepted")
	}
	if securityZK.VerifyWithSession(nil, X) || securityZK.VerifyWithSession([]byte{}, X) {
		t.Fatal("ZK verifier accepted an empty session")
	}
	mutatedSession := append([]byte(nil), session...)
	mutatedSession[0] ^= 0x01
	if securityZK.VerifyWithSession(mutatedSession, X) {
		t.Fatal("ZK verifier accepted a mutated session")
	}
	mutatedX := crypto.ScalarBaseMult(ec, new(big.Int).Add(x, big.NewInt(1)))
	if securityZK.VerifyWithSession(session, mutatedX) {
		t.Fatal("ZK verifier accepted a mutated public input")
	}
	wrongDomainChallenge := taggedChallenge(
		zkvDomain,
		session,
		X.X(), X.Y(), g.X(), g.Y(), alpha.X(), alpha.Y(),
	)
	wrongDomainProof := &schnorr.ZKProof{
		Alpha: alpha,
		T: common.ModInt(q).Add(
			a,
			new(big.Int).Mul(wrongDomainChallenge, x),
		),
	}
	if wrongDomainProof.VerifyWithSession(session, X) {
		t.Fatal("ZK verifier accepted a proof from the ZKV domain")
	}

	R := pointFromVector(t, fixture.ZKV.R)
	V := pointFromVector(t, fixture.ZKV.V)
	s := vectorInt(t, fixture.ZKV.S)
	l := vectorInt(t, fixture.ZKV.L)
	va := vectorInt(t, fixture.ZKV.NonceA)
	vb := vectorInt(t, fixture.ZKV.NonceB)
	vAlpha := pointFromVector(t, fixture.ZKV.SecurityV2Proof.Alpha)
	securityZKV := &schnorr.ZKVProof{
		Alpha: vAlpha,
		T:     vectorInt(t, fixture.ZKV.SecurityV2Proof.T),
		U:     vectorInt(t, fixture.ZKV.SecurityV2Proof.U),
	}
	legacyZKV := &schnorr.ZKVProof{
		Alpha: vAlpha,
		T:     vectorInt(t, fixture.ZKV.LegacyProof.T),
		U:     vectorInt(t, fixture.ZKV.LegacyProof.U),
	}
	zkvChallenge := taggedChallenge(
		zkvDomain,
		session,
		V.X(), V.Y(), R.X(), R.Y(),
		g.X(), g.Y(), vAlpha.X(), vAlpha.Y(),
	)
	if zkvChallenge.Cmp(vectorInt(t, fixture.ZKV.SecurityV2Challenge)) != 0 {
		t.Fatalf("security-v2 ZKV challenge = %x, want %s", zkvChallenge, fixture.ZKV.SecurityV2Challenge)
	}
	if !securityZKV.VerifyWithSession(session, V, R) {
		t.Fatal("security-v2 ZKV fixture did not verify")
	}
	if securityZKV.Verify(V, R) || legacyZKV.VerifyWithSession(session, V, R) {
		t.Fatal("ZKV proof crossed the legacy/security-v2 mode boundary")
	}
	if _, err := schnorr.NewZKVProofWithSession(nil, V, R, s, l); err == nil {
		t.Fatal("nil ZKV session was accepted")
	}
	if _, err := schnorr.NewZKVProofWithSession([]byte{}, V, R, s, l); err == nil {
		t.Fatal("non-nil empty ZKV session was accepted")
	}
	if securityZKV.VerifyWithSession(nil, V, R) ||
		securityZKV.VerifyWithSession([]byte{}, V, R) {
		t.Fatal("ZKV verifier accepted an empty session")
	}
	if securityZKV.VerifyWithSession(mutatedSession, V, R) {
		t.Fatal("ZKV verifier accepted a mutated session")
	}
	mutatedV := crypto.ScalarBaseMult(ec, new(big.Int).Add(s, l))
	if securityZKV.VerifyWithSession(session, mutatedV, R) {
		t.Fatal("ZKV verifier accepted a mutated public input")
	}
	wrongZKVDomainChallenge := taggedChallenge(
		zkDomain,
		session,
		V.X(), V.Y(), R.X(), R.Y(),
		g.X(), g.Y(), vAlpha.X(), vAlpha.Y(),
	)
	wrongDomainZKV := &schnorr.ZKVProof{
		Alpha: vAlpha,
		T: common.ModInt(q).Add(
			va,
			new(big.Int).Mul(wrongZKVDomainChallenge, s),
		),
		U: common.ModInt(q).Add(
			vb,
			new(big.Int).Mul(wrongZKVDomainChallenge, l),
		),
	}
	if wrongDomainZKV.VerifyWithSession(session, V, R) {
		t.Fatal("ZKV verifier accepted a proof from the ZK domain")
	}
}

// TestLegacySchnorrWireVectors pins the exact protobuf payload carrying the
// fixed PRIOR-compatible proofs through signing rounds 4 and 6. This catches a
// proof that cross-verifies mathematically but drifts on serialization.
func TestLegacySchnorrWireVectors(t *testing.T) {
	fixture := loadLegacyTranscriptVectors(t)
	party := tss.NewPartyID("r01-vector", "r01-vector", big.NewInt(42))
	zkProof := &schnorr.ZKProof{
		Alpha: pointFromVector(t, fixture.ZK.LegacyProof.Alpha),
		T:     vectorInt(t, fixture.ZK.LegacyProof.T),
	}
	zkvProof := &schnorr.ZKVProof{
		Alpha: pointFromVector(t, fixture.ZKV.LegacyProof.Alpha),
		T:     vectorInt(t, fixture.ZKV.LegacyProof.T),
		U:     vectorInt(t, fixture.ZKV.LegacyProof.U),
	}

	round4 := signing.NewSignRound4Message(
		party,
		commitments.HashDeCommitment{big.NewInt(11), big.NewInt(12), big.NewInt(13)},
		zkProof,
	)
	assertWireHex(t, round4, fixture.ZK.LegacyRound4Wire)

	round6 := signing.NewSignRound6Message(
		party,
		commitments.HashDeCommitment{
			big.NewInt(21), big.NewInt(22), big.NewInt(23), big.NewInt(24), big.NewInt(25),
		},
		zkProof,
		zkvProof,
	)
	assertWireHex(t, round6, fixture.ZKV.LegacyRound6Wire)
}

func assertWireHex(t *testing.T, message tss.ParsedMessage, expected string) {
	t.Helper()
	encoded, _, err := message.WireBytes()
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(encoded); got != expected {
		t.Fatalf("wire bytes differ\ngot:  %s\nwant: %s", got, expected)
	}
}

func TestLegacyVectorChecksumSidecar(t *testing.T) {
	raw, err := os.ReadFile(legacyVectorPath + ".sha256")
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("%s  legacy_transcript_vectors.json\n", legacyVectorSHA256)
	if string(raw) != want {
		t.Fatalf("checksum sidecar = %q, want %q", raw, want)
	}
}
