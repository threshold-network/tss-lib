package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"runtime"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/crypto/mta"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/crypto/vss"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
)

type deterministicReader struct {
	seed    []byte
	counter uint64
	buffer  []byte
}

func (r *deterministicReader) Read(output []byte) (int, error) {
	total := len(output)
	for len(output) > 0 {
		if len(r.buffer) == 0 {
			counter := make([]byte, 8)
			binary.BigEndian.PutUint64(counter, r.counter)
			digest := sha512.Sum512(append(append([]byte{}, r.seed...), counter...))
			r.buffer = digest[:]
			r.counter++
		}
		copied := copy(output, r.buffer)
		output = output[copied:]
		r.buffer = r.buffer[copied:]
	}
	return total, nil
}

func fixedRandom(label string) {
	cryptorand.Reader = &deterministicReader{seed: []byte("R01/" + label)}
}

func h(value *big.Int) string {
	if value == nil {
		return ""
	}
	return value.Text(16)
}

func hs(values []*big.Int) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = h(value)
	}
	return result
}

func bhs(values [][]byte) []string {
	result := make([]string, len(values))
	for i, value := range values {
		result[i] = hex.EncodeToString(value)
	}
	return result
}

func bools(values []bool) []bool { return append([]bool(nil), values...) }

func wire(message tss.ParsedMessage) string {
	value := wireBytes(message)
	return hex.EncodeToString(value)
}

func wireBytes(message tss.ParsedMessage) []byte {
	value, _, err := message.WireBytes()
	if err != nil {
		panic(err)
	}
	return value
}

func encrypt(pk *paillier.PublicKey, message, randomness *big.Int) *big.Int {
	mod := common.ModInt(pk.NSquare())
	return mod.Mul(
		mod.Exp(pk.Gamma(), message),
		mod.Exp(randomness, pk.N),
	)
}

type proofRecord struct {
	Inputs  map[string]string `json:"inputs"`
	Alpha   []string          `json:"alpha"`
	T       []string          `json:"t"`
	Proof   []string          `json:"proof"`
	WCProof []string          `json:"wc_proof"`
	W       string            `json:"w"`
	X       []string          `json:"x"`
	A       []bool            `json:"a"`
	B       []bool            `json:"b"`
	Z       []string          `json:"z"`
	Wire    string            `json:"wire"`
}

type vectorDocument struct {
	DLN    proofRecord `json:"dln"`
	Range  proofRecord `json:"range"`
	Bob    proofRecord `json:"bob"`
	Mod    proofRecord `json:"mod"`
	Factor proofRecord `json:"factor"`
}

func parseHex(value string) *big.Int {
	result, ok := new(big.Int).SetString(value, 16)
	if !ok {
		panic("invalid hex integer")
	}
	return result
}

func parseHexes(values []string) []*big.Int {
	result := make([]*big.Int, len(values))
	for i, value := range values {
		result[i] = parseHex(value)
	}
	return result
}

func parseBytes(values []string) [][]byte {
	result := make([][]byte, len(values))
	for i, value := range values {
		decoded, err := hex.DecodeString(value)
		if err != nil {
			panic(err)
		}
		result[i] = decoded
	}
	return result
}

func verifyDocument(path string) {
	raw, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var document vectorDocument
	if err := json.Unmarshal(raw, &document); err != nil {
		panic(err)
	}
	_, partyIDs, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil {
		panic(err)
	}

	dlnAlpha := parseHexes(document.DLN.Alpha)
	dlnT := parseHexes(document.DLN.T)
	dln, err := dlnproof.UnmarshalDLNProof(
		common.BigIntsToBytes(dlnAlpha),
		common.BigIntsToBytes(dlnT),
	)
	if err != nil {
		panic(err)
	}
	dlnOK := dln.Verify(
		parseHex(document.DLN.Inputs["h1"]),
		parseHex(document.DLN.Inputs["h2"]),
		parseHex(document.DLN.Inputs["n"]),
	)

	rangeProof, err := mta.RangeProofAliceFromBytes(parseBytes(document.Range.Proof))
	if err != nil {
		panic(err)
	}
	rangePK := &paillier.PublicKey{N: parseHex(document.Range.Inputs["pk_n"])}
	rangeOK := rangeProof.Verify(
		tss.EC(),
		rangePK,
		parseHex(document.Range.Inputs["n_tilde"]),
		parseHex(document.Range.Inputs["h1"]),
		parseHex(document.Range.Inputs["h2"]),
		parseHex(document.Range.Inputs["c"]),
	)
	rangeWireOK := wire(signing.NewSignRound1Message1(
		partyIDs[1],
		partyIDs[0],
		parseHex(document.Range.Inputs["c"]),
		rangeProof,
	)) == document.Range.Wire

	bob, err := mta.ProofBobFromBytes(parseBytes(document.Bob.Proof))
	if err != nil {
		panic(err)
	}
	bobWC, err := mta.ProofBobWCFromBytes(tss.EC(), parseBytes(document.Bob.WCProof))
	if err != nil {
		panic(err)
	}
	bobPK := &paillier.PublicKey{N: parseHex(document.Bob.Inputs["pk_n"])}
	bobArgs := []*big.Int{
		parseHex(document.Bob.Inputs["n_tilde"]),
		parseHex(document.Bob.Inputs["h1"]),
		parseHex(document.Bob.Inputs["h2"]),
		parseHex(document.Bob.Inputs["c1"]),
		parseHex(document.Bob.Inputs["c2"]),
	}
	bobOK := bob.Verify(tss.EC(), bobPK, bobArgs[0], bobArgs[1], bobArgs[2], bobArgs[3], bobArgs[4])
	bobX := crypto.ScalarBaseMult(tss.EC(), parseHex(document.Bob.Inputs["x"]))
	bobWCOK := bobWC.Verify(tss.EC(), bobPK, bobArgs[0], bobArgs[1], bobArgs[2], bobArgs[3], bobArgs[4], bobX)
	bobWireOK := wire(signing.NewSignRound2Message(
		partyIDs[1],
		partyIDs[0],
		bobArgs[3],
		bob,
		bobArgs[4],
		bobWC,
	)) == document.Bob.Wire

	modX := parseHexes(document.Mod.X)
	modZ := parseHexes(document.Mod.Z)
	modProof, err := paillier.UnmarshalModProof(
		parseHex(document.Mod.W).Bytes(),
		common.BigIntsToBytes(modX),
		document.Mod.A,
		document.Mod.B,
		common.BigIntsToBytes(modZ),
	)
	if err != nil {
		panic(err)
	}
	modOK, modErr := modProof.ModVerify(parseHex(document.Mod.Inputs["n"]))

	factorValues := parseHexes(document.Factor.Proof)
	factorProof := paillier.FactorProof{
		P: factorValues[0], Q: factorValues[1], A: factorValues[2],
		B: factorValues[3], T: factorValues[4], Sigma: factorValues[5],
		Z1: factorValues[6], Z2: factorValues[7], W1: factorValues[8],
		W2: factorValues[9], V: factorValues[10],
	}
	factorOK, factorErr := factorProof.FactorVerify(
		parseHex(document.Factor.Inputs["pk_n"]),
		parseHex(document.Factor.Inputs["n"]),
		parseHex(document.Factor.Inputs["s"]),
		parseHex(document.Factor.Inputs["t"]),
	)
	factorWireOK := wire(keygen.NewKGRound2Message1(
		partyIDs[1],
		partyIDs[0],
		&vss.Share{Threshold: 1, ID: big.NewInt(1), Share: big.NewInt(2)},
		&factorProof,
		&factorProof,
	)) == document.Factor.Wire

	fmt.Printf(
		"dln=%t range=%t range_wire=%t bob=%t bob_wc=%t bob_wire=%t mod=%t mod_err=%v factor=%t factor_wire=%t factor_err=%v\n",
		dlnOK, rangeOK, rangeWireOK, bobOK, bobWCOK, bobWireOK,
		modOK, modErr, factorOK, factorWireOK, factorErr,
	)
	if !dlnOK || !rangeOK || !rangeWireOK || !bobOK || !bobWCOK ||
		!bobWireOK || !modOK || modErr != nil || !factorOK ||
		!factorWireOK || factorErr != nil {
		os.Exit(1)
	}
}

// compareDocuments proves the byte-compatibility statement the two checked-in
// vectors are intended to make. Provenance differs by construction; every
// other JSON value — fixed public input, challenge, proof scalar, and wire
// message — must have the same canonical encoding.
func compareDocuments(priorPath, r1Path string) {
	canonical := func(path string) []byte {
		raw, err := os.ReadFile(path)
		if err != nil {
			panic(err)
		}

		var document map[string]json.RawMessage
		if err := json.Unmarshal(raw, &document); err != nil {
			panic(err)
		}
		delete(document, "provenance")

		encoded, err := json.Marshal(document)
		if err != nil {
			panic(err)
		}
		return encoded
	}

	if !bytes.Equal(canonical(priorPath), canonical(r1Path)) {
		fmt.Fprintln(os.Stderr, "PRIOR and R1 legacy vectors differ outside provenance")
		os.Exit(1)
	}
	fmt.Println("canonical_legacy_vectors_equal=true")
}

func main() {
	if len(os.Args) == 2 {
		verifyDocument(os.Args[1])
		return
	}
	if len(os.Args) == 3 {
		compareDocuments(os.Args[1], os.Args[2])
		return
	}
	originalRandom := cryptorand.Reader
	defer func() { cryptorand.Reader = originalRandom }()

	keys, partyIDs, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil {
		panic(err)
	}
	owner := keys[0]
	aux := keys[1]
	ec := tss.EC()
	q := ec.Params().N
	pk := &owner.PaillierSK.PublicKey

	output := map[string]any{
		"schema_version": 1,
		"curve":          "secp256k1",
		"provenance": map[string]any{
			"source_basis":        os.Getenv("TSS_VECTOR_SOURCE_BASIS"),
			"proof_source_sha256": os.Getenv("TSS_VECTOR_PROOF_SOURCE_SHA256"),
			"go_toolchain":        runtime.Version(),
			"input_fixtures": map[string]string{
				"keygen_data_0.json": os.Getenv("TSS_VECTOR_INPUT_0_SHA256"),
				"keygen_data_1.json": os.Getenv("TSS_VECTOR_INPUT_1_SHA256"),
			},
			"random_stream": "SHA-512 blocks over UTF-8 'R01/' + proof label + uint64 big-endian counter; crypto/rand.Reader is replaced only in this generator",
		},
	}

	fixedRandom("dln")
	dln := dlnproof.NewDLNProof(
		owner.H1i,
		owner.H2i,
		owner.Alpha,
		owner.P,
		owner.Q,
		owner.NTildei,
	)
	if !dln.Verify(owner.H1i, owner.H2i, owner.NTildei) {
		panic("dln proof did not verify")
	}
	dlnInputs := append(
		[]*big.Int{owner.H1i, owner.H2i, owner.NTildei},
		dln.Alpha[:]...,
	)
	output["dln"] = map[string]any{
		"inputs": map[string]string{
			"h1": h(owner.H1i), "h2": h(owner.H2i), "x": h(owner.Alpha),
			"p": h(owner.P), "q": h(owner.Q), "n": h(owner.NTildei),
		},
		"challenge": h(common.SHA512_256i(dlnInputs...)),
		"alpha":     hs(dln.Alpha[:]),
		"t":         hs(dln.T[:]),
	}

	m := big.NewInt(5)
	rangeR := big.NewInt(3)
	c := encrypt(pk, m, rangeR)
	fixedRandom("range")
	rangeProof, err := mta.ProveRangeAlice(
		ec, pk, c, aux.NTildei, aux.H1i, aux.H2i, m, rangeR,
	)
	if err != nil || !rangeProof.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c) {
		panic(fmt.Sprintf("range proof failed: %v", err))
	}
	rangeBytes := rangeProof.Bytes()
	rangeMessage := signing.NewSignRound1Message1(partyIDs[1], partyIDs[0], c, rangeProof)
	output["range"] = map[string]any{
		"inputs": map[string]string{
			"pk_n": h(pk.N), "n_tilde": h(aux.NTildei), "h1": h(aux.H1i),
			"h2": h(aux.H2i), "m": h(m), "r": h(rangeR), "c": h(c),
		},
		"challenge": h(common.HashToN(q, append(pk.AsInts(), c, rangeProof.Z, rangeProof.U, rangeProof.W)...)),
		"proof":     bhs(rangeBytes[:]),
		"wire":      wire(rangeMessage),
	}

	x := big.NewInt(7)
	y := big.NewInt(11)
	bobR := big.NewInt(2)
	c1 := c
	modNSquared := common.ModInt(pk.NSquare())
	c2 := modNSquared.Mul(
		modNSquared.Exp(c1, x),
		modNSquared.Mul(
			modNSquared.Exp(pk.Gamma(), y),
			modNSquared.Exp(bobR, pk.N),
		),
	)
	fixedRandom("bob")
	bob, err := mta.ProveBob(
		ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, x, y, bobR,
	)
	if err != nil || !bob.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2) {
		panic(fmt.Sprintf("bob proof failed: %v", err))
	}
	fixedRandom("bob-wc")
	X := crypto.ScalarBaseMult(ec, x)
	bobWC, err := mta.ProveBobWC(
		ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, x, y, bobR, X,
	)
	if err != nil || !bobWC.Verify(ec, pk, aux.NTildei, aux.H1i, aux.H2i, c1, c2, X) {
		panic(fmt.Sprintf("bob-wc proof failed: %v", err))
	}
	bobBytes := bob.Bytes()
	bobWCBytes := bobWC.Bytes()
	bobMessage := signing.NewSignRound2Message(
		partyIDs[1], partyIDs[0], c1, bob, c2, bobWC,
	)
	bobChallenge := common.HashToN(
		q,
		append(pk.AsInts(), c1, c2, bob.Z, bob.ZPrm, bob.T, bob.V, bob.W)...,
	)
	bobWCChallenge := common.HashToN(
		q,
		append(
			pk.AsInts(),
			X.X(), X.Y(), c1, c2, bobWC.U.X(), bobWC.U.Y(), bobWC.Z,
			bobWC.ZPrm, bobWC.T, bobWC.V, bobWC.W,
		)...,
	)
	output["bob"] = map[string]any{
		"inputs": map[string]string{
			"pk_n": h(pk.N), "n_tilde": h(aux.NTildei), "h1": h(aux.H1i),
			"h2": h(aux.H2i), "c1": h(c1), "c2": h(c2), "x": h(x),
			"y": h(y), "r": h(bobR),
		},
		"challenge":    h(bobChallenge),
		"proof":        bhs(bobBytes[:]),
		"wc_x":         []string{h(X.X()), h(X.Y())},
		"wc_challenge": h(bobWCChallenge),
		"wc_proof":     bhs(bobWCBytes[:]),
		"wire":         wire(bobMessage),
	}

	fixedRandom("mod")
	modProof := owner.PaillierSK.ModProof()
	if ok, err := modProof.ModVerify(pk.N); err != nil || !ok {
		panic(fmt.Sprintf("mod proof failed: %v", err))
	}
	modChallenges := paillier.ModChallenge(pk.N, modProof.W)
	output["mod"] = map[string]any{
		"inputs":    map[string]string{"n": h(pk.N)},
		"w":         h(modProof.W),
		"challenge": hs(modChallenges[:]),
		"x":         hs(modProof.X[:]),
		"a":         bools(modProof.A[:]),
		"b":         bools(modProof.B[:]),
		"z":         hs(modProof.Z[:]),
	}

	fixedRandom("factor")
	factorProof := owner.PaillierSK.FactorProof(aux.NTildei, aux.H1i, aux.H2i)
	if ok, err := factorProof.FactorVerify(pk.N, aux.NTildei, aux.H1i, aux.H2i); err != nil || !ok {
		panic(fmt.Sprintf("factor proof failed: %v", err))
	}
	factorChallenge := paillier.FactorChallenge(
		aux.NTildei, aux.H1i, aux.H2i, pk.N,
		factorProof.P, factorProof.Q, factorProof.A, factorProof.B,
		factorProof.T, factorProof.Sigma,
	)
	factorMessage := keygen.NewKGRound2Message1(
		partyIDs[1],
		partyIDs[0],
		&vss.Share{Threshold: 1, ID: big.NewInt(1), Share: big.NewInt(2)},
		factorProof,
		factorProof,
	)
	output["factor"] = map[string]any{
		"inputs": map[string]string{
			"pk_n": h(pk.N), "n": h(aux.NTildei), "s": h(aux.H1i), "t": h(aux.H2i),
		},
		"challenge": h(factorChallenge),
		"proof": []string{
			h(factorProof.P), h(factorProof.Q), h(factorProof.A), h(factorProof.B),
			h(factorProof.T), h(factorProof.Sigma), h(factorProof.Z1), h(factorProof.Z2),
			h(factorProof.W1), h(factorProof.W2), h(factorProof.V),
		},
		"wire": wire(factorMessage),
	}

	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		panic(err)
	}
	encoded = append(encoded, '\n')
	fmt.Print(string(encoded))
}
