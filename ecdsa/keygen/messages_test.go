// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package keygen

import (
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/crypto/dlnproof"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
)

func TestKGRound1MessageValidateBasicRequiresExactModulusWidth(t *testing.T) {
	msg := validKGRound1MessageForValidation()
	if !msg.ValidateBasic() {
		t.Fatal("expected baseline message to validate")
	}

	msg.PaillierN = big.NewInt(1).Bytes()
	if msg.ValidateBasic() {
		t.Fatal("expected sub-2048-bit Paillier modulus to fail validation")
	}

	msg = validKGRound1MessageForValidation()
	msg.NTilde = big.NewInt(1).Bytes()
	if msg.ValidateBasic() {
		t.Fatal("expected sub-2048-bit NTilde modulus to fail validation")
	}

	msg = validKGRound1MessageForValidation()
	msg.PaillierN = new(big.Int).Lsh(big.NewInt(1), paillierBitsLen).Bytes()
	if msg.ValidateBasic() {
		t.Fatal("expected over-2048-bit Paillier modulus to fail validation")
	}

	msg = validKGRound1MessageForValidation()
	msg.NTilde = new(big.Int).Lsh(big.NewInt(1), paillierBitsLen).Bytes()
	if msg.ValidateBasic() {
		t.Fatal("expected over-2048-bit NTilde modulus to fail validation")
	}

	// 2^(paillierBitsLen-1) - 1 has BitLen == paillierBitsLen - 1 (2047), which
	// is the just-below boundary that a `<= paillierBitsLen` mutation of
	// hasBitLen would silently let through.
	belowByOne := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), paillierBitsLen-1), big.NewInt(1)).Bytes()

	msg = validKGRound1MessageForValidation()
	msg.PaillierN = belowByOne
	if msg.ValidateBasic() {
		t.Fatal("expected 2047-bit Paillier modulus to fail validation")
	}

	msg = validKGRound1MessageForValidation()
	msg.NTilde = belowByOne
	if msg.ValidateBasic() {
		t.Fatal("expected 2047-bit NTilde modulus to fail validation")
	}
}

func validKGRound1MessageForValidation() *KGRound1Message {
	largeModulus := new(big.Int).Lsh(big.NewInt(1), paillierBitsLen-1).Bytes()

	return &KGRound1Message{
		Commitment:    []byte{1},
		PaillierN:     largeModulus,
		NTilde:        largeModulus,
		H1:            []byte{2},
		H2:            []byte{3},
		Dlnproof_1:    validDLNProofForValidation(),
		Dlnproof_2:    validDLNProofForValidation(),
		Modproof:      validModProofForValidation(),
		ModproofTilde: validModProofForValidation(),
	}
}

func validDLNProofForValidation() *KGRound1Message_DLNProof {
	alpha := make([][]byte, dlnproof.Iterations)
	t := make([][]byte, dlnproof.Iterations)
	for i := range alpha {
		alpha[i] = []byte{1}
		t[i] = []byte{1}
	}
	return &KGRound1Message_DLNProof{Alpha: alpha, T: t}
}

func validModProofForValidation() *KGRound1Message_ModProof {
	x := make([][]byte, paillier.PARAM_M)
	a := make([]bool, paillier.PARAM_M)
	b := make([]bool, paillier.PARAM_M)
	z := make([][]byte, paillier.PARAM_M)
	for i := range x {
		x[i] = []byte{1}
		z[i] = []byte{1}
	}
	return &KGRound1Message_ModProof{
		W: []byte{1},
		X: x,
		A: a,
		B: b,
		Z: z,
	}
}

// validFactorProofForValidation builds a KGRound2Message1_FactorProof whose
// every sub-field is the same 1-byte signed marshal (0x00, 0x01 -> +1) so the
// factor-proof decoders round-trip to deterministic big.Int values without
// keygen.
func validFactorProofForValidation() *KGRound2Message1_FactorProof {
	p := []byte{0x00, 0x01}
	return &KGRound2Message1_FactorProof{
		P:     p,
		Q:     p,
		A:     p,
		B:     p,
		T:     p,
		Sigma: p,
		Z1:    p,
		Z2:    p,
		W1:    p,
		W2:    p,
		V:     p,
	}
}

// TestKGRound3UnmarshalProofIntsArity pins the strict-arity contract of
// KGRound3Message.UnmarshalProofInts: exactly paillier.ProofIters non-empty
// parts decode, while any shortage, surplus, or empty part returns an error
// instead of panicking on an out-of-range index.
func TestKGRound3UnmarshalProofIntsArity(t *testing.T) {
	valid := make([][]byte, paillier.ProofIters)
	for i := range valid {
		valid[i] = []byte{1}
	}

	proof, err := (&KGRound3Message{PaillierProof: valid}).UnmarshalProofInts()
	if err != nil {
		t.Fatalf("expected exact-arity proof to decode, got err=%v", err)
	}
	if len(proof) != paillier.ProofIters {
		t.Fatalf("expected %d proof ints, got %d", paillier.ProofIters, len(proof))
	}
	for i, p := range proof {
		if p.Cmp(big.NewInt(1)) != 0 {
			t.Fatalf("expected decoded part %d to equal 1, got %v", i, p)
		}
	}

	// Any shortage of parts must error, not panic.
	for count := 0; count < paillier.ProofIters; count++ {
		_, err := (&KGRound3Message{PaillierProof: valid[:count]}).UnmarshalProofInts()
		if err == nil {
			t.Fatalf("expected short %d-part proof to be rejected", count)
		}
	}

	// A surplus of parts must also be rejected.
	long := append(append([][]byte(nil), valid...), []byte{1})
	if _, err := (&KGRound3Message{PaillierProof: long}).UnmarshalProofInts(); err == nil {
		t.Fatalf("expected extra 14th part to be rejected")
	}

	// An empty part must also be rejected.
	withEmpty := make([][]byte, paillier.ProofIters)
	for i := range withEmpty {
		withEmpty[i] = []byte{1}
	}
	withEmpty[5] = []byte{}
	if _, err := (&KGRound3Message{PaillierProof: withEmpty}).UnmarshalProofInts(); err == nil {
		t.Fatalf("expected empty part 5 to be rejected")
	}
}

// TestKGRound2UnmarshalFactorProofNil pins that the KGRound2Message1
// factor-proof decoders fail loudly on a missing sub-message instead of
// panicking on the nil dereference, and that a fully populated proof still
// round-trips.
func TestKGRound2UnmarshalFactorProofNil(t *testing.T) {
	msg := &KGRound2Message1{Share: []byte{1}}

	proof, err := msg.UnmarshalFactorProof()
	if err == nil {
		t.Fatal("expected nil Facproof to be rejected")
	}
	if proof != nil {
		t.Fatal("expected nil FactorProof on error")
	}

	proofTilde, err := msg.UnmarshalFactorProofTilde()
	if err == nil {
		t.Fatal("expected nil FacproofTilde to be rejected")
	}
	if proofTilde != nil {
		t.Fatal("expected nil FactorProof on error")
	}

	// One-sided nil plus a valid positive round-trip.
	msg.Facproof = validFactorProofForValidation()
	proof, err = msg.UnmarshalFactorProof()
	if err != nil {
		t.Fatalf("expected valid Facproof to decode, got err=%v", err)
	}
	if proof.P.Cmp(big.NewInt(1)) != 0 || proof.Sigma.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("expected all factor proof values to be 1, got P=%v Sigma=%v", proof.P, proof.Sigma)
	}
	if _, err = msg.UnmarshalFactorProofTilde(); err == nil {
		t.Fatalf("expected nil FacproofTilde to be rejected")
	}

	// Symmetric positive round-trip once FacproofTilde is also populated.
	msg.FacproofTilde = validFactorProofForValidation()
	proofTilde, err = msg.UnmarshalFactorProofTilde()
	if err != nil {
		t.Fatalf("expected valid FacproofTilde to decode, got err=%v", err)
	}
	if proofTilde.P.Cmp(big.NewInt(1)) != 0 || proofTilde.Sigma.Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("expected all factor proof values to be 1, got P=%v Sigma=%v", proofTilde.P, proofTilde.Sigma)
	}
}
