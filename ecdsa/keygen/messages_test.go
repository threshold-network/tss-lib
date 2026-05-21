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

func TestKGRound1MessageValidateBasicRequiresLargeModuli(t *testing.T) {
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
