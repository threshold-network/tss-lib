// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package dlnproof

import (
	"math/big"
	"testing"
)

func TestDLNProofRejectsEmptySessionTag(t *testing.T) {
	assertPanics(t, func() {
		_ = NewDLNProof(nil, nil, nil, nil, nil, nil, []byte{})
	})
}

func TestDLNProofVerifyRejectsOverwideT(t *testing.T) {
	proof := &Proof{}
	for i := 0; i < Iterations; i++ {
		proof.Alpha[i] = big.NewInt(2)
		proof.T[i] = big.NewInt(2)
	}
	proof.T[0] = big.NewInt(25)

	if proof.Verify(big.NewInt(2), big.NewInt(3), big.NewInt(23)) {
		t.Fatal("Verify must reject T values outside [2, N)")
	}
}

func TestDLNProofVerifyRejectsOverwideAlpha(t *testing.T) {
	proof := &Proof{}
	for i := 0; i < Iterations; i++ {
		proof.Alpha[i] = big.NewInt(2)
		proof.T[i] = big.NewInt(2)
	}
	proof.Alpha[0] = big.NewInt(25)

	if proof.Verify(big.NewInt(2), big.NewInt(3), big.NewInt(23)) {
		t.Fatal("Verify must reject Alpha values outside [2, N)")
	}
}

func TestDLNProofVerifyRejectsNilInputs(t *testing.T) {
	proof := &Proof{}
	for i := 0; i < Iterations; i++ {
		proof.Alpha[i] = big.NewInt(2)
		proof.T[i] = big.NewInt(2)
	}

	if proof.Verify(nil, big.NewInt(3), big.NewInt(23)) {
		t.Fatal("Verify must reject nil h1")
	}
	if proof.Verify(big.NewInt(2), nil, big.NewInt(23)) {
		t.Fatal("Verify must reject nil h2")
	}
	if proof.Verify(big.NewInt(2), big.NewInt(3), nil) {
		t.Fatal("Verify must reject nil N")
	}
}

func assertPanics(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic")
		}
	}()
	f()
}
