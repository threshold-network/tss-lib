// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package dlnproof

import (
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
)

func TestLegacyChallengeMatchesHistoricalTranscript(t *testing.T) {
	values := []*big.Int{
		big.NewInt(2),
		big.NewInt(3),
		big.NewInt(5),
		big.NewInt(7),
	}

	expected := common.SHA512_256i(values...)
	actual := proofChallenge(nil, values...)
	if expected.Cmp(actual) != 0 {
		t.Fatalf("legacy challenge changed: expected %v, got %v", expected, actual)
	}
}

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

func TestDLNProofVerifyRejectsNilProofElements(t *testing.T) {
	proof := &Proof{}
	for i := 0; i < Iterations; i++ {
		proof.Alpha[i] = big.NewInt(2)
		proof.T[i] = big.NewInt(2)
	}

	badAlpha := *proof
	badAlpha.Alpha[0] = nil
	assertNotPanics(t, func() {
		if badAlpha.Verify(big.NewInt(2), big.NewInt(3), big.NewInt(23)) {
			t.Fatal("Verify must reject nil Alpha values")
		}
	})

	badT := *proof
	badT.T[0] = nil
	assertNotPanics(t, func() {
		if badT.Verify(big.NewInt(2), big.NewInt(3), big.NewInt(23)) {
			t.Fatal("Verify must reject nil T values")
		}
	})
}

func assertNotPanics(t *testing.T, f func()) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("unexpected panic: %v", r)
		}
	}()
	f()
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
