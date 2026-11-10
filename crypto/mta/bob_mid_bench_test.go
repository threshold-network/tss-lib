// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// bobMidBenchInput holds the fixed inputs for one Bob step of the MtA share
// protocol. Alice's ciphertext and range proof are made once, outside the
// timed loop, so the benchmark measures only Bob's work.
type bobMidBenchInput struct {
	pk                *paillier.PublicKey
	b, cA             *big.Int
	NTildeA, h1A, h2A *big.Int
	NTildeB, h1B, h2B *big.Int
	pfA               *RangeProofAlice
	session           []byte
}

// setupBobMidBench loads committed fixtures, turns constant-time mode on and
// binds the proofs to a session, which is the security-v2 signing path.
func setupBobMidBench(b *testing.B) (*bobMidBenchInput, func()) {
	b.Helper()
	previousMode := common.IsConstantTimeEnabled()
	common.EnableConstantTimeOps()
	restore := func() {
		if previousMode {
			common.EnableConstantTimeOps()
		} else {
			common.DisableConstantTimeOps()
		}
	}

	_, pk, err := loadPaillierKeyFixture(0)
	if err != nil {
		restore()
		b.Fatal(err)
	}
	NTildeA, h1A, h2A, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	if err != nil {
		restore()
		b.Fatal(err)
	}
	NTildeB, h1B, h2B, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	if err != nil {
		restore()
		b.Fatal(err)
	}

	q := tss.EC().Params().N
	session := []byte("bob-mid-benchmark-session")
	a := common.GetRandomPositiveInt(q)
	cA, pfA, err := AliceInit(tss.EC(), pk, a, NTildeB, h1B, h2B, session)
	if err != nil {
		restore()
		b.Fatal(err)
	}
	in := &bobMidBenchInput{
		pk:      pk,
		b:       common.GetRandomPositiveInt(q),
		cA:      cA,
		NTildeA: NTildeA, h1A: h1A, h2A: h2A,
		NTildeB: NTildeB, h1B: h1B, h2B: h2B,
		pfA:     pfA,
		session: session,
	}
	return in, restore
}

func BenchmarkBobMid(b *testing.B) {
	in, restore := setupBobMidBench(b)
	defer restore()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, _, err := BobMid(tss.EC(), in.pk, in.pfA, in.b, in.cA,
			in.NTildeA, in.h1A, in.h2A, in.NTildeB, in.h1B, in.h2B, in.session); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBobMidWC(b *testing.B) {
	in, restore := setupBobMidBench(b)
	defer restore()
	B := crypto.ScalarBaseMult(tss.EC(), in.b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, _, _, _, err := BobMidWC(tss.EC(), in.pk, in.pfA, in.b, in.cA,
			in.NTildeA, in.h1A, in.h2A, in.NTildeB, in.h1B, in.h2B, B, in.session); err != nil {
			b.Fatal(err)
		}
	}
}
