// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common_test

import (
	"math/big"
	"reflect"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
)

func TestLiterallyJustMod(t *testing.T) {
	curveQ := common.GetRandomPrimeInt(256)
	randomQ := common.MustGetRandomInt(64)
	hash := common.SHA512_256iOne(big.NewInt(123))
	rs1 := common.LiterallyJustMod(curveQ, hash)
	rs2 := common.LiterallyJustMod(randomQ, hash)
	rs3 := common.LiterallyJustMod(common.MustGetRandomInt(64), hash)
	type args struct {
		q     *big.Int
		eHash *big.Int
	}
	tests := []struct {
		name       string
		args       args
		want       *big.Int
		wantBitLen int
		notEqual   bool
	}{{
		name:       "happy path with curve order",
		args:       args{curveQ, hash},
		want:       rs1,
		wantBitLen: 256,
	}, {
		name:       "happy path with random 64-bit int",
		args:       args{randomQ, hash},
		want:       rs2,
		wantBitLen: 64,
	}, {
		name:       "inequality with different input",
		args:       args{randomQ, hash},
		want:       rs3,
		wantBitLen: 64,
		notEqual:   true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := common.LiterallyJustMod(tt.args.q, tt.args.eHash)
			if !tt.notEqual && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RejectionSample() = %v, want %v", got, tt.want)
			}
			if tt.wantBitLen < got.BitLen() { // leading zeros not counted
				t.Errorf("RejectionSample() = bitlen %d, want %d", got.BitLen(), tt.wantBitLen)
			}
		})
	}
}

func TestRejectionSampleReducesModuloQ(t *testing.T) {
	q := big.NewInt(101)
	eHash := big.NewInt(12345)

	got := common.RejectionSample(q, new(big.Int).Set(eHash))
	want := new(big.Int).Mod(eHash, q)

	if got.Cmp(want) != 0 {
		t.Fatalf("RejectionSample() = %v, want %v", got, want)
	}
	if got.Sign() < 0 || got.Cmp(q) >= 0 {
		t.Fatal("RejectionSample must return a value in [0, q)")
	}
}
