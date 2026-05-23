// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common_test

import (
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
)

func TestSHA512_256iTaggedDomainSeparation(t *testing.T) {
	in := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}

	tagA := common.SHA512_256i_TAGGED([]byte("tag-a"), in...)
	tagAAgain := common.SHA512_256i_TAGGED([]byte("tag-a"), in...)
	tagB := common.SHA512_256i_TAGGED([]byte("tag-b"), in...)

	if tagA.Cmp(tagAAgain) != 0 {
		t.Fatal("same tag and inputs must hash deterministically")
	}
	if tagA.Cmp(tagB) == 0 {
		t.Fatal("different tags must produce different hashes")
	}
}

func TestSHA512_256iTaggedLengthDelimitsInputs(t *testing.T) {
	left := common.SHA512_256i_TAGGED([]byte("tag"), big.NewInt(1), big.NewInt(0x0203))
	right := common.SHA512_256i_TAGGED([]byte("tag"), big.NewInt(0x0102), big.NewInt(3))

	if left.Cmp(right) == 0 {
		t.Fatal("tagged hash must length-delimit adjacent inputs")
	}
}

func TestSHA512_256iTaggedNilAndEmptyTagMatch(t *testing.T) {
	nilTag := common.SHA512_256i_TAGGED(nil, big.NewInt(1))
	emptyTag := common.SHA512_256i_TAGGED([]byte{}, big.NewInt(1))

	if nilTag.Cmp(emptyTag) != 0 {
		t.Fatal("nil and empty tags should preserve the legacy untagged domain")
	}
}

func TestHashToNTaggedUsesFullModulusWidth(t *testing.T) {
	N := new(big.Int).Lsh(big.NewInt(1), 2048)
	N.Sub(N, big.NewInt(159))

	got := common.HashToNTagged([]byte("large-modulus-tag"), N, big.NewInt(1), big.NewInt(2))
	if got.Sign() < 0 || got.Cmp(N) >= 0 {
		t.Fatal("HashToNTagged must return a value in [0, N)")
	}
	if got.BitLen() <= 256 {
		t.Fatalf("HashToNTagged appears truncated to one hash block: bitlen=%d", got.BitLen())
	}
}
