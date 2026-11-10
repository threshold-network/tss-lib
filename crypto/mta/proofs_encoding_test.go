// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/mta"
	"github.com/bnb-chain/tss-lib/tss"
)

func TestProofBobEncodingArity(t *testing.T) {
	parts := make([][]byte, mta.ProofBobWCBytesParts)
	for i := range parts {
		parts[i] = []byte{1}
	}
	point := crypto.ScalarBaseMult(tss.EC(), big.NewInt(1))
	parts[10], parts[11] = point.X().Bytes(), point.Y().Bytes()

	for _, count := range []int{0, 9, 10, 11, 13} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			input := append(append([][]byte(nil), parts...), []byte{1})[:count]
			proof, err := mta.ProofBobWCFromBytes(tss.EC(), input)
			assert.Error(t, err)
			assert.Nil(t, proof)
		})
	}
	for _, count := range []int{mta.ProofBobBytesParts, mta.ProofBobWCBytesParts} {
		proof, err := mta.ProofBobFromBytes(parts[:count])
		if assert.NoError(t, err) {
			encoded := proof.Bytes()
			assert.Equal(t, parts[:mta.ProofBobBytesParts], encoded[:])
		}
	}
	proof, err := mta.ProofBobWCFromBytes(tss.EC(), parts)
	if assert.NoError(t, err) {
		encoded := proof.Bytes()
		assert.Equal(t, parts, encoded[:])
	}
}

func TestProofBobBytesNilReceiver(t *testing.T) {
	for _, test := range []struct {
		name string
		call func()
	}{
		{"ProofBob.Bytes:", func() { (*mta.ProofBob)(nil).Bytes() }},
		{"ProofBobWC.Bytes:", func() { (*mta.ProofBobWC)(nil).Bytes() }},
	} {
		func() {
			defer func() {
				value := recover()
				if assert.NotNil(t, value) {
					assert.Contains(t, fmt.Sprint(value), test.name)
				}
			}()
			test.call()
		}()
	}
}
