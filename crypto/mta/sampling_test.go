package mta

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/tss"
)

func TestProversRejectEmptyRandomnessDomain(t *testing.T) {
	pk := &paillier.PublicKey{N: big.NewInt(1)}
	nTilde, h1, h2 := big.NewInt(77), big.NewInt(4), big.NewInt(9)
	c, m, r := big.NewInt(1), big.NewInt(1), big.NewInt(1)

	rangeProof, err := ProveRangeAlice(tss.EC(), pk, c, nTilde, h1, h2, m, r)
	assert.EqualError(t, err, "ProveRangeAlice: could not sample randomness")
	assert.Nil(t, rangeProof)

	bobProof, err := ProveBob(tss.EC(), pk, nTilde, h1, h2, c, c, m, m, r)
	assert.EqualError(t, err, "ProveBob: could not sample randomness")
	assert.Nil(t, bobProof)

	bobWCProof, err := ProveBobWC(tss.EC(), pk, nTilde, h1, h2, c, c, m, m, r, nil)
	assert.EqualError(t, err, "ProveBob: could not sample randomness")
	assert.Nil(t, bobWCProof)
}
