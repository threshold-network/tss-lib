package mta

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/tss"
)

// TestProversRejectEmptyPlaintextDomain pins that a Paillier modulus of N <= 1
// has no valid plaintext (nothing satisfies 0 <= v < N), so every prover
// rejects the out-of-domain witness before any randomness is sampled or
// exponentiation runs. The assertion is consumer-visible: an error plus a nil
// proof, with no reliance on the specific error string.
func TestProversRejectEmptyPlaintextDomain(t *testing.T) {
	pk := &paillier.PublicKey{N: big.NewInt(1)}
	nTilde, h1, h2 := big.NewInt(77), big.NewInt(4), big.NewInt(9)
	c, m, r := big.NewInt(1), big.NewInt(1), big.NewInt(1)

	rangeProof, err := ProveRangeAlice(tss.EC(), pk, c, nTilde, h1, h2, m, r)
	assert.Error(t, err)
	assert.Nil(t, rangeProof)

	bobProof, err := ProveBob(tss.EC(), pk, nTilde, h1, h2, c, c, m, m, r)
	assert.Error(t, err)
	assert.Nil(t, bobProof)

	bobWCProof, err := ProveBobWC(tss.EC(), pk, nTilde, h1, h2, c, c, m, m, r, nil)
	assert.Error(t, err)
	assert.Nil(t, bobWCProof)
}
