package paillier

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/tss"
)

func TestGenerateKeyPairRejectsUnsupportedSizes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, bits := range []int{-1, 0, 1, 10, 11, 12, 13, 14, 15, 16, 17} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			sk, pk, err := GenerateKeyPair(ctx, bits, 1)
			assert.EqualError(t, err, "paillier modulus size must be at least 18 bits")
			assert.Nil(t, sk)
			assert.Nil(t, pk)
		})
	}
}

func TestGenerateKeyPairMinimumSizeReachesGenerator(t *testing.T) {
	for _, bits := range []int{18, 19} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			sk, pk, err := GenerateKeyPair(ctx, bits, 1)
			assert.Equal(t, common.ErrGeneratorCancelled, err)
			assert.Nil(t, sk)
			assert.Nil(t, pk)
		})
	}
}

func TestEncryptRejectsEmptyRandomnessDomain(t *testing.T) {
	pk := &PublicKey{N: big.NewInt(1)}
	ciphertext, randomness, err := pk.EncryptAndReturnRandomness(big.NewInt(0))
	assert.EqualError(t, err, "EncryptAndReturnRandomness: could not sample randomness")
	assert.Nil(t, ciphertext)
	assert.Nil(t, randomness)
	ciphertext, err = pk.Encrypt(big.NewInt(0))
	assert.Error(t, err)
	assert.Nil(t, ciphertext)
}

func TestGenerateXsRejectsEmptyDomain(t *testing.T) {
	pub := crypto.ScalarBaseMult(tss.EC(), big.NewInt(1))
	for _, n := range []*big.Int{nil, big.NewInt(-1), big.NewInt(0), big.NewInt(1)} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			assert.Nil(t, GenerateXs(ProofIters, big.NewInt(42), n, pub))
			sk := &PrivateKey{PublicKey: PublicKey{N: n}}
			assert.Panics(t, func() { sk.Proof(big.NewInt(42), pub) })
		})
	}
}

func TestGenerateXsModulusWidths(t *testing.T) {
	pub := crypto.ScalarBaseMult(tss.EC(), big.NewInt(1))
	for _, bits := range []uint{2, 7, 255, 256, 257, 2047, 2048, 2049} {
		t.Run(fmt.Sprint(bits), func(t *testing.T) {
			n := new(big.Int).Lsh(big.NewInt(1), bits)
			n.Sub(n, big.NewInt(1))
			xs := GenerateXs(ProofIters, big.NewInt(42), n, pub)
			assert.Len(t, xs, ProofIters)
			for _, x := range xs {
				assert.True(t, common.IsNumberInMultiplicativeGroup(n, x))
			}
			assert.Equal(t, xs, GenerateXs(ProofIters, big.NewInt(42), n, pub))
		})
	}
}

func TestGenerateXsPreserves2048BitChallenges(t *testing.T) {
	n := new(big.Int).Lsh(big.NewInt(1), 2048)
	n.Sub(n, big.NewInt(159))
	pub := crypto.ScalarBaseMult(tss.EC(), big.NewInt(1))
	xs := GenerateXs(ProofIters, big.NewInt(42), n, pub)
	h := sha256.New()
	for _, x := range xs {
		h.Write(x.FillBytes(make([]byte, 256)))
	}
	// Digest of all 13 fixed-width challenges from the unmodified generator.
	assert.Equal(t, "908da79551167de1d29f91b5d19662c1fc391fb0bd9ee37768ad00d81991cd95", fmt.Sprintf("%x", h.Sum(nil)))
}
