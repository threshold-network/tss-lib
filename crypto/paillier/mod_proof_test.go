package paillier

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func modSetUp(t *testing.T) {
	if privateKey != nil && publicKey != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	var err error
	privateKey, publicKey, err = GenerateKeyPair(ctx, testPaillierKeyLength)
	assert.NoError(t, err)
}

func TestModProofVerify(t *testing.T) {
	modSetUp(t)
	proof := privateKey.ModProof()
	res, err := proof.ModVerify(publicKey.N)
	assert.NoError(t, err)
	assert.True(t, res, "proof verify result must be true")
}

func TestModProofSessionBinding(t *testing.T) {
	modSetUp(t)
	session := []byte("mod-proof-session-a")
	proof := privateKey.ModProof(session)

	res, err := proof.ModVerify(publicKey.N, session)
	assert.NoError(t, err)
	assert.True(t, res, "proof verify result must be true")

	res, err = proof.ModVerify(publicKey.N, []byte("mod-proof-session-b"))
	assert.Error(t, err)
	assert.False(t, res, "proof verify result must be false")

	res, err = proof.ModVerify(publicKey.N)
	assert.Error(t, err)
	assert.False(t, res, "session-bound proof must not verify without its session")
}

// TestModChallenge_SessionPath_NotTruncated pins the invariant that the
// session-tagged ModChallenge path produces challenges with the full
// ~N.BitLen() of entropy, not the 256-bit truncated form that would result
// from a single SHA512_256i_TAGGED → Mod N reduction against a 2048-bit
// Paillier N. A regression to truncation here would weaken the
// session-tagged proof to a strictly smaller challenge space than the
// legacy HashToN path it shares the verifier with.
func TestModChallenge_SessionPath_NotTruncated(t *testing.T) {
	modSetUp(t)
	N := publicKey.N
	w := big.NewInt(7)
	session := []byte("mod-challenge-bitwidth-pin")

	y := ModChallenge(N, w, session)

	// For uniform y_i in [0, N) with N.BitLen() ≈ 2048, the probability that
	// y_i.BitLen() ≤ 1024 is ≈ 2^-1024. A pass here means no truncation path
	// is silently capping the challenge to 256 bits.
	bound := N.BitLen() / 2
	for i, yi := range y {
		assert.NotNil(t, yi, "y_%d must be non-nil", i)
		assert.True(t, yi.Sign() >= 0, "y_%d must be non-negative", i)
		assert.True(t, yi.Cmp(N) < 0, "y_%d must be < N", i)
		assert.True(t, yi.BitLen() > bound,
			"y_%d.BitLen()=%d must exceed %d (regression to 256-bit truncation)", i, yi.BitLen(), bound)
	}
}

// TestModChallenge_SessionPath_ChainsPreviousChallenges pins that each
// session-tagged y_i mixes y[:i] into its derivation, so a single-iteration
// collision cannot be replayed across all PARAM_M iterations.
func TestModChallenge_SessionPath_ChainsPreviousChallenges(t *testing.T) {
	modSetUp(t)
	N := publicKey.N
	w := big.NewInt(7)
	session := []byte("mod-challenge-chaining-pin")

	y := ModChallenge(N, w, session)

	for i := 1; i < PARAM_M; i++ {
		assert.NotEqual(t, y[0].Cmp(y[i]), 0,
			"y_0 and y_%d must differ — chaining of y[:i] in derivation broken", i)
	}
}

func TestModProofVerifyFail(t *testing.T) {
	modSetUp(t)
	proof := privateKey.ModProof()
	last := proof.Z[PARAM_M-1]
	last.Sub(last, big.NewInt(1))
	res, err := proof.ModVerify(publicKey.N)
	assert.Error(t, err)
	assert.False(t, res, "proof verify result must be false")
}

func TestModProofVerify_ForgedProof(t *testing.T) {
	p := big.NewInt(17) // NOT a safe prime and NOT congruent to 3 (mod 4) because 17 mod 4 = 1
	q := big.NewInt(7)  // safe prime because 2*3+1 and congruent to 3 (mod 4) because 7 mod 4 = 3
	N := new(big.Int).Mul(p, q)

	// phiN = (p-1)(q-1)
	pMinus1 := new(big.Int).Sub(p, big.NewInt(1))
	qMinus1 := new(big.Int).Sub(q, big.NewInt(1))
	phiN := new(big.Int).Mul(pMinus1, qMinus1)

	// Use w = 0 deliberately.
	w := big.NewInt(0)
	// Construct the mod challenge as usual.
	y := ModChallenge(N, w)

	var x [PARAM_M]*big.Int
	var a [PARAM_M]bool
	var b [PARAM_M]bool
	var z [PARAM_M]*big.Int

	z_0 := new(big.Int).ModInverse(N, phiN)

	for i, y_i := range y {
		// Use a_i = true, b_i = true, x_i = 0 deliberately.
		x[i] = big.NewInt(0)
		a[i] = true
		b[i] = true
		z[i] = new(big.Int).Exp(y_i, z_0, N)
	}

	forgedMoodProof := &ModProof{
		W: w,
		X: x,
		A: a,
		B: b,
		Z: z,
	}

	res, err := forgedMoodProof.ModVerify(N)
	assert.Error(t, err)
	assert.False(t, res, "proof verify result must be false")
}

func TestModSqrt(t *testing.T) {
	assert := assert.New(t)
	b := big.NewInt
	// safe prime: 7 = 2*3+1
	// safe prime: 11 = 2*5+1

	// 1*1 = 1  = 1 mod 7 = 1 mod 11
	// 2*2 = 4  = 4 mod 7 = 4 mod 11
	// 3*3 = 9  = 2 mod 7 = 9 mod 11
	// 4*4 = 16 = 2 mod 7 = 5 mod 11
	// 5*5 = 25 = 4 mod 7 = 3 mod 11
	// 6*6 = 36 = 1 mod 7 = 3 mod 11
	// 7*7 = 49           = 5 mod 11
	// 8*8 = 64           = 9 mod 11
	// 9*9 = 81           = 4 mod 11
	// 10*10 = 100        = 1 mod 11

	// 37^2 = 1369 = 60 mod 77

	// 60^2 = 3600 = 58 mod 77
	// 37^4 = 58 mod 77

	// 59 = 3 (mod 7) which is not a residue
	// 59 = 4 (mod 11)

	assert.True(isQuadResidueModPrime(b(58), b(7)))
	assert.True(isQuadResidueModPrime(b(58), b(11)))

	assert.False(isQuadResidueModPrime(b(59), b(7)))
	assert.True(isQuadResidueModPrime(b(59), b(11)))

	assert.True(isQuadResidueModComposite(b(58), b(7), b(11)))
	assert.False(isQuadResidueModComposite(b(59), b(7), b(11)))

	assert.Equal(b(37), quadResidueModComposite(b(58), b(7), b(11), b(77), b(60)))
}
