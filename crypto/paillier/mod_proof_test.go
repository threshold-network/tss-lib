package paillier

import (
	"context"
	"fmt"
	"math/big"

	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bnb-chain/tss-lib/common"
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

func TestModChallengeRejectsEmptySessionTag(t *testing.T) {
	assert.Panics(t, func() {
		_ = ModChallenge(big.NewInt(11), big.NewInt(2), []byte{})
	})
}

// TestModChallenge_SessionPath_NotTruncated pins the invariant that the
// session-tagged ModChallenge path produces challenges with the full
// ~N.BitLen() of entropy, not the 256-bit truncated form that would result
// from a single SHA512_256i_TAGGED → Mod N reduction against a 2048-bit
// Paillier N. A regression to truncation here would weaken the
// session-tagged proof to a strictly smaller challenge space than the
// HashToN path it shares the verifier with.
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

func TestSampleYModNDeterministicAndSupportsManyBlocks(t *testing.T) {
	// Force 257 SHA512_256 blocks, exceeding the former uint8 block-index
	// capacity that would have collided block 256 with block 0.
	N := new(big.Int).Lsh(one, 32*257*8)
	N.Sub(N, one)
	tag := []byte("sample-y-large-modulus-test")
	inputs := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}

	y1 := sampleYModN(tag, N, inputs...)
	y2 := sampleYModN(tag, N, inputs...)

	assert.Equal(t, y1, y2)
	assert.True(t, y1.Sign() >= 0)
	assert.True(t, y1.Cmp(N) < 0)
	assert.True(t, N.BitLen() > 32*256*8)
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

func TestModProofVerify_AttackMod(t *testing.T) {
	session := []byte("mod-proof-attack-session")

	P := mustSetString("11956161572522965463")
	Q := []*big.Int{
		mustSetString("2495927741"),
		mustSetString("3726287311"),
		mustSetString("3756248813"),
		mustSetString("3962607427"),
		mustSetString("2685519289"),
		mustSetString("2316427879"),
		mustSetString("3704490329"),
	}

	N := new(big.Int).Set(P)
	for _, q := range Q {
		N.Mul(N, q)
	}

	proof, err := newHackedModProof(session, N, P, Q)
	assert.NoError(t, err)

	ok, err := proof.ModVerify(N, session)
	assert.Error(t, err)
	assert.False(t, ok, "false proof should not verify")
}

func newHackedModProof(session []byte, N, P *big.Int, Q []*big.Int) (*ModProof, error) {
	phi := new(big.Int).Sub(P, one)
	bigQ := new(big.Int).Set(one)
	for _, q := range Q {
		phi.Mul(phi, new(big.Int).Sub(q, one))
		bigQ.Mul(bigQ, q)
	}

	invBigQ := new(big.Int).ModInverse(bigQ, P)
	w := new(big.Int).Mul(invBigQ, bigQ)
	if new(big.Int).Mod(w, P).Cmp(one) != 0 {
		return nil, fmt.Errorf("w is not congruent to 1 modulo p")
	}
	for _, q := range Q {
		if new(big.Int).Mod(w, q).Cmp(zero) != 0 {
			return nil, fmt.Errorf("w is not congruent to 0 modulo all q values")
		}
	}

	y := ModChallenge(N, w, session)
	invN := new(big.Int).ModInverse(N, phi)
	if invN == nil {
		return nil, fmt.Errorf("N is not invertible modulo phi")
	}

	modN := common.ModInt(N)
	modP := common.ModInt(P)
	expo := new(big.Int).Add(P, one)
	expo.Rsh(expo, 3)

	var x [PARAM_M]*big.Int
	var a [PARAM_M]bool
	var b [PARAM_M]bool
	var z [PARAM_M]*big.Int

	for i, yi := range y {
		yiP := new(big.Int).Set(yi)
		if big.Jacobi(yiP, P) == 1 {
			a[i] = false
		} else {
			a[i] = true
			yiP = modN.Mul(big.NewInt(-1), yiP)
		}
		b[i] = true
		x[i] = modN.Mul(modP.Exp(yiP, expo), w)
		z[i] = modN.Exp(yi, invN)
	}

	return &ModProof{
		W: w,
		X: x,
		A: a,
		B: b,
		Z: z,
	}, nil
}

func mustSetString(s string) *big.Int {
	i, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("failed to parse integer: " + s)
	}
	return i
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

// TestModProofVerifyAcceptsCeilingBoundary pins the exact modulus width
// verifyMaxModulusBitLen (65536 bits): a modulus of that width is NOT rejected
// at the ceiling, so it fails at the later oddness check. This guards against
// an off-by-one in the ceiling comparison.
func TestModProofVerifyAcceptsCeilingBoundary(t *testing.T) {
	// 2^(65536-1) is exactly 65536 bits and even, so it is rejected at the
	// oddness check, not the ceiling check.
	n := new(big.Int).Lsh(one, uint(verifyMaxModulusBitLen-1))
	if n.BitLen() != verifyMaxModulusBitLen {
		t.Fatalf("boundary modulus is %d bits, wanted %d", n.BitLen(), verifyMaxModulusBitLen)
	}
	if n.Bit(0) == 1 {
		t.Fatal("boundary modulus must be even to reach the ceiling check")
	}
	proof := minimalModProof()
	res, err := proof.ModVerify(n)
	if res {
		t.Fatal("expected even modulus to be rejected")
	}
	if err == nil {
		t.Fatal("expected error for even modulus")
	}
	if strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("65536-bit modulus must pass the ceiling check, got %v", err)
	}
}

// TestModProofVerifyRejectsOversizedModulus pins the ceiling: a 65537-bit odd
// composite modulus is rejected up front with an "exceeds maximum" error,
// without the O(bitLen) allocation the session sampler would otherwise make.
func TestModProofVerifyRejectsOversizedModulus(t *testing.T) {
	// Odd composite of exactly verifyMaxModulusBitLen+1 bits, built as a
	// product so no primality search is needed.
	//
	//	a = 2^h + 1, b = 2^h + 3 with h = (verifyMaxModulusBitLen+1)/2,
	//	both odd; a*b > 2^verifyMaxModulusBitLen, so a*b is
	//	verifyMaxModulusBitLen+1 bits wide.
	h := uint((verifyMaxModulusBitLen + 1) / 2)
	a := new(big.Int).Add(new(big.Int).Lsh(one, h), big.NewInt(1))
	b := new(big.Int).Add(new(big.Int).Lsh(one, h), big.NewInt(3))
	n := new(big.Int).Mul(a, b)
	if n.BitLen() != verifyMaxModulusBitLen+1 || n.Bit(0) == 0 {
		t.Fatalf("oversized modulus produced a %d-bit, parity-%d value", n.BitLen(), n.Bit(0))
	}
	proof := minimalModProof()
	res, err := proof.ModVerify(n)
	if res {
		t.Fatal("ModVerify accepted a modulus wider than the sampler is defined for")
	}
	if err == nil {
		t.Fatal("expected an error for the oversized modulus")
	}
	if !strings.Contains(err.Error(), "exceeds maximum") {
		t.Fatalf("expected ceiling rejection, got %v", err)
	}
	// The ceiling check must fire before any O(bitLen) allocation.
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	proof.ModVerify(n)
	runtime.ReadMemStats(&after)
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 256<<10 {
		t.Fatalf("ModVerify allocated %d bytes for a %d-bit modulus it must reject up front", grew, n.BitLen())
	}
}

// minimalModProof builds a ModProof that clears every per-member check, so
// control reaches the ceiling comparison and later checks.
func minimalModProof() *ModProof {
	proof := &ModProof{W: big.NewInt(2)}
	for i := range proof.X {
		proof.X[i], proof.Z[i] = big.NewInt(7), big.NewInt(5)
	}
	return proof
}
