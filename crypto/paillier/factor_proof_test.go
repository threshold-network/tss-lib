package paillier

import (
	"context"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
)

var (
	auxPrime      *PublicKey
	s             *big.Int
	tt            *big.Int
	badPrivateKey *PrivateKey
	badPublicKey  *PublicKey
)

func facSetUp(t *testing.T) {
	if privateKey != nil && publicKey != nil && auxPrime != nil && s != nil && tt != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	var err error
	privateKey, publicKey, err = GenerateKeyPair(ctx, testPaillierKeyLength)
	if err != nil {
		t.Fatalf("failed to generate Paillier key pair: %v", err)
	}

	var err2 error
	var auxSecret *PrivateKey
	auxSecret, auxPrime, err2 = GenerateKeyPair(ctx, testPaillierKeyLength)
	if err2 != nil {
		t.Fatalf("failed to generate auxiliary Paillier key pair: %v", err2)
	}

	lambda := common.GetRandomPositiveInt(auxSecret.PhiN)
	N := auxPrime.N
	r := common.GetRandomPositiveRelativelyPrimeInt(N)
	tt = new(big.Int).Mod(new(big.Int).Mul(r, r), N)
	s = new(big.Int).Exp(tt, lambda, N)

	badPrivateKey, badPublicKey = GenerateBadKeyPair()
}

func GenerateBadKeyPair() (privateKey *PrivateKey, publicKey *PublicKey) {
	one := big.NewInt(1)

	// Use fixed odd factors with a 1792-bit size gap. The factor proof must
	// reject this malformed Paillier modulus, and the fixture should not spend
	// CI time searching for random safe primes just to construct bad inputs.
	P := new(big.Int).Sub(new(big.Int).Lsh(one, 1920), big.NewInt(133))
	Q := new(big.Int).Sub(new(big.Int).Lsh(one, 128), big.NewInt(159))
	N := new(big.Int).Mul(P, Q)

	// phiN = P-1 * Q-1
	PMinus1, QMinus1 := new(big.Int).Sub(P, one), new(big.Int).Sub(Q, one)
	phiN := new(big.Int).Mul(PMinus1, QMinus1)

	// lambdaN = lcm(P−1, Q−1)
	gcd := new(big.Int).GCD(nil, nil, PMinus1, QMinus1)
	lambdaN := new(big.Int).Div(phiN, gcd)

	publicKey = &PublicKey{N: N}
	privateKey = &PrivateKey{PublicKey: *publicKey, LambdaN: lambdaN, PhiN: phiN}
	return
}

func TestFactorProofVerify(t *testing.T) {
	facSetUp(t)
	proof := privateKey.FactorProof(auxPrime.N, s, tt)
	res, err := proof.FactorVerify(publicKey.N, auxPrime.N, s, tt)
	assert.NoError(t, err)
	assert.True(t, res, "proof verify result must be true")
}

func TestFactorProofSessionBinding(t *testing.T) {
	facSetUp(t)
	session := []byte("factor-proof-session-a")
	proof := privateKey.FactorProof(auxPrime.N, s, tt, session)

	res, err := proof.FactorVerify(publicKey.N, auxPrime.N, s, tt, session)
	assert.NoError(t, err)
	assert.True(t, res, "proof verify result must be true")

	res, err = proof.FactorVerify(publicKey.N, auxPrime.N, s, tt, []byte("factor-proof-session-b"))
	assert.Error(t, err)
	assert.False(t, res, "proof verify result must be false")

	res, err = proof.FactorVerify(publicKey.N, auxPrime.N, s, tt)
	assert.Error(t, err)
	assert.False(t, res, "session-bound proof must not verify without its session")
}

func TestFactorChallengeRejectsEmptySessionTag(t *testing.T) {
	assert.Panics(t, func() {
		_ = FactorChallenge(big.NewInt(11), big.NewInt(2), big.NewInt(3), big.NewInt(5),
			big.NewInt(7), big.NewInt(11), big.NewInt(13), big.NewInt(17), big.NewInt(19), big.NewInt(23), []byte{})
	})
}

func TestFactorProofVerifyFail1(t *testing.T) {
	facSetUp(t)
	badN := new(big.Int).Mul(publicKey.N, big.NewInt(3))
	proof := privateKey.FactorProof(auxPrime.N, s, tt)
	res, err := proof.FactorVerify(badN, auxPrime.N, s, tt)
	assert.Error(t, err)
	assert.False(t, res, "proof verify result must be false")
}

func TestFactorProofVerifyFail2(t *testing.T) {
	facSetUp(t)
	proof := privateKey.FactorProof(auxPrime.N, s, tt)
	proof.V = nil
	res, err := proof.FactorVerify(publicKey.N, auxPrime.N, s, tt)
	assert.Error(t, err)
	assert.False(t, res, "proof verify result must be false")
}

func TestFactorProofVerifyFail3(t *testing.T) {
	facSetUp(t)
	proof := privateKey.FactorProof(auxPrime.N, s, tt)
	res, err := proof.FactorVerify(publicKey.N, auxPrime.N, s, nil)
	assert.Error(t, err)
	assert.False(t, res, "proof verify result must be false")
}

func TestFactorProofVerifyRejectsNonInvertibleBase(t *testing.T) {
	facSetUp(t)
	proof := privateKey.FactorProof(auxPrime.N, s, tt)
	proof.Q = big.NewInt(0)
	proof.Z1 = big.NewInt(-1)

	assert.NotPanics(t, func() {
		res, err := proof.FactorVerify(publicKey.N, auxPrime.N, s, tt)
		assert.Error(t, err)
		assert.False(t, res, "proof verify result must be false")
	})
}

func TestFactorProofVerifyRejectsNonZeroInvalidBases(t *testing.T) {
	facSetUp(t)

	cases := []struct {
		name   string
		verify func(proof *FactorProof) (bool, error)
	}{
		{
			name: "verifier s",
			verify: func(proof *FactorProof) (bool, error) {
				return proof.FactorVerify(publicKey.N, auxPrime.N, new(big.Int).Set(auxPrime.N), tt)
			},
		},
		{
			name: "verifier t",
			verify: func(proof *FactorProof) (bool, error) {
				return proof.FactorVerify(publicKey.N, auxPrime.N, s, new(big.Int).Set(auxPrime.N))
			},
		},
		{
			name: "proof P",
			verify: func(proof *FactorProof) (bool, error) {
				proof.P = new(big.Int).Set(auxPrime.N)
				return proof.FactorVerify(publicKey.N, auxPrime.N, s, tt)
			},
		},
		{
			name: "proof Q",
			verify: func(proof *FactorProof) (bool, error) {
				proof.Q = new(big.Int).Set(auxPrime.N)
				return proof.FactorVerify(publicKey.N, auxPrime.N, s, tt)
			},
		},
		{
			name: "proof A",
			verify: func(proof *FactorProof) (bool, error) {
				proof.A = new(big.Int).Set(auxPrime.N)
				return proof.FactorVerify(publicKey.N, auxPrime.N, s, tt)
			},
		},
		{
			name: "proof B",
			verify: func(proof *FactorProof) (bool, error) {
				proof.B = new(big.Int).Set(auxPrime.N)
				return proof.FactorVerify(publicKey.N, auxPrime.N, s, tt)
			},
		},
		{
			name: "proof T",
			verify: func(proof *FactorProof) (bool, error) {
				proof.T = new(big.Int).Set(auxPrime.N)
				return proof.FactorVerify(publicKey.N, auxPrime.N, s, tt)
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			proof := privateKey.FactorProof(auxPrime.N, s, tt)

			assert.NotPanics(t, func() {
				res, err := test.verify(proof)
				assert.Error(t, err)
				assert.False(t, res, "proof verify result must be false")
			})
		})
	}
}

func TestFactorProofVerifyRejectsOverwideResponses(t *testing.T) {
	facSetUp(t)

	q := new(big.Int).Lsh(big.NewInt(1), PARAM_L)
	q3 := new(big.Int).Mul(q, q)
	q3.Mul(q3, q)
	qN := new(big.Int).Mul(q, auxPrime.N)
	qPkNN := new(big.Int).Mul(qN, publicKey.N)
	q3N := new(big.Int).Mul(q3, auxPrime.N)
	q3PkNN := new(big.Int).Mul(q3N, publicKey.N)
	limitW := new(big.Int).Lsh(q3N, 1)
	limitV := new(big.Int).Lsh(q3PkNN, 2)

	cases := []struct {
		name   string
		mutate func(proof *FactorProof)
	}{
		{
			name: "W1",
			mutate: func(proof *FactorProof) {
				proof.W1 = new(big.Int).Add(limitW, big.NewInt(1))
			},
		},
		{
			name: "W2",
			mutate: func(proof *FactorProof) {
				proof.W2 = new(big.Int).Add(limitW, big.NewInt(1))
			},
		},
		{
			name: "Sigma",
			mutate: func(proof *FactorProof) {
				proof.Sigma = new(big.Int).Add(qPkNN, big.NewInt(1))
			},
		},
		{
			name: "V",
			mutate: func(proof *FactorProof) {
				proof.V = new(big.Int).Add(limitV, big.NewInt(1))
			},
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			proof := privateKey.FactorProof(auxPrime.N, s, tt)
			test.mutate(proof)

			res, err := proof.FactorVerify(publicKey.N, auxPrime.N, s, tt)
			assert.Error(t, err)
			assert.False(t, res, "proof verify result must be false")
		})
	}
}

func TestFactorProofVerifyFailBadFactors(t *testing.T) {
	facSetUp(t)
	proof := badPrivateKey.FactorProof(auxPrime.N, s, tt)
	res, err := proof.FactorVerify(badPublicKey.N, auxPrime.N, s, tt)
	assert.Error(t, err)
	assert.False(t, res, "proof verify result must be false")
}
