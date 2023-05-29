package paillier

import (
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
)

const (
	PARAM_M = 80
)

type (
	ParamProof struct {
		A [PARAM_M]*big.Int
		Z [PARAM_M]*big.Int
	}
)

// ParamProof is an implementation of the ring-pedersen parameter proof of
// Canetti, R., Gennaro, R., Goldfeder, S., Makriyannis, N., Peled, U.:
// UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.
// In: Cryptology ePrint Archive 2021/060
func (privateKey *PrivateKey) ParamProof(s, t, lambda *big.Int) *ParamProof {
	N := privateKey.PublicKey.N
	modN := common.ModInt(N)
	var A [PARAM_M]*big.Int
	var a [PARAM_M]*big.Int
	for i := 0; i < PARAM_M; i++ {
		ai := common.GetRandomPositiveInt(privateKey.PhiN)
		a[i] = ai
		A[i] = modN.Exp(t, ai)
	}

	modPhiN := common.ModInt(privateKey.PhiN)
	e := ParamChallenge(N, s, t, A)
	var z [PARAM_M]*big.Int
	for i := 0; i < PARAM_M; i++ {
		z[i] = modPhiN.Add(a[i], modPhiN.Mul(big.NewInt(int64(e[i])), lambda))
	}

	return &ParamProof{A, z}
}

func (pf ParamProof) ParamVerify(N, s, t *big.Int) bool {
	if common.AnyIsNil(N, s, t) || common.AnyIsNil(pf.A[:]...) || common.AnyIsNil(pf.Z[:]...) {
		return false
	}

	e := ParamChallenge(N, s, t, pf.A)
	modN := common.ModInt(N)
	for i := 0; i < PARAM_M; i++ {
		tzi := modN.Exp(t, pf.Z[i])
		Aisei := modN.MulExp(pf.A[i], s, big.NewInt(int64(e[i])))
		if !common.Eq(tzi, Aisei) {
			return false
		}
	}
	return true
}

// Standard Fiat-Shamir transform
func ParamChallenge(N, s, t *big.Int, A [PARAM_M]*big.Int) [PARAM_M]byte {
	aHash := common.SHA512_256i(A[:]...)
	e := common.SHA512_256i(N, s, t, aHash)
	return BytesToBits(e)
}

// Turn a big.Int with at least 80 (PARAM_M) bits into 80 bytes,
// each being either 1 or 0
func BytesToBits(b *big.Int) [PARAM_M]byte {
	var e [PARAM_M]byte
	for i := 0; i < PARAM_M; i++ {
		e[i] = byte(b.Bit(i))
	}
	return e
}

func UnmarshalParamProof(as [][]byte, zs [][]byte) (*ParamProof, error) {
	if len(as) != PARAM_M {
		return nil, fmt.Errorf("UnmarshalParamProof: incorrect number of commitments: %d, expected %d", len(as), PARAM_M)
	}
	if len(zs) != PARAM_M {
		return nil, fmt.Errorf("UnmarshalParamProof: incorrect number of responses: %d, expected %d", len(zs), PARAM_M)
	}

	a := common.MultiBytesToBigInts(as)
	z := common.MultiBytesToBigInts(zs)

	var A [PARAM_M]*big.Int
	var Z [PARAM_M]*big.Int

	for i := 0; i < PARAM_M; i++ {
		A[i] = a[i]
		Z[i] = z[i]
	}

	return &ParamProof{A, Z}, nil
}
