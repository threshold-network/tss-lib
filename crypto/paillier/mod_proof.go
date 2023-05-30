package paillier

import (
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
)

type (
	ModProof struct {
		W *big.Int
		X [PARAM_M]*big.Int
		A [PARAM_M]bool
		B [PARAM_M]bool
		Z [PARAM_M]*big.Int
	}
)

// ModProof is an implementation of the paillier-blum modulus proof of
// Canetti, R., Gennaro, R., Goldfeder, S., Makriyannis, N., Peled, U.:
// UC Non-Interactive, Proactive, Threshold ECDSA with Identifiable Aborts.
// In: Cryptology ePrint Archive 2021/060
func (privateKey *PrivateKey) ModProof() *ModProof {
	N := privateKey.PublicKey.N
	phiN := privateKey.PhiN
	p, q := privateKey.GetPQ()

	w := new(big.Int)
	for {
		w = common.GetRandomPositiveInt(N)
		if big.Jacobi(w, N) == -1 {
			break
		}
	}

	y := ModChallenge(N, w)

	var x [PARAM_M]*big.Int
	var a [PARAM_M]bool
	var b [PARAM_M]bool
	var z [PARAM_M]*big.Int

	for i, y_i := range y {
		a_i, b_i, x_i := DefineXi(w, y_i, p, q, N)
		x[i] = x_i
		a[i] = a_i
		b[i] = b_i

		z_i := new(big.Int).ModInverse(N, phiN)
		z_i.Exp(y_i, z_i, N)

		z[i] = z_i
	}

	return &ModProof{
		W: w,
		X: x,
		A: a,
		B: b,
		Z: z,
	}
}

// Verification: Accept iff all of the following hold:
// – N is an odd composite number.
// – z_i^N = y_i for every i ∈ [m]
// – x_i^4 = (-1)^a_i * w^b_i * y_i mod N and a_i, b_i ∈ {0, 1} for every i ∈ [m].
func (pf ModProof) ModVerify(N *big.Int) (bool, error) {
	rem2 := new(big.Int).Mod(N, big.NewInt(2))
	odd := rem2.Int64() == 1

	if !odd {
		return false, fmt.Errorf("mod proof verify: modulus %d is even", N)
	}

	if N.ProbablyPrime(30) {
		return false, fmt.Errorf("mod proof verify: modulus %d seems prime", N)
	}

	y := ModChallenge(N, pf.W)

	for i, yi := range y {
		ziN := new(big.Int).Exp(pf.Z[i], N, N)

		if !common.Eq(ziN, yi) {
			return false, fmt.Errorf("mod proof verify: z_%d^N = %d != y_%d = %d", i, ziN, i, yi)
		}

		xi4 := new(big.Int).Exp(pf.X[i], big.NewInt(4), N)
		yy_i := new(big.Int).Set(yi)
		if pf.B[i] {
			yy_i.Mul(yy_i, pf.W)
		}
		if pf.A[i] {
			yy_i.Neg(yy_i)
		}
		yy_i.Mod(yy_i, N)
		if !common.Eq(xi4, yy_i) {
			return false, fmt.Errorf("mod proof verify: x_%d^4 = %d != (-1)^a_%d w^b_%d y_%d = %d", i, xi4, i, i, i, yy_i)
		}
	}

	return true, nil
}

// Standard Fiat-Shamir transform
func ModChallenge(N, w *big.Int) [PARAM_M]*big.Int {
	var y [PARAM_M]*big.Int

	for i := range y {
		y[i] = common.HashToN(N, w, big.NewInt(int64(i)))
	}

	return y
}

// Determine values a_i and b_i so that a valid x_i exists,
// and return a_i, b_i and x_i.
func DefineXi(w, y_i, p, q, N *big.Int) (bool, bool, *big.Int) {
	as := [...]bool{false, true}
	bs := [...]bool{false, true}

	for _, a := range as {
		for _, b := range bs {
			yy_i := new(big.Int).Set(y_i)

			if b {
				yy_i.Mul(yy_i, w)
			}

			if a {
				yy_i.Neg(yy_i)
			}

			yy_i.Mod(yy_i, N)

			roots := CompMod4thRt(yy_i, p, q, N)

			if roots != nil {
				return a, b, roots[0]
			}
		}
	}

	panic("no root found")
}

// calculate the square root of x modulo safe prime p
func PrimeModSqrt(x, p *big.Int) []*big.Int {
	r := new(big.Int).ModSqrt(x, p)
	if r == nil {
		return []*big.Int{}
	} else {
		return []*big.Int{r, common.ModInt(p).Neg(r)}
	}
}

// calculate the square root of x modulo n = pq for safe primes p,q
func CompModSqrt(x, p, q, n *big.Int) []*big.Int {
	rps := PrimeModSqrt(x, p)
	rqs := PrimeModSqrt(x, q)

	var res []*big.Int

	modN := common.ModInt(n)

	a := big.NewInt(0)
	b := big.NewInt(0)
	// z.GCD(x, y, a, b) sets z to the greatest common divisor of a and b and returns z.
	// If x or y are not nil, GCD sets their value such that z = a*x + b*y. 
	new(big.Int).GCD(a, b, p, q)

	for _, rp := range rps {
		for _, rq := range rqs {
			if rp != nil && rq != nil {
				temp1 := modN.Mul(modN.Mul(b, q), rp)
				temp2 := modN.Mul(modN.Mul(a, p), rq)
				restemp := modN.Add(temp1, temp2)
				res = append(res, restemp)
			}
		}
	}

	return res
}

func CompMod4thRt(x, p, q, n *big.Int) []*big.Int {
	sqroots := CompModSqrt(x, p, q, n)

	var res []*big.Int

	for _, sqroot := range sqroots {
		troots := CompModSqrt(sqroot, p, q, n)
		for _, troot := range troots {
			res = append(res, troot)
		}
	}

	return res
}

func UnmarshalModProof(ws []byte, xs [][]byte, as []bool, bs []bool, zs [][]byte) (*ModProof, error) {
	if len(ws) == 0 {
		return nil, fmt.Errorf("UnmarshalModProof: W length zero")
	}
	if len(xs) != PARAM_M {
		return nil, fmt.Errorf("UnmarshalModProof: incorrect number of Xs: %d, expected %d", len(xs), PARAM_M)
	}
	if len(as) != PARAM_M {
		return nil, fmt.Errorf("UnmarshalModProof: incorrect number of As: %d, expected %d", len(as), PARAM_M)
	}
	if len(bs) != PARAM_M {
		return nil, fmt.Errorf("UnmarshalModProof: incorrect number of Bs: %d, expected %d", len(bs), PARAM_M)
	}
	if len(zs) != PARAM_M {
		return nil, fmt.Errorf("UnmarshalModProof: incorrect number of Zs: %d, expected %d", len(zs), PARAM_M)
	}

	W := new(big.Int).SetBytes(ws)
	x := common.MultiBytesToBigInts(xs)
	z := common.MultiBytesToBigInts(zs)

	var X [PARAM_M]*big.Int
	var A [PARAM_M]bool
	var B [PARAM_M]bool
	var Z [PARAM_M]*big.Int

	for i := 0; i < PARAM_M; i++ {
		X[i] = x[i]
		A[i] = as[i]
		B[i] = bs[i]
		Z[i] = z[i]
	}

	return &ModProof{W, X, A, B, Z}, nil
}
