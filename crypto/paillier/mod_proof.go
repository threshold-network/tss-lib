package paillier

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/bnb-chain/tss-lib/common"
)

const (
	PARAM_M             = 80 // ZKP iterations
	fsDomainTagModProof = "tss-lib.threshold.modproof"
)

// errModulusCeiling distinguishes the shared width-ceiling rejection in
// package tests without making error text or a new exported API contractual.
var errModulusCeiling = errors.New("unknown-order modulus exceeds the shared ceiling")

func fsSessionModProof(session []byte) []byte {
	return append([]byte(fsDomainTagModProof+"|"), session...)
}

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
func (privateKey *PrivateKey) ModProof(session ...[]byte) *ModProof {
	N := privateKey.PublicKey.N
	phiN := privateKey.PhiN
	p, q := privateKey.GetPQ()

	w := common.GetRandomPositiveInt(N)
	for big.Jacobi(w, N) != -1 {
		w = common.GetRandomPositiveInt(N)
	}

	y := ModChallenge(N, w, session...)

	var x [PARAM_M]*big.Int
	var a [PARAM_M]bool
	var b [PARAM_M]bool
	var z [PARAM_M]*big.Int

	// invN = N^(-1) mod phiN. phiN is even, so this inverse stays on math/big (bigmod
	// requires an odd modulus); it is a prover-side value, never transmitted. Only the
	// Exp mod N (odd) below carries the secret exponent and gets the constant-time
	// path, reusing the context's pre-encoded fixed-width invN encoding across all
	// iterations.
	invN := new(big.Int).ModInverse(N, phiN)
	// One snapshot for context creation and every use, even if the global
	// toggle changes while this proof is being generated.
	useCT := common.IsConstantTimeEnabled()
	// Build the p/q/N constant-time contexts and the secret-derived fixed
	// exponents once, reused across all PARAM_M iterations. Each bigmod
	// modulus and byte pool is otherwise re-created inside every QR
	// predicate and root computation; the exponents are fixed for the key,
	// so recomputing them per iteration only adds setup work without
	// changing any proof byte. On the constant-time path the context also
	// pre-encodes those exponents at the modulus public byte widths and
	// zeroes the owned encodings before the proof is returned.
	ctx := newModProofCTContext(p, q, N, phiN, invN, useCT)

	for i, y_i := range y {
		a_i, b_i, x_i := ctx.defineXi(w, y_i, p, q, N)
		x[i] = x_i
		a[i] = a_i
		b[i] = b_i

		var z_i *big.Int
		if useCT {
			// y_i is in [0, N) (HashToN / sampleYModN outputs), so the
			// canonical in-range exponentiation avoids the per-iteration
			// operand reduction; invNExp is the context's pre-encoded,
			// proof-owned encoding of the invariant secret exponent.
			z_i = ctx.ctN.ExpCTCanonicalWithBytes(y_i, ctx.invNExp)
		} else {
			z_i = new(big.Int).Exp(y_i, invN, N)
		}

		z[i] = z_i
	}
	// Wipe the secret-derived exponent encodings owned by the context;
	// the proof values above are already plain big.Ints.
	ctx.wipeExponentEncodings()

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
func (pf ModProof) ModVerify(N *big.Int, session ...[]byte) (bool, error) {
	if common.AnyIsNil(pf.W) || common.AnyIsNil(pf.X[:]...) || common.AnyIsNil(pf.Z[:]...) {
		return false, fmt.Errorf("mod proof verify: nil inputs in proof")
	}

	// Width policy: reject a caller-supplied modulus wider than the shared
	// ceiling before IsUsableUnknownOrderModulus's ProbablyPrime call, the
	// sampler and any per-candidate exponentiation is run against it.
	if common.ExceedsUnknownOrderModulusCeiling(N) {
		return false, fmt.Errorf("mod proof verify: modulus bit length %d exceeds maximum %d: %w", N.BitLen(), common.MaxUnknownOrderModulusBitLen, errModulusCeiling)
	}

	if !common.IsUsableUnknownOrderModulus(N, common.MinUnknownOrderModulusBitLen) {
		return false, fmt.Errorf("mod proof verify: invalid modulus %d", N)
	}

	if !common.Gt(pf.W, zero) || !common.Lt(pf.W, N) {
		return false, fmt.Errorf("mod proof verify: w must be in [1, N), got %d", pf.W)
	}

	if big.Jacobi(pf.W, N) != -1 {
		return false, fmt.Errorf("mod proof verify: w %d has invalid jacobi symbol %d", pf.W, big.Jacobi(pf.W, N))
	}

	y := ModChallenge(N, pf.W, session...)

	for i, yi := range y {
		if !common.Gt(pf.X[i], zero) || !common.Lt(pf.X[i], N) {
			return false, fmt.Errorf("mod proof verify: x_%d must be in [1, N), got %d", i, pf.X[i])
		}
		if !common.Gt(pf.Z[i], zero) || !common.Lt(pf.Z[i], N) {
			return false, fmt.Errorf("mod proof verify: z_%d must be in [1, N), got %d", i, pf.Z[i])
		}
		if new(big.Int).GCD(nil, nil, pf.X[i], N).Cmp(one) != 0 {
			return false, fmt.Errorf("mod proof verify: x_%d is not a unit modulo N", i)
		}
		if new(big.Int).GCD(nil, nil, pf.Z[i], N).Cmp(one) != 0 {
			return false, fmt.Errorf("mod proof verify: z_%d is not a unit modulo N", i)
		}

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

// Standard Fiat-Shamir transform.
//
// The session-tagged path uses expand-then-reject sampling to derive each y_i
// uniformly in [0, N). Reducing a single
// 256-bit SHA512_256i_TAGGED output mod ~2^2048 would emit challenges in
// [0, 2^256) instead of [0, N), giving the session-tagged path a strictly
// weaker challenge distribution than the HashToN path it shares the
// verifier with. Each iteration also chains the previously-derived challenges
// (y[:i]) into the hash inputs, preserving the sequential-challenge property of
// the original session-tagged construction.
func ModChallenge(N, w *big.Int, session ...[]byte) [PARAM_M]*big.Int {
	var y [PARAM_M]*big.Int

	for i := range y {
		if len(session) == 0 {
			y[i] = common.HashToN(N, w, big.NewInt(int64(i)))
			continue
		}
		if len(session[0]) == 0 {
			panic("paillier: mod proof session tag must be non-empty")
		}
		inputs := append([]*big.Int{w, N}, y[:i]...)
		y[i] = sampleYModN(fsSessionModProof(session[0]), N, inputs...)
	}

	return y
}

func sampleYModN(tag []byte, N *big.Int, inputs ...*big.Int) *big.Int {
	seedInt := common.SHA512_256i_TAGGED(tag, inputs...)
	seed := seedInt.FillBytes(make([]byte, 32))
	byteLen := (N.BitLen() + 7) / 8
	blocks := (byteLen + 31) / 32
	excessBits := uint(byteLen*8 - N.BitLen())

	for counter := uint32(0); ; counter++ {
		counterBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(counterBytes, counter)
		out := make([]byte, 0, blocks*32)
		for blockIdx := 0; blockIdx < blocks; blockIdx++ {
			blockIdxBytes := make([]byte, 4)
			binary.BigEndian.PutUint32(blockIdxBytes, uint32(blockIdx))
			out = append(out, common.SHA512_256(seed, counterBytes, blockIdxBytes)...)
		}
		out = out[:byteLen]
		if excessBits > 0 {
			out[0] &= byte(0xff >> excessBits)
		}
		candidate := new(big.Int).SetBytes(out)
		if candidate.Cmp(N) < 0 {
			return candidate
		}
	}
}

// modProofCTContext is the precomputed state ModProof reuses across all
// PARAM_M iterations: the constant-time modular contexts for p, q and N,
// plus the secret-derived exponents fixed for the key ((p-1)/2, (q-1)/2
// and the fourth-root exponent (phiN+4)/8) and the key's invN = N^(-1)
// mod phiN. Without this context every quadratic-residue check and
// fourth-root computation re-created its bigmod modulus and byte pool;
// the proof bytes are identical either way, so the precomputed form
// only removes repeated setup from the hot path.
//
// In the constant-time path the context also owns fixed-width encodings
// of those invariant exponents (psPExp, psQExp, rootExpExp, invNExp),
// pre-encoded once at the modulus public byte widths and reused across
// all iterations instead of being re-encoded and re-wiped on every
// call; wipeExponentEncodings zeroes them when proof generation
// finishes.
type modProofCTContext struct {
	useCT bool
	ctP   *common.CTModInt
	ctQ   *common.CTModInt
	ctN   *common.CTModInt

	psP     *big.Int // (p-1)/2: Euler's-criterion exponent mod p
	psQ     *big.Int // (q-1)/2: Euler's-criterion exponent mod q
	rootExp *big.Int // (phiN+4)/8: fourth-root exponent mod N

	// Owned fixed-width encodings of the secret-derived exponents
	// above plus invN, created only on the constant-time path.
	psPExp, psQExp, rootExpExp, invNExp []byte
}

// fixedWidthExponentBytes encodes a nonnegative exponent as a
// big-endian byte string at the modulus public byte width
// (len(mod.Bytes()), the same width the public bigmod path pads to).
func fixedWidthExponentBytes(exp, mod *big.Int) []byte {
	return exp.FillBytes(make([]byte, len(mod.Bytes())))
}

// wipeExponentEncodings zeroes the secret-derived fixed-width exponent
// encodings owned by this context. Call it when proof generation
// finishes (or aborts); the fields keep pointing at the zeroed arrays.
func (ctx *modProofCTContext) wipeExponentEncodings() {
	for _, enc := range [][]byte{ctx.psPExp, ctx.psQExp, ctx.rootExpExp, ctx.invNExp} {
		for i := range enc {
			enc[i] = 0
		}
	}
}

func newModProofCTContext(p, q, N, phiN, invN *big.Int, useCT bool) *modProofCTContext {
	ctx := &modProofCTContext{
		useCT:   useCT,
		psP:     new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(2)),
		psQ:     new(big.Int).Div(new(big.Int).Sub(q, big.NewInt(1)), big.NewInt(2)),
		rootExp: new(big.Int).Div(new(big.Int).Add(phiN, big.NewInt(4)), big.NewInt(8)),
	}
	if useCT {
		// SECURITY: p and q are secret primes and the exponents are
		// secret-derived; build the constant-time contexts and pre-encode
		// the invariant exponents once here instead of re-creating or
		// re-encoding them inside every iteration.
		ctx.ctP = common.NewCTModInt(p)
		ctx.ctQ = common.NewCTModInt(q)
		ctx.ctN = common.NewCTModInt(N)
		ctx.psPExp = fixedWidthExponentBytes(ctx.psP, p)
		ctx.psQExp = fixedWidthExponentBytes(ctx.psQ, q)
		ctx.rootExpExp = fixedWidthExponentBytes(ctx.rootExp, N)
		ctx.invNExp = fixedWidthExponentBytes(invN, N)
	}
	return ctx
}

// isQuadResidueModPrime is x^ps == 1 mod prime, where ps is the precomputed
// (prime-1)/2 exponent of this context. The CT path reuses the pre-encoded
// fixed-width exponent psExp; x is reduced modulo prime by the generic
// reducing path because x may exceed prime (it is reduced mod N, not mod
// prime).
func (ctx *modProofCTContext) isQuadResidueModPrime(x, prime *big.Int, ct *common.CTModInt, ps *big.Int, psExp []byte) bool {
	if ctx.useCT {
		return common.Eq(ct.ExpCTWithBytes(x, psExp), one)
	}
	return common.Eq(new(big.Int).Exp(x, ps, prime), one)
}

// x is a quadratic residue modulo pq iff x is one modulo p and q
func (ctx *modProofCTContext) isQuadResidueModComposite(x, p, q *big.Int) bool {
	return ctx.isQuadResidueModPrime(x, p, ctx.ctP, ctx.psP, ctx.psPExp) &&
		ctx.isQuadResidueModPrime(x, q, ctx.ctQ, ctx.psQ, ctx.psQExp)
}

// fourthRoot computes the fourth root of a quadratic residue x modulo
// n = pq by squaring x^((phiN+4)/8) twice. The CT path reuses the
// pre-encoded fixed-width root exponent; both bases are in [0, n)
// (x comes from defineXi's reduction mod n, and res is the mod-n
// exponentiation output), so the canonical in-range path is used and no
// operand reduction is needed.
func (ctx *modProofCTContext) fourthRoot(x, n *big.Int) *big.Int {
	if ctx.useCT {
		// SECURITY: rootExp derives from secret phiN; the modulus n is odd,
		// so both square-root steps stay on the constant-time path.
		res := ctx.ctN.ExpCTCanonicalWithBytes(x, ctx.rootExpExp)
		return ctx.ctN.ExpCTCanonicalWithBytes(res, ctx.rootExpExp)
	}
	res := new(big.Int).Exp(x, ctx.rootExp, n)
	return res.Exp(res, ctx.rootExp, n)
}

// defineXi determines values a_i and b_i so that a valid x_i exists,
// and returns a_i, b_i and x_i.
func (ctx *modProofCTContext) defineXi(w, y_i, p, q, N *big.Int) (bool, bool, *big.Int) {
	bools := [...]bool{false, true}

	for _, a := range bools {
		for _, b := range bools {
			yy_i := new(big.Int).Set(y_i)

			if b {
				yy_i.Mul(yy_i, w)
			}

			if a {
				yy_i.Neg(yy_i)
			}

			yy_i.Mod(yy_i, N)

			if ctx.isQuadResidueModComposite(yy_i, p, q) {
				return a, b, ctx.fourthRoot(yy_i, N)
			}
		}
	}

	panic("no root found") // this should not be reached with n=pq for safe primes p, q
}

// Standalone one-shot wrappers: they pay no context setup and snapshot the
// constant-time toggle for the call only.

// x is a quadratic residue modulo pq if x is a quadratic residue modulo p
// and q
func isQuadResidueModComposite(x, p, q *big.Int) bool {
	useCT := common.IsConstantTimeEnabled()
	psP := new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(2))
	psQ := new(big.Int).Div(new(big.Int).Sub(q, big.NewInt(1)), big.NewInt(2))
	return isQuadResidueModPrimeWithExponent(x, p, useCT, psP) && isQuadResidueModPrimeWithExponent(x, q, useCT, psQ)
}

// x is a quadratic residue modulo p if x^((p-1)/2) = 1
func isQuadResidueModPrime(x, p *big.Int) bool {
	ps := new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(2))
	return isQuadResidueModPrimeWithExponent(x, p, common.IsConstantTimeEnabled(), ps)
}

func isQuadResidueModPrimeWithExponent(x, p *big.Int, useCT bool, ps *big.Int) bool {
	if useCT {
		// SECURITY: p is a secret prime (odd) and the exponent (p-1)/2 is
		// secret-derived; use the constant-time path.
		return common.Eq(common.NewCTModInt(p).ExpCT(x, ps), one)
	}
	return common.Eq(new(big.Int).Exp(x, ps, p), one)
}

// the square root of x can be calculated as x^((phiN+4)/8)
// apply this twice to get the 4th root
func quadResidueModComposite(x, p, q, n, phiN *big.Int) *big.Int {
	e := new(big.Int).Div(new(big.Int).Add(phiN, big.NewInt(4)), big.NewInt(8))
	useCT := common.IsConstantTimeEnabled()
	if useCT {
		// SECURITY: the fourth-root exponent e derives from secret phiN; the
		// modulus n = N is odd, so both square-root steps stay on the
		// constant-time path.
		ctModN := common.NewCTModInt(n)
		res := ctModN.ExpCT(x, e)
		return ctModN.ExpCT(res, e)
	}
	res := new(big.Int).Exp(x, e, n)
	return res.Exp(res, e, n)
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
