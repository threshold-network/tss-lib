package paillier

import (
	"math/big"
	"testing"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// modProofContextInputs derives the invariant, key-fixed inputs of the mod
// proof CT context from the loaded 2048-bit fixture key: the secret primes,
// the key's phiN, and invN = N^(-1) mod phiN.
func modProofContextInputs(t *testing.T) (p, q, N, phiN, invN *big.Int) {
	t.Helper()
	setUp(t)
	p, q = privateKey.GetPQ()
	N = publicKey.N
	phiN = privateKey.PhiN
	invN = new(big.Int).ModInverse(N, phiN)
	require.NotNil(t, invN, "the fixture key must admit N^(-1) mod phiN")
	return
}

// deterministicModProofXs returns PARAM_M deterministic challenge-like
// inputs spread across [0, N): a HashToN stream plus small constants that
// cover the zero-base edge. They stand in for the y_i / yy_i bases the
// context's predicate and root computations actually receive.
func deterministicModProofXs(N *big.Int) []*big.Int {
	var xs []*big.Int
	for i := range PARAM_M {
		xs = append(xs, common.HashToN(N, big.NewInt(int64(i))))
	}
	xs = append(xs, big.NewInt(0), big.NewInt(1), big.NewInt(2), big.NewInt(4))
	return xs
}

// TestModProofCTContextExponentReuseEquivalence is the regression guard for
// the context's pre-encoded, once-per-proof secret exponents: a wrong
// width, value, or mis-reused encoding of psP/psQ/rootExp/invN would
// change the QR verdicts, the fourth root, or the z_i exponentiation, so
// the CT context (reusing its encodings across every base) must stay
// byte-identical to the non-CT context and to the math/big reference for
// every base.
func TestModProofCTContextExponentReuseEquivalence(t *testing.T) {
	p, q, N, phiN, invN := modProofContextInputs(t)

	ctxOn := newModProofCTContext(p, q, N, phiN, invN, true)
	ctxOff := newModProofCTContext(p, q, N, phiN, invN, false)

	psP := new(big.Int).Div(new(big.Int).Sub(p, big.NewInt(1)), big.NewInt(2))
	psQ := new(big.Int).Div(new(big.Int).Sub(q, big.NewInt(1)), big.NewInt(2))
	rootExp := new(big.Int).Div(new(big.Int).Add(phiN, big.NewInt(4)), big.NewInt(8))

	for _, x := range deterministicModProofXs(N) {
		// Reference QR verdict: x^((p-1)/2) == 1 mod p and likewise mod q.
		qrRef := new(big.Int).Exp(x, psP, p).Cmp(one) == 0 &&
			new(big.Int).Exp(x, psQ, q).Cmp(one) == 0

		// The CT context reuses its pre-encoded psP/psQ exponent bytes for
		// this base and every other base; both contexts must agree with
		// the reference.
		qrOn := ctxOn.isQuadResidueModComposite(x, p, q)
		qrOff := ctxOff.isQuadResidueModComposite(x, p, q)
		assert.Equal(t, qrRef, qrOff, "non-CT QR verdict must match the math/big reference")
		assert.Equal(t, qrRef, qrOn, "CT context QR verdict (reused encoded exponent) must match the reference")

		// Fourth-root exponentiation of a residue base: x^(rootExp) twice.
		rootRef := new(big.Int).Exp(x, rootExp, N)
		rootRef = rootRef.Exp(rootRef, rootExp, N)
		rootOn := ctxOn.fourthRoot(x, N)
		rootOff := ctxOff.fourthRoot(x, N)
		assert.Zero(t, rootOff.Cmp(rootRef), "non-CT fourth root must match the math/big reference")
		assert.Zero(t, rootOn.Cmp(rootRef), "CT context fourth root (reused encoded exponent) must match the reference")

		// The pre-encoded invN exponent: z_i = y_i^invN mod N, reused for
		// every iteration's challenge. The production path is the
		// canonical in-range form (x is in [0, N)).
		zRef := new(big.Int).Exp(x, invN, N)
		zOn := ctxOn.ctN.ExpCTCanonicalWithBytes(x, ctxOn.invNExp)
		assert.Zero(t, zOn.Cmp(zRef), "CT context z (reused encoded invN) must match the math/big reference")
	}
}
