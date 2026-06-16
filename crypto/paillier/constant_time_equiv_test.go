// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package paillier

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/tss"
)

// These tests verify the invariant that the constant-time path computes the SAME
// function as the standard path: for deterministic operations the outputs are
// byte-identical, and randomised proofs produced with constant-time ops enabled
// still verify. (The primitive-level ExpCT==Exp / MulCT==Mul equivalence is covered
// in common/constant_time_test.go.)

// TestDecryptCTEquivalence: Decrypt is deterministic; CT and non-CT must agree
// byte-for-byte and both must recover the plaintext.
func TestDecryptCTEquivalence(t *testing.T) {
	facSetUp(t)

	pt := big.NewInt(424242)
	cipher, err := publicKey.Encrypt(pt)
	assert.NoError(t, err)

	mOff, err := privateKey.Decrypt(cipher)
	assert.NoError(t, err)

	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")
	mOn, err := privateKey.Decrypt(cipher)
	assert.NoError(t, err)

	assert.Zero(t, mOff.Cmp(mOn), "CT and non-CT Decrypt must be byte-identical")
	assert.Zero(t, pt.Cmp(mOn), "CT Decrypt must recover the plaintext")
}

// TestHomoMultCTEquivalence: HomoMult(m, c1) = c1^m mod N2 is deterministic; CT and
// non-CT must agree byte-for-byte, and the homomorphic multiplication property must
// hold under CT. m is the secret scalar exponent hardened by the CT path.
func TestHomoMultCTEquivalence(t *testing.T) {
	facSetUp(t)

	a := big.NewInt(111111)
	b := big.NewInt(222222)
	cA, err := publicKey.Encrypt(a)
	assert.NoError(t, err)

	cbOff, err := publicKey.HomoMult(b, cA)
	assert.NoError(t, err)

	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")
	cbOn, err := publicKey.HomoMult(b, cA)
	assert.NoError(t, err)

	assert.Zero(t, cbOff.Cmp(cbOn), "CT and non-CT HomoMult must be byte-identical")

	// Dec(HomoMult(b, Enc(a))) must equal a*b mod N.
	dec, err := privateKey.Decrypt(cbOn)
	assert.NoError(t, err)
	want := new(big.Int).Mod(new(big.Int).Mul(a, b), publicKey.N)
	assert.Zero(t, want.Cmp(dec), "CT HomoMult must satisfy the homomorphic multiplication property")
}

// TestEncryptCTRoundTrip: Encrypt is randomised (fresh nonce x), so CT and non-CT
// ciphertexts differ; instead verify that a CT-produced ciphertext decrypts back to the
// plaintext, exercising the constant-time gamma^m path (m is the secret exponent).
func TestEncryptCTRoundTrip(t *testing.T) {
	facSetUp(t)

	pt := big.NewInt(987654321)

	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")
	cipher, err := publicKey.Encrypt(pt)
	assert.NoError(t, err)
	dec, err := privateKey.Decrypt(cipher)
	assert.NoError(t, err)
	assert.Zero(t, pt.Cmp(dec), "CT Encrypt must round-trip through Decrypt")
}

// TestPaillierProofCTEquivalence: the Paillier square-free Proof is deterministic
// given (k, key, ecdsaPub); CT and non-CT must agree byte-for-byte and both verify.
func TestPaillierProofCTEquivalence(t *testing.T) {
	facSetUp(t)

	ki := common.MustGetRandomInt(256)
	ui := common.GetRandomPositiveInt(tss.EC().Params().N)
	yX, yY := tss.EC().ScalarBaseMult(ui.Bytes())
	pub := crypto.NewECPointNoCurveCheck(tss.EC(), yX, yY)

	proofOff := privateKey.Proof(ki, pub)

	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")
	proofOn := privateKey.Proof(ki, pub)

	for i := range proofOff {
		assert.Zero(t, proofOff[i].Cmp(proofOn[i]), "Proof element %d must be byte-identical", i)
	}

	okOff, err := proofOff.Verify(publicKey.N, ki, pub)
	assert.NoError(t, err)
	assert.True(t, okOff, "non-CT proof must verify")
	okOn, err := proofOn.Verify(publicKey.N, ki, pub)
	assert.NoError(t, err)
	assert.True(t, okOn, "CT proof must verify")
}

// TestFactorProofCTVerifies: FactorProof is randomised; a CT-generated proof must verify.
func TestFactorProofCTVerifies(t *testing.T) {
	facSetUp(t)

	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")
	proof := privateKey.FactorProof(auxPrime.N, s, tt)
	res, err := proof.FactorVerify(publicKey.N, auxPrime.N, s, tt)
	assert.NoError(t, err)
	assert.True(t, res, "CT FactorProof must verify")
}

// TestModProofCTVerifies: ModProof is randomised; a CT-generated proof must verify.
func TestModProofCTVerifies(t *testing.T) {
	facSetUp(t)

	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")
	proof := privateKey.ModProof()
	res, err := proof.ModVerify(publicKey.N)
	assert.NoError(t, err)
	assert.True(t, res, "CT ModProof must verify")
}

// TestModProofHelpersCTEquivalence: the QR helpers are deterministic; CT and non-CT
// must agree (boolean predicates and the byte-identical fourth root) on real-key inputs.
func TestModProofHelpersCTEquivalence(t *testing.T) {
	facSetUp(t)

	p, q := privateKey.GetPQ()
	N := publicKey.N
	phiN := privateKey.PhiN

	// x = r^2 mod N is a quadratic residue mod N (exercises the true branch).
	r := common.GetRandomPositiveRelativelyPrimeInt(N)
	x := new(big.Int).Mod(new(big.Int).Mul(r, r), N)

	// nr is a known quadratic NON-residue mod p (exercises the false branch of
	// isQuadResidueModPrime); located using the standard (non-CT) predicate.
	nr := big.NewInt(2)
	for isQuadResidueModPrime(nr, p) {
		nr.Add(nr, big.NewInt(1))
	}

	qrPOff := isQuadResidueModPrime(x, p)
	nrPOff := isQuadResidueModPrime(nr, p)
	qrCompOff := isQuadResidueModComposite(x, p, q)
	rootOff := quadResidueModComposite(x, p, q, N, phiN)

	common.EnableConstantTimeOps()
	defer common.DisableConstantTimeOps()
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")
	qrPOn := isQuadResidueModPrime(x, p)
	nrPOn := isQuadResidueModPrime(nr, p)
	qrCompOn := isQuadResidueModComposite(x, p, q)
	rootOn := quadResidueModComposite(x, p, q, N, phiN)

	assert.True(t, qrPOff, "x=r^2 must be a residue mod p")
	assert.False(t, nrPOff, "nr must be a non-residue mod p")
	assert.Equal(t, qrPOff, qrPOn, "isQuadResidueModPrime must agree (residue)")
	assert.Equal(t, nrPOff, nrPOn, "isQuadResidueModPrime must agree (non-residue)")
	assert.Equal(t, qrCompOff, qrCompOn, "isQuadResidueModComposite must agree")
	assert.Zero(t, rootOff.Cmp(rootOn), "quadResidueModComposite must be byte-identical")
}
