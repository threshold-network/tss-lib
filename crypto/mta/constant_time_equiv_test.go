// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mta

import (
	"crypto/rand"
	"fmt"
	"math/big"
	mathrand "math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/tss"
)

// Replaying this test-only stream makes the random commitments comparable. These
// tests must remain non-parallel because both the entropy reader and CT mode are
// process-wide; cleanup restores their previous values after each subtest.
func setMTAProofTestMode(t *testing.T, enabled bool) {
	t.Helper()
	previousReader, previousMode := rand.Reader, common.IsConstantTimeEnabled()
	t.Cleanup(func() {
		rand.Reader = previousReader
		if previousMode {
			common.EnableConstantTimeOps()
		} else {
			common.DisableConstantTimeOps()
		}
	})
	rand.Reader = mathrand.New(mathrand.NewSource(1))
	if enabled {
		common.EnableConstantTimeOps()
	} else {
		common.DisableConstantTimeOps()
	}
	require.Equal(t, enabled, common.IsConstantTimeEnabled())
}

func mtaFixtureKey(t *testing.T) *paillier.PrivateKey {
	t.Helper()
	fixtures, _, err := keygen.LoadKeygenTestFixtures(1)
	require.NoError(t, err)
	require.NotNil(t, fixtures[0].PaillierSK)
	return fixtures[0].PaillierSK
}

func TestDecryptFixtureWithoutPhiNCTEquivalence(t *testing.T) {
	key := mtaFixtureKey(t)
	plaintext := big.NewInt(424242)
	ciphertext, err := key.Encrypt(plaintext)
	require.NoError(t, err)
	keyWithoutPhi := *key
	keyWithoutPhi.PhiN = nil
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("CT=%t", enabled), func(t *testing.T) {
			setMTAProofTestMode(t, enabled)
			for _, candidate := range []*paillier.PrivateKey{key, &keyWithoutPhi} {
				got, err := candidate.Decrypt(ciphertext)
				require.NoError(t, err)
				require.Zero(t, got.Cmp(plaintext))
			}
		})
	}
}

func TestRangeProofAliceUnequalWidthsCTEquivalence(t *testing.T) {
	key := mtaFixtureKey(t)
	pk := &key.PublicKey
	// Small test-only auxiliary modulus (two safe primes) and quadratic residues.
	// Its byte width is independent of the Paillier plaintext domain.
	NTilde, h1, h2 := big.NewInt(11*23), big.NewInt(4), big.NewInt(9)
	m, r := big.NewInt(1<<24+3), big.NewInt(2)
	require.True(t, m.BitLen() > 8*len(NTilde.Bytes()))
	require.True(t, m.Cmp(tss.EC().Params().N) < 0)
	require.True(t, m.Cmp(pk.N) < 0)
	modN2 := common.ModInt(pk.NSquare())
	c := modN2.Mul(modN2.Exp(pk.Gamma(), m), modN2.Exp(r, pk.N))

	var proofOff *RangeProofAlice
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("CT=%t", enabled), func(t *testing.T) {
			setMTAProofTestMode(t, enabled)
			proof, err := ProveRangeAlice(tss.EC(), pk, c, NTilde, h1, h2, m, r)
			require.NoError(t, err)
			// Compare arithmetic only: this tiny auxiliary modulus is below
			// the production verifier's minimum size.
			if enabled {
				require.Equal(t, proofOff.Bytes(), proof.Bytes(), "fixed randomness must produce identical Alice commitments and responses")
			} else {
				proofOff = proof
			}
		})
	}
}

func TestBobProofUnequalWidthsCTEquivalence(t *testing.T) {
	key := mtaFixtureKey(t)
	pk := &key.PublicKey
	NTilde, h1, h2 := big.NewInt(11*23), big.NewInt(4), big.NewInt(9)
	m, x, r := big.NewInt(1<<24+3), big.NewInt(1<<32+5), big.NewInt(3)
	require.True(t, x.BitLen() > 8*len(NTilde.Bytes()))
	require.True(t, x.Cmp(tss.EC().Params().N) < 0)
	require.True(t, x.Cmp(pk.N) < 0)
	X := crypto.ScalarBaseMult(tss.EC(), x)
	modN2 := common.ModInt(pk.NSquare())
	c1 := modN2.Mul(modN2.Exp(pk.Gamma(), m), modN2.Exp(big.NewInt(2), pk.N))

	// Fixed y values cross several byte boundaries, then reach the top of the
	// Paillier domain. Even the largest is a valid betaPrm plaintext (y < pk.N).
	yValues := []*big.Int{
		big.NewInt(0), big.NewInt(255), big.NewInt(256),
		big.NewInt(65535), big.NewInt(65536),
		big.NewInt(1<<24 - 1), big.NewInt(1 << 24),
		new(big.Int).Sub(pk.N, big.NewInt(1)),
	}
	for _, y := range yValues {
		t.Run(fmt.Sprintf("y_bits=%d", y.BitLen()), func(t *testing.T) {
			require.True(t, y.Cmp(pk.N) < 0)
			cY := modN2.Mul(modN2.Exp(pk.Gamma(), y), modN2.Exp(r, pk.N))
			c2 := modN2.Mul(modN2.Exp(c1, x), cY)
			var proofOff *ProofBob
			var proofWCOff *ProofBobWC
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("CT=%t", enabled), func(t *testing.T) {
					setMTAProofTestMode(t, enabled)
					proof, err := ProveBob(tss.EC(), pk, NTilde, h1, h2, c1, c2, x, y, r)
					require.NoError(t, err)
					proofWC, err := ProveBobWC(tss.EC(), pk, NTilde, h1, h2, c1, c2, x, y, r, X)
					require.NoError(t, err)
					if enabled {
						require.Equal(t, proofOff.Bytes(), proof.Bytes(), "fixed randomness must produce identical Bob commitments and responses")
						require.Equal(t, proofWCOff.Bytes(), proofWC.Bytes(), "fixed randomness must produce identical Bob WC commitments and responses")
					} else {
						proofOff, proofWCOff = proof, proofWC
					}
				})
			}
		})
	}
}

// TestShareProtocolUnequalWidthsCTEquivalence restores the #10 regression guard that
// #17 dropped: a byte-exact comparison of the complete MtA share-protocol transcript
// (AliceInit -> BobMid/BobMidWC -> AliceEnd/AliceEndWC, including all proof bytes, the
// homomorphic ciphertexts, and the decrypted shares) across constant-time ops off vs
// on. With a fixed replayed entropy stream, every randomized commitment and blind is
// identical in both modes, so the two transcripts must be byte-identical. That
// determinism invariant is the guard: if a future change makes the CT path diverge
// from the math/big path for a secret-exponent operation in the full share protocol —
// for example reintroducing a padding width derived from the auxiliary modulus instead
// of the public plaintext bound, or a width change that breaks determinism — the CT-on
// transcript will stop matching the CT-off one and this test fails.
//
// The protocol's internal Verify calls must complete, so the keygen fixture's ~2048-bit
// auxiliary moduli are used instead of #10's tiny 11*23 modulus, which the current
// hardened verifiers reject (MinUnknownOrderModulusBitLen floor). The witness betaPrm is a
// q5-width random that can approach the public plaintext domain width; it is a valid
// Paillier plaintext and the homomorphic result does not wrap the domain.
func TestShareProtocolUnequalWidthsCTEquivalence(t *testing.T) {
	key := mtaFixtureKey(t)
	pk := &key.PublicKey
	q := tss.EC().Params().N

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	require.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	require.NoError(t, err)
	// The fixture auxiliary moduli must clear the verifier floor so the full share
	// protocol's internal Verify calls complete.
	require.True(t, common.IsUsableUnknownOrderModulus(NTildei, common.MinUnknownOrderModulusBitLen), "fixture auxiliary modulus must clear the verifier floor")
	require.True(t, common.IsUsableUnknownOrderModulus(NTildej, common.MinUnknownOrderModulusBitLen), "fixture auxiliary modulus must clear the verifier floor")

	a, b := big.NewInt(1<<24+3), big.NewInt(1<<32+5)
	B := crypto.ScalarBaseMult(tss.EC(), b)
	want := new(big.Int).Mod(new(big.Int).Mul(a, b), q)

	for _, withCheck := range []bool{false, true} {
		t.Run(fmt.Sprintf("WC=%t", withCheck), func(t *testing.T) {
			var transcriptOff [][]byte
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("CT=%t", enabled), func(t *testing.T) {
					setMTAProofTestMode(t, enabled)
					cA, proofA, err := AliceInit(tss.EC(), pk, a, NTildej, h1j, h2j)
					require.NoError(t, err)
					var alpha, beta, cB, betaPrm *big.Int
					var proofBytes [][]byte
					if withCheck {
						var proofB *ProofBobWC
						beta, cB, betaPrm, proofB, err = BobMidWC(tss.EC(), pk, proofA, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j, B)
						require.NoError(t, err)
						alpha, err = AliceEndWC(tss.EC(), pk, proofB, B, cA, cB, NTildei, h1i, h2i, key)
						require.NoError(t, err)
						proofBWCParts := proofB.Bytes()
						proofBytes = proofBWCParts[:]
					} else {
						var proofB *ProofBob
						beta, cB, betaPrm, proofB, err = BobMid(tss.EC(), pk, proofA, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j)
						require.NoError(t, err)
						alpha, err = AliceEnd(tss.EC(), pk, proofB, h1i, h2i, cA, cB, NTildei, key)
						require.NoError(t, err)
						proofBParts := proofB.Bytes()
						proofBytes = proofBParts[:]
					}
					// betaPrm is a valid Paillier plaintext and the homomorphic result
					// does not wrap the plaintext domain.
					require.True(t, betaPrm.Cmp(pk.N) < 0, "betaPrm must be a valid Paillier plaintext")
					require.True(t, new(big.Int).Add(new(big.Int).Mul(a, b), betaPrm).Cmp(pk.N) < 0, "fixed transcript must avoid Paillier plaintext wraparound")
					require.Zero(t, common.ModInt(q).Add(alpha, beta).Cmp(want), "MtA shares must sum to a*b mod q")
					transcript := append([][]byte{cA.Bytes(), cB.Bytes(), betaPrm.Bytes(), alpha.Bytes(), beta.Bytes()}, proofBytes...)
					aliceParts := proofA.Bytes()
					transcript = append(transcript, aliceParts[:]...)
					if enabled {
						require.Equal(t, transcriptOff, transcript, "fixed randomness must produce identical complete MtA transcripts")
					} else {
						transcriptOff = transcript
					}
				})
			}
		})
	}
}

// These tests verify that the MtA flow run with constant-time ops enabled — which
// hardens the secret-witness exponentiations h1^x, h1^y (proofs.go) and h1^m
// (range_proof.go), plus the secret-exponent Paillier Encrypt (gamma^m) and HomoMult
// (c1^m) — still produces verifying proofs and the correct homomorphic result. The
// proofs are randomised, so outputs are not byte-identical across paths; the protocol
// completing and the result matching is the invariant. Primitive ExpCT==Exp / MulCT==Mul
// equivalence is covered in common/constant_time_test.go.

// TestShareProtocolWCConstantTime runs the full MtA "with check" share protocol with
// constant-time ops enabled. It exercises ProveRangeAlice (h1^m via AliceInit),
// ProveBobWC (h1^x, h1^y with x=b, y=betaPrm via BobMidWC), and the CT Paillier
// Encrypt/HomoMult paths, with proof verification happening inside BobMidWC/AliceEndWC.
func TestShareProtocolWCConstantTime(t *testing.T) {
	q := tss.EC().Params().N

	sk, pk, err := loadPaillierKeyFixture(12)
	assert.NoError(t, err)

	a := common.GetRandomPositiveInt(q)
	b := common.GetRandomPositiveInt(q)
	gBX, gBY := tss.EC().ScalarBaseMult(b.Bytes())

	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	assert.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	assert.NoError(t, err)

	previousMode := common.IsConstantTimeEnabled()
	t.Cleanup(func() {
		if previousMode {
			common.EnableConstantTimeOps()
		} else {
			common.DisableConstantTimeOps()
		}
	})
	common.EnableConstantTimeOps()
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")

	cA, pf, err := AliceInit(tss.EC(), pk, a, NTildej, h1j, h2j)
	assert.NoError(t, err)

	gBPoint, err := crypto.NewECPoint(tss.EC(), gBX, gBY)
	assert.NoError(t, err)
	_, cB, betaPrm, pfB, err := BobMidWC(tss.EC(), pk, pf, b, cA, NTildei, h1i, h2i, NTildej, h1j, h2j, gBPoint)
	assert.NoError(t, err)

	alpha, err := AliceEndWC(tss.EC(), pk, pfB, gBPoint, cA, cB, NTildei, h1i, h2i, sk)
	assert.NoError(t, err)

	// expect: alpha = ab + betaPrm (mod q) — proves the CT-hardened proofs verified and
	// the CT Encrypt/HomoMult produced the correct homomorphic ciphertext.
	aTimesB := new(big.Int).Mul(a, b)
	aTimesBPlusBeta := new(big.Int).Add(aTimesB, betaPrm)
	aTimesBPlusBetaModQ := new(big.Int).Mod(aTimesBPlusBeta, q)
	assert.Equal(t, 0, alpha.Cmp(aTimesBPlusBetaModQ), "constant-time MtA must yield alpha = ab + betaPrm")
}

// TestMtaProversAtCurveOrderEdge pins the constant-time exponent widths at
// the top of the curve-order witness domain: x = q-1 for ProveBob and
// ProveBobWC, m = q-1 for ProveRangeAlice, and b = q-1 for BobMid and
// BobMidWC. These witnesses use the full q.BitLen() width, so an exponent
// padded to fewer bits panics or gives a wrong result.
func TestMtaProversAtCurveOrderEdge(t *testing.T) {
	key := mtaFixtureKey(t)
	pk := &key.PublicKey
	NTildei, h1i, h2i, err := keygen.LoadNTildeH1H2FromTestFixture(0)
	require.NoError(t, err)
	NTildej, h1j, h2j, err := keygen.LoadNTildeH1H2FromTestFixture(1)
	require.NoError(t, err)
	ec := tss.EC()
	q := ec.Params().N
	qMinus1 := new(big.Int).Sub(q, one)
	require.Equal(t, q.BitLen(), qMinus1.BitLen())

	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("CT=%t", enabled), func(t *testing.T) {
			setMTAProofTestMode(t, enabled)

			t.Run("ProveRangeAlice m = q-1", func(t *testing.T) {
				c, r, err := key.EncryptAndReturnRandomness(qMinus1)
				require.NoError(t, err)
				proof, err := ProveRangeAlice(ec, pk, c, NTildei, h1i, h2i, qMinus1, r)
				require.NoError(t, err)
				assert.True(t, proof.Verify(ec, pk, NTildei, h1i, h2i, c))
			})

			t.Run("ProveBob and ProveBobWC x = q-1", func(t *testing.T) {
				y, r := big.NewInt(11), firstSmallUnit(pk.N, 2)
				c1 := fixedPaillierEncryption(pk, big.NewInt(5), firstSmallUnit(pk.N, 3))
				c2 := c2ForWitness(t, ec, pk, c1, qMinus1, y, r)
				X := crypto.ScalarBaseMult(ec, qMinus1)
				proofBob, err := ProveBob(ec, pk, NTildei, h1i, h2i, c1, c2, qMinus1, y, r)
				require.NoError(t, err)
				assert.True(t, proofBob.Verify(ec, pk, NTildei, h1i, h2i, c1, c2), "ProveBob")
				proofBobWC, err := ProveBobWC(ec, pk, NTildei, h1i, h2i, c1, c2, qMinus1, y, r, X)
				require.NoError(t, err)
				assert.True(t, proofBobWC.Verify(ec, pk, NTildei, h1i, h2i, c1, c2, X), "ProveBobWC")
			})

			t.Run("BobMid and BobMidWC b = q-1", func(t *testing.T) {
				a := big.NewInt(424242)
				cA, pfA, err := AliceInit(ec, pk, a, NTildej, h1j, h2j)
				require.NoError(t, err)
				// Alice's share must equal a*b + betaPrm mod q.
				want := func(betaPrm *big.Int) *big.Int {
					v := new(big.Int).Mul(a, qMinus1)
					v.Add(v, betaPrm)
					return v.Mod(v, q)
				}

				_, cB, betaPrm, pfB, err := BobMid(ec, pk, pfA, qMinus1, cA, NTildei, h1i, h2i, NTildej, h1j, h2j)
				require.NoError(t, err)
				alpha, err := AliceEnd(ec, pk, pfB, h1i, h2i, cA, cB, NTildei, key)
				require.NoError(t, err)
				assert.Zero(t, alpha.Cmp(want(betaPrm)), "BobMid share")

				B := crypto.ScalarBaseMult(ec, qMinus1)
				_, cBWC, betaPrmWC, pfBWC, err := BobMidWC(ec, pk, pfA, qMinus1, cA, NTildei, h1i, h2i, NTildej, h1j, h2j, B)
				require.NoError(t, err)
				alphaWC, err := AliceEndWC(ec, pk, pfBWC, B, cA, cBWC, NTildei, h1i, h2i, key)
				require.NoError(t, err)
				assert.Zero(t, alphaWC.Cmp(want(betaPrmWC)), "BobMidWC share")
			})
		})
	}
}
