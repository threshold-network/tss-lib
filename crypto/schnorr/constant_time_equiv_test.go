// Copyright © 2019-2026 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package schnorr_test

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	mathrand "math/rand/v2"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	. "github.com/bnb-chain/tss-lib/crypto/schnorr"
	"github.com/bnb-chain/tss-lib/tss"
)

// seededReader adapts math/rand/v2's *Rand (which dropped the Read method
// that math/rand exposed) to io.Reader, so it can substitute for
// crypto/rand.Reader in tests that need a deterministic byte stream. PCG with
// fixed (seed1, seed2) is reproducible across runs; the filler consumes the
// stream in 8-byte Little-Endian chunks.
type seededReader struct{ r *mathrand.Rand }

func newSeededReader(seed1, seed2 uint64) io.Reader {
	return seededReader{r: mathrand.New(mathrand.NewPCG(seed1, seed2))}
}

func (s seededReader) Read(p []byte) (int, error) {
	n := len(p)
	for len(p) >= 8 {
		binary.LittleEndian.PutUint64(p, s.r.Uint64())
		p = p[8:]
	}
	if len(p) > 0 {
		u := s.r.Uint64()
		for i := range p {
			p[i] = byte(u >> (8 * i))
		}
	}
	return n, nil
}

// withCTMode saves the ambient constant-time mode, sets it to `enabled`, and
// restores the saved mode on cleanup. CT is enabled by default in this library,
// so tests that want a genuine non-CT baseline must disable it explicitly rather
// than assume it is off; restoring afterwards keeps coverage independent of test
// order and preserves default-path coverage for the other Schnorr tests.
func withCTMode(t *testing.T, enabled bool) {
	t.Helper()
	prev := common.IsConstantTimeEnabled()
	if enabled {
		common.EnableConstantTimeOps()
	} else {
		common.DisableConstantTimeOps()
	}
	t.Cleanup(func() {
		if prev {
			common.EnableConstantTimeOps()
		} else {
			common.DisableConstantTimeOps()
		}
	})
}

// TestSchnorrProofCTVerifies builds a valid ZK proof instance exactly as
// TestSchnorrProofVerify does, then checks that a proof generated with
// constant-time ops enabled still verifies, alongside the standard (non-CT)
// baseline. The proof is randomised, so this asserts correctness of the CT
// prover; the primitive-level ExpCT==Exp / MulCT==Mul / ModInverseCT==ModInverse
// equivalence is covered in common/constant_time_test.go.
func TestSchnorrProofCTVerifies(t *testing.T) {
	q := tss.EC().Params().N
	u := common.GetRandomPositiveInt(q)
	X := crypto.ScalarBaseMult(tss.EC(), u)

	// Replaying this test-only stream makes the random commitments comparable.
	// Both the entropy reader and CT mode are process-wide; cleanup restores
	// their previous values after each subtest. The reader is reset to a fresh
	// copy of the same seed immediately before each proof generation below, so
	// both runs draw identical bytes from offset zero rather than continuing
	// one shared stream (which would make the two draws diverge).
	previousReader := rand.Reader
	t.Cleanup(func() {
		rand.Reader = previousReader
	})

	// Baseline: non-CT proof verifies.
	rand.Reader = newSeededReader(1, 1)
	withCTMode(t, false)
	assert.False(t, common.IsConstantTimeEnabled(), "CT must be off for the baseline")
	proofOff, err := NewZKProof(u, X)
	assert.NoError(t, err)
	assert.True(t, proofOff.Verify(X), "non-CT Schnorr proof must verify")

	// CT proof must also verify and must be byte-identical under matched entropy.
	rand.Reader = newSeededReader(1, 1)
	withCTMode(t, true)
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")
	proofOn, err := NewZKProof(u, X)
	assert.NoError(t, err)
	assert.True(t, proofOn.Verify(X), "CT Schnorr proof must verify")

	assert.True(t, proofOff.Alpha.Equals(proofOn.Alpha), "Alpha must be bit-identical between CT and non-CT paths under matched randomness")
	assert.Zero(t, proofOff.T.Cmp(proofOn.T), "T must be bit-identical between CT and non-CT paths under matched randomness")
}

// TestSchnorrVProofCTVerifies is the ZKVProof analogue of
// TestSchnorrProofCTVerifies.
func TestSchnorrVProofCTVerifies(t *testing.T) {
	q := tss.EC().Params().N
	k := common.GetRandomPositiveInt(q)
	s := common.GetRandomPositiveInt(q)
	l := common.GetRandomPositiveInt(q)
	R := crypto.ScalarBaseMult(tss.EC(), k)
	Rs := R.ScalarMult(s)
	lG := crypto.ScalarBaseMult(tss.EC(), l)
	V, err := Rs.Add(lG)
	assert.NoError(t, err)

	// Replaying this test-only stream makes the random commitments comparable.
	// Both the entropy reader and CT mode are process-wide; cleanup restores
	// their previous values after each subtest. The reader is reset to a fresh
	// copy of the same seed immediately before each proof generation below, so
	// both runs draw identical bytes from offset zero rather than continuing
	// one shared stream (which would make the two draws diverge).
	previousReader := rand.Reader
	t.Cleanup(func() {
		rand.Reader = previousReader
	})

	// Baseline: non-CT proof verifies.
	rand.Reader = newSeededReader(1, 1)
	withCTMode(t, false)
	assert.False(t, common.IsConstantTimeEnabled(), "CT must be off for the baseline")
	proofOff, err := NewZKVProof(V, R, s, l)
	assert.NoError(t, err)
	assert.True(t, proofOff.Verify(V, R), "non-CT Schnorr V proof must verify")

	// CT proof must also verify and must be byte-identical under matched entropy.
	rand.Reader = newSeededReader(1, 1)
	withCTMode(t, true)
	assert.True(t, common.IsConstantTimeEnabled(), "CT must be engaged (else this test is vacuous)")
	proofOn, err := NewZKVProof(V, R, s, l)
	assert.NoError(t, err)
	assert.True(t, proofOn.Verify(V, R), "CT Schnorr V proof must verify")

	assert.True(t, proofOff.Alpha.Equals(proofOn.Alpha), "Alpha must be bit-identical between CT and non-CT paths under matched randomness")
	assert.Zero(t, proofOff.T.Cmp(proofOn.T), "T must be bit-identical between CT and non-CT paths under matched randomness")
	assert.Zero(t, proofOff.U.Cmp(proofOn.U), "U must be bit-identical between CT and non-CT paths under matched randomness")
}
