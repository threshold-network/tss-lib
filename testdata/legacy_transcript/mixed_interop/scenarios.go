package main

import (
	"crypto/elliptic"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"

	cryptorand "crypto/rand"

	"github.com/bnb-chain/tss-lib/common"
	"github.com/bnb-chain/tss-lib/crypto"
	"github.com/bnb-chain/tss-lib/crypto/mta"
	"github.com/bnb-chain/tss-lib/crypto/paillier"
	"github.com/bnb-chain/tss-lib/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/ecdsa/signing"
	"github.com/bnb-chain/tss-lib/tss"
)

// ---- deterministic randomness (host side) ----

type deterministicReader struct {
	seed    []byte
	mu      sync.Mutex
	counter uint64
	buffer  []byte
}

// Read is safe for concurrent use: this implementation's signing rounds draw
// fresh MtA blinding randomness for a peer's Bob and BobWC proofs from two
// goroutines running concurrently (round_2.go), and both draw from the
// process-global crypto/rand.Reader this function replaces. Serializing
// access to the counter/buffer keystream state avoids torn reads that would
// otherwise corrupt both goroutines' values.
func (r *deterministicReader) Read(output []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	total := len(output)
	for len(output) > 0 {
		if len(r.buffer) == 0 {
			counter := make([]byte, 8)
			binary.BigEndian.PutUint64(counter, r.counter)
			digest := sha512.Sum512(append(append([]byte{}, r.seed...), counter...))
			r.buffer = digest[:]
			r.counter++
		}
		copied := copy(output, r.buffer)
		output = output[copied:]
		r.buffer = r.buffer[copied:]
	}
	return total, nil
}

func fixedRandom(label string) func() {
	original := cryptorand.Reader
	cryptorand.Reader = &deterministicReader{seed: []byte("mixed-interop/" + label)}
	return func() { cryptorand.Reader = original }
}

// ---- scenario machinery ----

// roundNumberOf identifies the signing-round number of a message purely from
// its concrete protobuf content type, never from error text or any other
// source-derived string.
func roundNumberOf(m tss.Message) int {
	pm, ok := m.(tss.ParsedMessage)
	if !ok {
		return 0
	}
	switch pm.Content().(type) {
	case *signing.SignRound1Message1, *signing.SignRound1Message2:
		return 1
	case *signing.SignRound2Message:
		return 2
	case *signing.SignRound3Message:
		return 3
	case *signing.SignRound4Message:
		return 4
	case *signing.SignRound5Message:
		return 5
	case *signing.SignRound6Message:
		return 6
	case *signing.SignRound7Message:
		return 7
	case *signing.SignRound8Message:
		return 8
	case *signing.SignRound9Message:
		return 9
	default:
		return 0
	}
}

type scenarioResult struct {
	Name string `json:"name"`
	// Behavioral: default rejection. RejectionRound and the peer culprit count
	// come from *tss.Error's structured Round()/Culprits() accessors, never
	// from parsing RejectionErr's text. Both round-3 verifier goroutines must
	// independently attribute their failure to the historical peer.
	DefaultRejected           bool   `json:"default_rejected"`
	RejectionRound            int    `json:"rejection_round,omitempty"`
	RejectionPeerCulpritCount int    `json:"rejection_peer_culprit_count"`
	AliceEmittedRound3        bool   `json:"alice_emitted_round3"`
	RejectionErr              string `json:"rejection_err,omitempty"`
	// Behavioral: acceptance/progress
	Accepted        bool `json:"accepted"`
	AliceProgressed bool `json:"alice_progressed"`
	// Per-actor round-8 boundary evidence. Each actor's first round-8-or-
	// later message is captured as evidence and dropped (never forwarded);
	// lower-round pending messages keep flowing until BOTH sides have
	// emitted round 8, at which point the exchange stops.
	AliceReachedRound8 bool `json:"alice_reached_round_8"`
	BobReachedRound8   bool `json:"bob_reached_round_8"`
	Completed          bool `json:"completed"`
	// Per-proof verification: tight bound
	WitnessBobT1    string `json:"witness_bob_t1,omitempty"`
	WitnessBobWCT1  string `json:"witness_bob_wc_t1,omitempty"`
	TightBound      string `json:"tight_bound,omitempty"`
	AboveTightBound bool   `json:"above_tight_bound"`
	// Per-proof assertions (independent Bob vs BobWC, compat off vs on)
	BobProofOff   bool `json:"bob_proof_off"`
	BobWCProofOff bool `json:"bob_wc_proof_off"`
	BobProofOn    bool `json:"bob_proof_on"`
	BobWCProofOn  bool `json:"bob_wc_proof_on"`
}

// round8BothReached reports the documented termination condition: BOTH actors
// have emitted a round-8-or-later message. Round-8-or-later messages are
// captured and dropped, never forwarded, so the exchange stops exactly when
// both directions have reached the round-8 boundary and the threshold-
// mismatched fixture can never run into round 9.
func (r *scenarioResult) round8BothReached() bool {
	return r.AliceReachedRound8 && r.BobReachedRound8
}

const fixedMessageHex = "00f163ee51bcaeff9cdff5e0e3c1a646abd19885fffbab0b3b4236e0cf95c9f5"

// verifyBobProof calls ProofBob.VerifyLegacy against the given public inputs,
// with the compat flag set to the supplied value. Returns true iff the proof
// verifies successfully.
func verifyBobProof(pf *mta.ProofBob, ec elliptic.Curve, pk *paillier.PublicKey,
	NTilde, h1, h2, c1, c2 *big.Int, compat bool) bool {
	if pf == nil {
		return false
	}
	return pf.VerifyLegacy(ec, pk, NTilde, h1, h2, c1, c2, compat)
}

// verifyBobWCProof calls ProofBobWC.VerifyLegacy against the given public
// inputs, with the compat flag set to the supplied value. Returns true iff the
// proof verifies successfully.
func verifyBobWCProof(pf *mta.ProofBobWC, ec elliptic.Curve, pk *paillier.PublicKey,
	NTilde, h1, h2, c1, c2 *big.Int, B *crypto.ECPoint, compat bool) bool {
	if pf == nil || pf.ProofBob == nil || B == nil {
		return false
	}
	return pf.VerifyLegacy(ec, pk, NTilde, h1, h2, c1, c2, B, compat)
}

// verifyPerProofIndependently extracts Bob's captured round-2 message and
// verifies the Bob and BobWC proofs independently (each against its own
// tight/loose compat flag), storing the four results on result. Called from
// every exit path of runMixedScenario — including the early return on
// rejection — since capturedBobR2/aliceCA are already fully populated by the
// time round 3 verification runs; skipping this on the rejection path would
// silently leave the four fields at their zero value instead of reporting a
// genuine verification outcome.
func verifyPerProofIndependently(result *scenarioResult, capturedBobR2 *signing.SignRound2Message, aliceCA *big.Int, keys []keygen.LocalPartySaveData, partyIDs tss.SortedPartyIDs, ec elliptic.Curve) {
	if capturedBobR2 == nil || aliceCA == nil {
		return
	}
	pfBob, _ := capturedBobR2.UnmarshalProofBob()
	pfBobWC, _ := capturedBobR2.UnmarshalProofBobWC(ec)

	// ProofBob and ProofBobWC public inputs, per the exact call convention
	// in ecdsa/signing/round_3.go's Alice_end/Alice_end_wc goroutines: the
	// MtA scheme runs entirely under Alice's own Paillier key and
	// Ring-Pedersen parameters (Bob homomorphically operates on Alice's
	// ciphertext and proves he did so correctly against Alice's trusted
	// setup, which only Alice can verify).
	// - pk = Alice's OWN Paillier public key (not Bob's)
	// - NTilde, h1, h2 = Alice's own Ring-Pedersen parameters
	// - c1 = Alice's own round-1 MtA ciphertext to Bob (cA; shared by both
	//   proofs)
	// - c2 = Bob's round-2 response for that specific proof: C1 for Bob,
	//   C2 for BobWC (per NewSignRound2Message's field order)
	// - B = Bob's EC contribution, the same public value round_3.go's
	//   bigWs[j] resolves to via PrepareForSigning
	bobIdx := partyIDs[1].Index
	aliceIdx := partyIDs[0].Index

	pkAlice := keys[aliceIdx].PaillierPKs[aliceIdx]
	NTildeA := keys[aliceIdx].NTildei
	h1A := keys[aliceIdx].H1i
	h2A := keys[aliceIdx].H2i
	cBBob := new(big.Int).SetBytes(capturedBobR2.GetC1())
	cBBobWC := new(big.Int).SetBytes(capturedBobR2.GetC2())

	// B must be Alice's own PrepareForSigning-derived bigWs[bobIdx], not a
	// raw BigXj[bobIdx]: PrepareForSigning applies a Lagrange scalar
	// multiplication across every party's Shamir share (prepare.go), and
	// the party count it must use is the *signing session's* party count
	// (2), not the fixture file's underlying 20-party keygen ceremony.
	// Production's NewLocalPartyWithKDD reslices to the session's party
	// count via keygen.BuildLocalSaveDataSubset before ever calling
	// PrepareForSigning (see ecdsa/signing/local_party.go); replaying
	// PrepareForSigning against the raw, un-resliced 20-party fixture data
	// would silently compute the wrong Lagrange coefficients.
	aliceSubset := keygen.BuildLocalSaveDataSubset(keys[aliceIdx], partyIDs)
	var B *crypto.ECPoint
	if _, bigWs, pfsErr := signing.PrepareForSigning(
		ec, aliceIdx, len(aliceSubset.Ks), aliceSubset.Xi,
		aliceSubset.Ks, aliceSubset.BigXj,
	); pfsErr == nil && bobIdx < len(bigWs) {
		B = bigWs[bobIdx]
	}

	result.BobProofOff = pfBob != nil && verifyBobProof(pfBob, ec, pkAlice, NTildeA, h1A, h2A, aliceCA, cBBob, false)
	result.BobProofOn = pfBob != nil && verifyBobProof(pfBob, ec, pkAlice, NTildeA, h1A, h2A, aliceCA, cBBob, true)

	if B != nil {
		result.BobWCProofOff = pfBobWC != nil && verifyBobWCProof(pfBobWC, ec, pkAlice, NTildeA, h1A, h2A, aliceCA, cBBobWC, B, false)
		result.BobWCProofOn = pfBobWC != nil && verifyBobWCProof(pfBobWC, ec, pkAlice, NTildeA, h1A, h2A, aliceCA, cBBobWC, B, true)
	}
}

// runMixedScenario drives one live ceremony between a current-implementation
// Alice (party index 0, in this process) and a historical subprocess Bob
// (party index 1), asserting the given compatibility configuration. Each run
// is a fresh exchange: the current side and the pinned historical subprocess
// each draw their own deterministic seeds, so no two runs share one random
// stream or one identical wire transcript.
//
// The exchange is deliberately bounded to round 8: this repository's own
// existing round3Fixture (ecdsa/signing/round_3_test.go) and
// historicalBobProofForWitnessY (crypto/mta/legacy_bob_historical_witness_test.go)
// already establish the precedent of driving a 2-of-20 minimal subset of the
// test/_ecdsa_fixtures keygen fixtures (threshold=1, not the fixture set's
// real threshold=10) for exactly this kind of round-level interop check.
// That minimal subset is sufficient for every per-peer MtA/Schnorr check
// through round 8 (each is a property of the two parties' own consistent
// local computation), but round 9's final aggregate check (U == T) verifies
// a *global* Shamir reconstruction identity that only holds for a
// correctly-sized threshold+1 co-signer set.
//
// The round-8 boundary is tracked per actor: the current party's first
// round-8-or-later outbound message and the historical peer's first
// round-8-or-later event are each captured as evidence and dropped, never
// forwarded. Only lower-round pending messages keep flowing, until BOTH
// sides have emitted round 8; the loop then stops. Because round-8-or-
// later messages are never delivered, the threshold-mismatched fixture can
// never cascade into round 9's global reconstruction check. Reaching a real,
// live-exchanged round 8 on both sides already proves the historical
// Bob/BobWC witness was accepted and every subsequent round-3..8
// verification/decommitment step (Bob_end, the Gamma/Schnorr proofs, and
// both decommitments) succeeded against a genuine historical binary.
//
// Independently of the live ceremony, each run's captured historical Bob and
// BobWC proofs are re-verified pairwise against the actual captured wire
// bytes — each against both the tight N+q^6 bound (compat off) and the
// widened historical bound (compat on) — so acceptance is paired per proof,
// not inferred from a shared, identical replay.
func runMixedScenario(name, seedSuffix string, historicalDir string, compat bool) (*scenarioResult, error) {
	restore := fixedRandom("alice-" + seedSuffix)
	defer restore()

	keys, partyIDs, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil {
		return nil, fmt.Errorf("load keygen fixtures: %w", err)
	}
	ec := tss.S256()
	alicePK := &keys[0].PaillierSK.PublicKey
	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	q6 := new(big.Int).Mul(q3, q3)
	tightBound := new(big.Int).Add(alicePK.N, q6)

	ctx := tss.NewPeerContext(partyIDs)
	params := tss.NewParameters(ec, ctx, partyIDs[0], 2, 1)
	params.SetProtocolMode(tss.ProtocolModeLegacy)
	if compat {
		params.SetLegacyHistoricalBobCompatibility(true)
	}

	msg := new(big.Int)
	msg.SetString(fixedMessageHex, 16)
	msgBytes, _ := hex.DecodeString(fixedMessageHex)

	outCh := make(chan tss.Message, 16)
	endCh := make(chan common.SignatureData, 1)
	alice := signing.NewLocalParty(msg, params, keys[0], outCh, endCh, len(msgBytes))

	peer, err := spawnHistoricalPeer(historicalDir)
	if err != nil {
		return nil, fmt.Errorf("spawn historical peer: %w", err)
	}
	defer peer.quit()

	if err := peer.send(command{Cmd: "init", Seed: "bob-" + seedSuffix, MessageHex: fixedMessageHex}); err != nil {
		return nil, fmt.Errorf("send init: %w", err)
	}
	peerEvents, err := peer.readTurn()
	if err != nil {
		return nil, fmt.Errorf("read historical init turn: %w", err)
	}

	if err := alice.Start(); err != nil {
		return nil, fmt.Errorf("alice start: %w", err)
	}

	result := &scenarioResult{Name: name, TightBound: tightBound.Text(16)}

	var pendingToBob []tss.Message
	var pendingToAlice []event
	// aliceCA captures Alice's own round-1 MtA ciphertext to Bob (the "cA"
	// input shared by both the Bob and BobWC per-proof verifications
	// below); it is not otherwise observable from Bob's round-2 message.
	var aliceCA *big.Int

	drainOut := func() {
		for {
			select {
			case m := <-outCh:
				rnd := roundNumberOf(m)
				if rnd == 3 {
					result.AliceEmittedRound3 = true
				}
				if rnd >= 8 {
					// Round-8-or-later output is the per-actor boundary
					// evidence: capture it on result, drop it (never
					// forward it to the historical peer), and keep
					// delivering only lower-round pending messages until
					// the other side also emits round 8.
					result.AliceReachedRound8 = true
				} else {
					pendingToBob = append(pendingToBob, m)
				}
				if aliceCA == nil {
					if pm, ok := m.(tss.ParsedMessage); ok {
						if r1msg1, ok := pm.Content().(*signing.SignRound1Message1); ok {
							aliceCA = r1msg1.UnmarshalC()
						}
					}
				}
			case <-endCh:
				result.Completed = true
			default:
				return
			}
		}
	}
	drainOut()
	pendingToAlice = append(pendingToAlice, peerEvents...)

	// captureRound2 captures the first historical Bob round-2 message and
	// records the raw T1 scalar values for each proof.
	var capturedBobR2 *signing.SignRound2Message

	captureWitness := func(e event) {
		if capturedBobR2 != nil {
			return
		}
		wireBytes, decErr := hex.DecodeString(e.WireHex)
		if decErr != nil {
			return
		}
		parsed, parseErr := tss.ParseWireMessage(wireBytes, partyIDs[1], e.IsBroadcast)
		if parseErr != nil {
			return
		}
		r2msg, ok := parsed.Content().(*signing.SignRound2Message)
		if !ok {
			return
		}
		capturedBobR2 = r2msg
		bob, bErr := r2msg.UnmarshalProofBob()
		if bErr == nil && bob != nil {
			result.WitnessBobT1 = bob.T1.Text(16)
			result.AboveTightBound = bob.T1.Cmp(tightBound) >= 0
		}
		bobWC, wcErr := r2msg.UnmarshalProofBobWC(ec)
		if wcErr == nil && bobWC != nil {
			result.WitnessBobWCT1 = bobWC.T1.Text(16)
			if bobWC.T1.Cmp(tightBound) < 0 {
				result.AboveTightBound = false
			}
		}
	}

pump:
	for len(pendingToBob) > 0 || len(pendingToAlice) > 0 {
		// Termination rule: once BOTH actors have emitted a round-8-or-
		// later message (each captured and dropped, never forwarded), stop.
		// Because round-8-or-later messages are never delivered onward, the
		// threshold-mismatched fixture can never reach round 9.
		if result.round8BothReached() {
			break pump
		}
		for _, m := range pendingToBob {
			// pendingToBob holds only lower-round messages: drainOut drops
			// the current party's round-8-or-later output as per-actor
			// boundary evidence, so nothing here reaches round 9.
			wireBytes, _, wErr := m.WireBytes()
			if wErr != nil {
				return nil, fmt.Errorf("alice wire bytes: %w", wErr)
			}
			if sErr := peer.send(command{Cmd: "deliver", IsBroadcast: m.IsBroadcast(), WireHex: hex.EncodeToString(wireBytes)}); sErr != nil {
				return nil, fmt.Errorf("send deliver to historical peer: %w", sErr)
			}
			events, rErr := peer.readTurn()
			if rErr != nil {
				return nil, fmt.Errorf("read historical peer turn: %w", rErr)
			}
			for _, e := range events {
				switch e.Event {
				case "message":
					pendingToAlice = append(pendingToAlice, e)
				case "signature":
				case "error":
					return nil, fmt.Errorf("historical peer reported an unexpected error: %s", e.Message)
				}
			}
		}
		pendingToBob = nil

		toDeliver := pendingToAlice
		pendingToAlice = nil
		for _, e := range toDeliver {
			captureWitness(e)
			wireBytes, decErr := hex.DecodeString(e.WireHex)
			if decErr != nil {
				return nil, fmt.Errorf("decode historical wire hex: %w", decErr)
			}
			if parsed, pErr := tss.ParseWireMessage(wireBytes, partyIDs[1], e.IsBroadcast); pErr == nil {
				if roundNumberOf(parsed) >= 8 {
					// Per-actor boundary evidence: capture the historical
					// side's round-8-or-later message and drop it (never
					// forward it), then keep delivering the remaining
					// lower-round pending messages until the current side
					// also emits round 8.
					result.BobReachedRound8 = true
					continue
				}
			}
			ok, aErr := alice.UpdateFromBytes(wireBytes, partyIDs[1], e.IsBroadcast)
			if aErr != nil {
				result.DefaultRejected = true
				result.RejectionErr = aErr.Error()
				// Structural (non-text) constraints on the rejection: it
				// must be tss.Error's own Round()==3, and both production
				// verifier failures must attribute the historical peer.
				result.RejectionRound = aErr.Round()
				for _, culprit := range aErr.Culprits() {
					if culprit.Index == partyIDs[1].Index {
						result.RejectionPeerCulpritCount++
					}
				}
				// UpdateFromBytes may enqueue output before returning an
				// error. Observe that output before asserting fail-closed.
				drainOut()
				verifyPerProofIndependently(result, capturedBobR2, aliceCA, keys, partyIDs, ec)
				return result, nil
			}
			_ = ok
			result.AliceProgressed = true
		}
		drainOut()
	}

	// Per-proof independent verification: extract Bob's round-2 message
	// from the pump's captured state, unmarshal each proof, and verify
	// them independently with compat=false and compat=true. This asserts
	// that each proof individually (Bob and BobWC) rejects at the tight
	// bound and accepts at the loose bound, catching a regression where
	// only one proof path is correctly wired.
	verifyPerProofIndependently(result, capturedBobR2, aliceCA, keys, partyIDs, ec)

	if compat {
		result.Accepted = true
	}
	return result, nil
}
