// Command mixed_interop drives a genuine mixed-binary legacy signing
// ceremony between this checked-out (current) implementation and a
// subprocess running the historical threshold-network/tss-lib@2e712689
// commit, exchanging real GG18/GG20 round wire messages between the two
// processes.
//
// It closes the mixed-binary assurance gap left by in-process fixtures
// (crypto/mta/legacy_bob_historical_witness_test.go,
// ecdsa/signing/round_3_test.go): those pin the *shape* of a historical
// witness using this implementation's own prover equations, which proves the
// verifier's bound math but never exercises an actual historical binary. This
// program instead spawns the pinned historical commit as a child process (the
// two versions share one Go module path and cannot be linked into one
// binary), drives it through a live 2-of-2 signing ceremony opposite a
// current-implementation party in ProtocolModeLegacy, and asserts on the
// resulting behavior:
//
//   - "reject": the historical peer's real, live-drawn Bob/BobWC witness
//     (MtA blinding value sampled below the Paillier modulus N, per the
//     historical BobMid/BobMidWC) produces a round-2 proof whose T1 exceeds
//     the default tight N+q^6 bound; a default-configured current party's
//     round 3 must fail closed.
//   - "accept": the same exchange, replayed against a fresh historical
//     process with the identical deterministic seed (so the witness is
//     provably the same shape), succeeds when the current party opts into
//     SetLegacyHistoricalBobCompatibility(true), and the ceremony provably
//     progresses: the current party emits its round-3 message, the
//     historical peer accepts it, and the live exchange continues through
//     round 8 in both directions (see runMixedScenario's doc comment for why
//     full signature completion is intentionally out of scope here).
//   - "homogeneous-control": two current-implementation parties (no
//     historical subprocess at all) drive the same ceremony shape through
//     round 8 under the default (non-opt-in) configuration, to make clear
//     that "reject" is specific to the historical witness range and not a
//     general legacy-mode defect. This scenario never claims a current-only
//     run is a substitute for the cross-version exchange above.
//
// Usage: mixed_interop <historical-module-dir>
//
// <historical-module-dir> must contain a working `go run ./main.go` for
// testdata/legacy_transcript/historical_signer/main.go, built against the
// go.mod.fixture/go.sum.fixture pin (see verify_mixed_interop.sh).
package main

import (
	"bufio"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"sync"

	"github.com/bnb-chain/tss-lib/common"
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

// ---- subprocess wire protocol ----

type command struct {
	Cmd         string `json:"cmd"`
	Seed        string `json:"seed,omitempty"`
	MessageHex  string `json:"message_hex,omitempty"`
	IsBroadcast bool   `json:"is_broadcast,omitempty"`
	WireHex     string `json:"wire_hex,omitempty"`
}

type event struct {
	Event       string `json:"event"`
	IsBroadcast bool   `json:"is_broadcast,omitempty"`
	WireHex     string `json:"wire_hex,omitempty"`
	Message     string `json:"message,omitempty"`
	RHex        string `json:"r_hex,omitempty"`
	SHex        string `json:"s_hex,omitempty"`
}

type historicalPeer struct {
	cmd    *exec.Cmd
	stdin  *json.Encoder
	stdout *bufio.Scanner
}

func spawnHistoricalPeer(dir string) (*historicalPeer, error) {
	cmd := exec.Command("go", "run", "-mod=readonly", "./main.go")
	cmd.Dir = dir
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	return &historicalPeer{cmd: cmd, stdin: json.NewEncoder(stdin), stdout: scanner}, nil
}

func (h *historicalPeer) send(c command) error {
	return h.stdin.Encode(c)
}

// readTurn reads events until (and excluding) a "turn_done" sentinel.
func (h *historicalPeer) readTurn() ([]event, error) {
	var events []event
	for h.stdout.Scan() {
		line := h.stdout.Bytes()
		if len(line) == 0 {
			continue
		}
		var e event
		if err := json.Unmarshal(line, &e); err != nil {
			return events, fmt.Errorf("decode historical event: %w", err)
		}
		if e.Event == "turn_done" {
			return events, nil
		}
		events = append(events, e)
	}
	return events, fmt.Errorf("historical subprocess closed stdout before turn_done")
}

func (h *historicalPeer) quit() {
	_ = h.send(command{Cmd: "quit"})
	_ = h.cmd.Wait()
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
	Name            string `json:"name"`
	DefaultRejected bool   `json:"default_rejected"`
	RejectionErr    string `json:"rejection_err,omitempty"`
	Accepted        bool   `json:"accepted"`
	AliceProgressed bool   `json:"alice_progressed"`
	ReachedRound8   bool   `json:"reached_round_8"`
	Completed       bool   `json:"completed"`
	AliceR          string `json:"alice_r,omitempty"`
	AliceS          string `json:"alice_s,omitempty"`
	PeerR           string `json:"peer_r,omitempty"`
	PeerS           string `json:"peer_s,omitempty"`
	WitnessBobT1    string `json:"witness_bob_t1,omitempty"`
	WitnessBobWCT1  string `json:"witness_bob_wc_t1,omitempty"`
	TightBound      string `json:"tight_bound,omitempty"`
	AboveTightBound bool   `json:"above_tight_bound"`
}

const fixedMessageHex = "00f163ee51bcaeff9cdff5e0e3c1a646abd19885fffbab0b3b4236e0cf95c9f5"

// runMixedScenario drives one live ceremony between a current-implementation
// Alice (party index 0, in this process) and a historical subprocess Bob
// (party index 1), asserting the given compatibility configuration.
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
// correctly-sized threshold+1 co-signer set. Reaching a real, live-exchanged
// round 8 message already proves the historical Bob/BobWC witness was
// accepted and every subsequent round-3..8 verification/decommitment step
// (Bob_end, the Gamma/Schnorr proofs, and both decommitments) succeeded
// against a genuine historical binary; deliberately stopping there avoids an
// unrelated, expected reconstruction mismatch rather than masking a real one.
func runMixedScenario(name, seedSuffix string, historicalDir string, compat bool) (*scenarioResult, error) {
	restore := fixedRandom("alice-" + seedSuffix)
	defer restore()

	keys, partyIDs, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil {
		return nil, fmt.Errorf("load keygen fixtures: %w", err)
	}
	ec := tss.S256()
	pk := &keys[0].PaillierSK.PublicKey
	q := ec.Params().N
	q3 := new(big.Int).Mul(q, q)
	q3 = new(big.Int).Mul(q, q3)
	q6 := new(big.Int).Mul(q3, q3)
	tightBound := new(big.Int).Add(pk.N, q6)

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

	drainOut := func() {
		for {
			select {
			case m := <-outCh:
				if roundNumberOf(m) >= 8 {
					result.ReachedRound8 = true
				}
				pendingToBob = append(pendingToBob, m)
			case <-endCh:
				// Unreachable in practice: this scenario deliberately stops
				// before round 9 (see runMixedScenario's doc comment), so
				// the ceremony never actually produces a signature. Kept
				// only so a future change to the stopping point doesn't
				// silently deadlock on an undrained channel. Matches this
				// package's own local_party_test.go convention of not
				// binding the received value (a common.SignatureData is a
				// protobuf message and copying it by value trips go vet's
				// lock-copy check).
				result.Completed = true
			default:
				return
			}
		}
	}
	drainOut()
	pendingToAlice = append(pendingToAlice, peerEvents...)

	captureWitness := func(e event) {
		if result.WitnessBobT1 != "" {
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
		for _, m := range pendingToBob {
			if result.ReachedRound8 {
				break pump
			}
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
					result.PeerR, result.PeerS = e.RHex, e.SHex
				case "error":
					// A historical-side rejection is unexpected in every
					// scenario this harness drives (the current legacy
					// prover's own witness stays well inside every
					// historical/current bound); surface it as a hard
					// failure rather than silently ignoring it.
					return nil, fmt.Errorf("historical peer reported an unexpected error: %s", e.Message)
				}
			}
		}
		pendingToBob = nil

		toDeliver := pendingToAlice
		pendingToAlice = nil
		for _, e := range toDeliver {
			if result.ReachedRound8 {
				break
			}
			captureWitness(e)
			wireBytes, decErr := hex.DecodeString(e.WireHex)
			if decErr != nil {
				return nil, fmt.Errorf("decode historical wire hex: %w", decErr)
			}
			// Peek at the message's concrete type before delivering it: a
			// historical peer that has just processed one of Alice's
			// messages can legitimately cascade through more than one of
			// its own rounds in a single turn (e.g. producing round 7 and
			// round 8 together once round 7's local precondition is
			// already satisfied). Delivering a round-8-or-later message
			// would drive Alice past round 8 into round 9's global
			// reconstruction check within the same UpdateFromBytes call,
			// which this deliberately minimal 2-of-20 fixture subset
			// cannot satisfy (see the doc comment on this function).
			if parsed, pErr := tss.ParseWireMessage(wireBytes, partyIDs[1], e.IsBroadcast); pErr == nil {
				if roundNumberOf(parsed) >= 8 {
					result.ReachedRound8 = true
					break
				}
			}
			ok, aErr := alice.UpdateFromBytes(wireBytes, partyIDs[1], e.IsBroadcast)
			if aErr != nil {
				result.DefaultRejected = true
				result.RejectionErr = aErr.Error()
				return result, nil
			}
			_ = ok
			result.AliceProgressed = true
		}
		drainOut()
		if result.ReachedRound8 {
			break pump
		}
	}

	if compat {
		result.Accepted = true
	}
	return result, nil
}

// runHomogeneousControl drives the identical ceremony shape through round 8
// with two current-implementation parties and no historical subprocess at
// all, to demonstrate the default legacy path is otherwise fully functional
// and that "reject" above is specific to the historical witness range.
func runHomogeneousControl() (*scenarioResult, error) {
	restore := fixedRandom("homogeneous-control")
	defer restore()

	keys, partyIDs, err := keygen.LoadKeygenTestFixtures(2)
	if err != nil {
		return nil, fmt.Errorf("load keygen fixtures: %w", err)
	}
	ec := tss.S256()
	ctx := tss.NewPeerContext(partyIDs)

	msg := new(big.Int)
	msg.SetString(fixedMessageHex, 16)
	msgBytes, _ := hex.DecodeString(fixedMessageHex)

	outCh := make(chan tss.Message, 16)
	endCh := make(chan common.SignatureData, 2)
	parties := make([]tss.Party, 2)
	for i := 0; i < 2; i++ {
		p := tss.NewParameters(ec, ctx, partyIDs[i], 2, 1)
		p.SetProtocolMode(tss.ProtocolModeLegacy)
		parties[i] = signing.NewLocalParty(msg, p, keys[i], outCh, endCh, len(msgBytes))
	}
	for _, p := range parties {
		if err := p.Start(); err != nil {
			return nil, fmt.Errorf("homogeneous control start: %w", err)
		}
	}

	result := &scenarioResult{Name: "homogeneous-control"}
	for {
		select {
		case m := <-outCh:
			// See runMixedScenario's doc comment: stop before forwarding a
			// round-8-or-later message so neither party auto-cascades into
			// round 9's global reconstruction check, which this 2-of-20
			// minimal fixture subset cannot satisfy.
			if roundNumberOf(m) >= 8 {
				result.ReachedRound8 = true
				break
			}
			dest := m.GetTo()
			wireBytes, _, wErr := m.WireBytes()
			if wErr != nil {
				return nil, fmt.Errorf("homogeneous wire bytes: %w", wErr)
			}
			if dest == nil {
				for _, p := range parties {
					if p.PartyID().Index == m.GetFrom().Index {
						continue
					}
					if _, uErr := p.UpdateFromBytes(wireBytes, m.GetFrom(), true); uErr != nil {
						return nil, fmt.Errorf("homogeneous update: %w", uErr)
					}
				}
			} else {
				if _, uErr := parties[dest[0].Index].UpdateFromBytes(wireBytes, m.GetFrom(), false); uErr != nil {
					return nil, fmt.Errorf("homogeneous update: %w", uErr)
				}
			}
		case <-endCh:
			// Unreachable in practice; see the identical case in
			// runMixedScenario's drainOut.
			result.Completed = true
		}
		if result.ReachedRound8 {
			break
		}
	}
	return result, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %s <historical-module-dir>\n", os.Args[0])
		os.Exit(2)
	}
	historicalDir := os.Args[1]

	failed := false
	report := map[string]any{}

	reject, err := runMixedScenario("reject", "reject", historicalDir, false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reject scenario error: %v\n", err)
		os.Exit(1)
	}
	report["reject"] = reject
	if !reject.DefaultRejected {
		fmt.Fprintln(os.Stderr, "FAIL: default-off current party did not reject the historical witness proof")
		failed = true
	}
	if !reject.AboveTightBound {
		fmt.Fprintln(os.Stderr, "FAIL: historical witness T1 did not exceed the default tight N+q^6 bound")
		failed = true
	}

	accept, err := runMixedScenario("accept", "reject", historicalDir, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "accept scenario error: %v\n", err)
		os.Exit(1)
	}
	report["accept"] = accept
	if !accept.Accepted || !accept.AliceProgressed {
		fmt.Fprintln(os.Stderr, "FAIL: opt-in current party did not accept and progress past round 3")
		failed = true
	}
	if !accept.AboveTightBound {
		fmt.Fprintln(os.Stderr, "FAIL: accept scenario's historical witness was not above the tight bound (test would be vacuous)")
		failed = true
	}
	if !accept.ReachedRound8 {
		fmt.Fprintln(os.Stderr, "FAIL: opt-in mixed ceremony did not progress through round 8")
		failed = true
	}

	control, err := runHomogeneousControl()
	if err != nil {
		fmt.Fprintf(os.Stderr, "homogeneous control error: %v\n", err)
		os.Exit(1)
	}
	report["homogeneous_control"] = control
	if !control.ReachedRound8 {
		fmt.Fprintln(os.Stderr, "FAIL: homogeneous current-only control did not reach round 8")
		failed = true
	}

	encoded, _ := json.MarshalIndent(report, "", "  ")
	fmt.Println(string(encoded))

	if failed {
		os.Exit(1)
	}
}
