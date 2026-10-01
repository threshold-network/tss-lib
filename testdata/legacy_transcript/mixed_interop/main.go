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
//   - "accept": a fresh exchange against a separate historical process
//     (its own deterministic seed, independent of the reject run above —
//     the two runs are paired per-proof, not an identical replay), where
//     the current party opts into SetLegacyHistoricalBobCompatibility(true)
//     and the ceremony provably progresses: the current party emits its
//     round-3 message, the historical peer accepts it, and the live
//     exchange continues through round 8 in both directions (each actor's
//     first round-8-or-later message captured as boundary evidence, never
//     forwarded). Each captured Bob/BobWC proof is verified pairwise
//     against the actual captured wire bytes — rejecting at the tight N+q^6
//     bound (compat off) and accepting under the widened historical bound
//     (compat on) — so acceptance is paired per proof rather than inferred
//     from a shared replay (see runMixedScenario's doc comment for why
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
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: mixed_interop <historical-module-dir>")
		os.Exit(1)
	}
	histDir := os.Args[1]

	results := map[string]interface{}{}

	for _, cfg := range []struct {
		name    string
		seed    string
		histDir string
		compat  bool
	}{
		{"reject", "reject-seed", histDir, false},
		{"accept", "accept-seed", histDir, true},
	} {
		result, err := runMixedScenario(cfg.name, cfg.seed, cfg.histDir, cfg.compat)
		if err != nil {
			results[cfg.name] = map[string]string{"error": err.Error()}
			continue
		}
		results[cfg.name] = result
	}

	homCtrl, err := runHomogeneousControl()
	if err != nil {
		results["homogeneous-control"] = map[string]string{"error": err.Error()}
	} else {
		results["homogeneous-control"] = homCtrl
	}
	// Validate post-conditions: durable assertions about the protocol.
	// Each scenario's result is qualified by the predicate in this file
	// (qualifyRejectionScenario / qualifySuccessfulScenario /
	// qualifyHomogeneousControl) that encodes that scenario's required
	// invariants (round-3 fail-closed attribution for reject; per-actor
	// round-8 emission plus per-proof tight/loose discrimination for accept
	// and the homogeneous control). The predicate's reason string is the
	// FAIL message, preserving the original per-check diagnostics.
	for name, res := range results {
		switch r := res.(type) {
		case *scenarioResult:
			var (
				ok     bool
				reason string
			)
			switch name {
			case "reject":
				ok, reason = qualifyRejectionScenario(r)
			case "accept":
				ok, reason = qualifySuccessfulScenario(r)
			case "homogeneous-control":
				ok, reason = qualifyHomogeneousControl(r)
			}
			if !ok {
				if name == "reject" {
					// Keep the live-drawn witness scalars and the tight
					// bound they are compared against in the FAIL line so
					// a low-draw rerun stays actionable.
					fmt.Printf("FAIL: %s: %s (witness_bob_t1=%s, witness_bob_wc_t1=%s, tight_bound=%s, above_tight=%v)\n",
						name, reason, r.WitnessBobT1, r.WitnessBobWCT1, r.TightBound, r.AboveTightBound)
				} else {
					fmt.Printf("FAIL: %s: %s\n", name, reason)
				}
				os.Exit(1)
			}
		case map[string]string:
			fmt.Printf("FAIL: %s: scenario returned an error: %s\n", name, r["error"])
			os.Exit(1)
		default:
			fmt.Printf("FAIL: %s: unexpected result type %T\n", name, res)
			os.Exit(1)
		}
	}

	enc := json.NewEncoder(os.Stdout)
	enc.Encode(map[string]interface{}{"results": results})
}

// qualifyRejectionScenario asserts the reject scenario's required invariants:
// a closed-by-default round-3 failure attributed to the historical peer, no
// round-3 outbound, a high live-drawn witness (above the tight N+q^6 bound),
// and both captured Bob/BobWC proofs observed rejecting at the tight bound
// while accepting under compat. Each proof must discriminate between the two
// bound settings, which is what proves the compatibility switch — not a
// witness that would pass the tight bound too — is the acceptance gate.
func qualifyRejectionScenario(r *scenarioResult) (bool, string) {
	if !r.DefaultRejected {
		return false, "default-configured party did not reject"
	}
	if r.RejectionRound != 3 {
		return false, fmt.Sprintf("rejection was not at round 3 (tss.Error.Round()=%d)", r.RejectionRound)
	}
	if r.RejectionPeerCulpritCount < 2 {
		return false, fmt.Sprintf("both production verifier failures did not name the historical peer (count=%d)", r.RejectionPeerCulpritCount)
	}
	if r.AliceEmittedRound3 {
		return false, "current party emitted a round-3 message despite rejecting"
	}
	if !r.AboveTightBound {
		return false, "live Bob witness T1 not above tight bound (this scenario requires a high witness; re-run for a fresh draw)"
	}
	if r.BobProofOff {
		return false, "Bob proof accepted at tight bound (must reject)"
	}
	if r.BobWCProofOff {
		return false, "BobWC proof accepted at tight bound (must reject)"
	}
	if !r.BobProofOn {
		return false, "Bob proof not accepted with compat on (witness shape not confirmed valid)"
	}
	if !r.BobWCProofOn {
		return false, "BobWC proof not accepted with compat on (witness shape not confirmed valid)"
	}
	return true, ""
}

// qualifySuccessfulScenario asserts the opt-in accept scenario's required
// invariants:
//   - round-8 emission observed from BOTH actors (the documented round-8
//     boundary in both directions, each first round-8 message captured and
//     dropped, never forwarded);
//   - the opt-in party progressed through round 3 and into rounds 4–8;
//   - the live witness T1 was observed above the tight N+q^6 bound
//     (tight-bound evidence);
//   - each captured Bob and BobWC proof observed rejecting at the tight
//     bound (compat off) and accepting with the widened historical bound
//     (compat on) — the per-proof discrimination that proves the
//     compatibility switch is the acceptance gate, not a witness that
//     would pass the tight bound too.
func qualifySuccessfulScenario(r *scenarioResult) (bool, string) {
	if !r.AliceProgressed {
		return false, "opt-in party did not progress"
	}
	if !r.round8BothReached() {
		return false, fmt.Sprintf("round-8 boundary not established in both directions (alice_reached_round_8=%v, bob_reached_round_8=%v)", r.AliceReachedRound8, r.BobReachedRound8)
	}
	if !r.AboveTightBound {
		return false, "live Bob witness T1 not above tight bound (accept scenario requires a high witness; re-run for a fresh draw)"
	}
	if r.BobProofOff {
		return false, "Bob proof accepted at tight bound (should reject; compat widening not the gate)"
	}
	if !r.BobProofOn {
		return false, "Bob proof not accepted with compat on"
	}
	if r.BobWCProofOff {
		return false, "BobWC proof accepted at tight bound (should reject; compat widening not the gate)"
	}
	if !r.BobWCProofOn {
		return false, "BobWC proof not accepted with compat on"
	}
	return true, ""
}

// qualifyHomogeneousControl asserts the two current-implementation control
// completed the ceremony through round 8 in both directions under the
// default (non-opt-in) configuration, using the same per-actor round-8 flags
// and the same termination rule as the mixed scenarios (never forward
// round-8-or-later; stop once both sides have emitted round 8).
func qualifyHomogeneousControl(r *scenarioResult) (bool, string) {
	if !r.round8BothReached() {
		return false, fmt.Sprintf("homogeneous control did not reach round 8 in both directions (alice_reached_round_8=%v, bob_reached_round_8=%v)", r.AliceReachedRound8, r.BobReachedRound8)
	}
	return true, ""
}
