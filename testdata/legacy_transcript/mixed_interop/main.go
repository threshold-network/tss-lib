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
	for name, res := range results {
		switch r := res.(type) {
		case *scenarioResult:
			switch name {
			case "reject":
				if !r.DefaultRejected {
					fmt.Printf("FAIL: %s: default-configured current party did not reject (compat off, live Bob/BobWC witness T1=%s, tight_bound=%s, above_tight=%v)\n",
						name, r.WitnessBobT1, r.TightBound, r.AboveTightBound)
					os.Exit(1)
				}
				if r.RejectionRound != 3 {
					fmt.Printf("FAIL: %s: rejection was not at round 3 (tss.Error.Round()=%d)\n", name, r.RejectionRound)
					os.Exit(1)
				}
				if r.RejectionPeerCulpritCount < 2 {
					fmt.Printf("FAIL: %s: both production verifier failures did not name the historical peer (count=%d)\n", name, r.RejectionPeerCulpritCount)
					os.Exit(1)
				}
				if r.AliceEmittedRound3 {
					fmt.Printf("FAIL: %s: current party emitted a round-3 message despite rejecting\n", name)
					os.Exit(1)
				}
				if r.BobProofOff {
					fmt.Printf("FAIL: %s: Bob proof accepted at tight bound (compat off)\n", name)
					os.Exit(1)
				}
				if r.BobWCProofOff {
					fmt.Printf("FAIL: %s: BobWC proof accepted at tight bound (compat off)\n", name)
					os.Exit(1)
				}
				if !r.AboveTightBound {
					fmt.Printf("FAIL: %s: live Bob witness T1 not above tight bound (this scenario requires a high witness; re-run to get a fresh draw)\n", name)
					os.Exit(1)
				}
				if !r.BobProofOn {
					fmt.Printf("FAIL: %s: Bob proof not independently accepted with compat on (witness shape not confirmed valid)\n", name)
					os.Exit(1)
				}
				if !r.BobWCProofOn {
					fmt.Printf("FAIL: %s: BobWC proof not independently accepted with compat on (witness shape not confirmed valid)\n", name)
					os.Exit(1)
				}
			case "accept":
				if !r.Accepted {
					fmt.Printf("FAIL: %s: opt-in current party did not accept and progress past round 3\n", name)
					os.Exit(1)
				}
				if !r.AliceProgressed {
					fmt.Printf("FAIL: %s: opt-in party did not progress\n", name)
					os.Exit(1)
				}
				if !r.ReachedRound8 {
					fmt.Printf("FAIL: %s: opt-in mixed ceremony did not progress through round 8\n", name)
					os.Exit(1)
				}
				// Per-proof accept assertions
				if !r.BobProofOn {
					fmt.Printf("FAIL: %s: Bob proof not accepted with compat on\n", name)
					os.Exit(1)
				}
				if !r.BobWCProofOn {
					fmt.Printf("FAIL: %s: BobWC proof not accepted with compat on\n", name)
					os.Exit(1)
				}
			case "homogeneous-control":
				if !r.ReachedRound8 {
					fmt.Printf("FAIL: %s: homogeneous control did not reach round 8\n", name)
					os.Exit(1)
				}
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
