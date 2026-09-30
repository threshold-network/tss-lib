#!/usr/bin/env bash
#
# Runs the mixed-binary legacy signing interop harness: a live, two-process
# ECDSA signing ceremony between this checked-out (current) implementation
# and a subprocess running the pinned historical threshold-network/tss-lib@
# 2e712689 commit (the same commit qualified by verify.sh's oracle vectors).
#
# Unlike verify.sh's oracle, which replays fixed, pre-recorded proof
# transcripts, this script drives an actual live historical LocalParty
# through a real signing round exchange and asserts on its behavior:
#
#   - the historical peer's real, live-drawn Bob/BobWC witness (sampled below
#     the Paillier modulus N, per the historical BobMid/BobMidWC) produces a
#     round-2 proof whose T1 exceeds the default tight N+q^6 bound;
#   - a default-configured current party's round 3 fails closed against it;
#   - a current party with SetLegacyHistoricalBobCompatibility(true) accepts
#     the identical exchange and provably progresses (through round 8; see
#     testdata/legacy_transcript/mixed_interop/main.go's doc comment for why
#     full signature completion is out of scope for this specific check);
#   - a homogeneous (current-only) control completes the same shape, so the
#     rejection above is never mistaken for a general legacy-mode defect.
#
# See testdata/legacy_transcript/README.md for the full design rationale.
set -euo pipefail

data_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${data_dir}/../.." && pwd)"
historical_module="$(mktemp -d "${TMPDIR:-/tmp}/tss-mixed-interop.XXXXXX")"
trap 'chmod -R u+w "${historical_module}" 2>/dev/null || true; rm -rf "${historical_module}"' EXIT

cp "${data_dir}/historical/go.mod.fixture" "${historical_module}/go.mod"
cp "${data_dir}/historical/go.sum.fixture" "${historical_module}/go.sum"
cp "${data_dir}/historical_signer/main.go" "${historical_module}/main.go"

(
  cd "${repository_root}"
  go run ./testdata/legacy_transcript/mixed_interop "${historical_module}"
)
