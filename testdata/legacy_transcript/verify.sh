#!/usr/bin/env bash

set -euo pipefail

data_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${data_dir}/../.." && pwd)"
historical_module="$(mktemp -d "${TMPDIR:-/tmp}/tss-legacy-oracle.XXXXXX")"
generated_vector="$(mktemp "${TMPDIR:-/tmp}/tss-legacy-generated.XXXXXX")"
trap 'chmod -R u+w "${historical_module}" 2>/dev/null || true; rm -rf "${historical_module}"; rm -f "${generated_vector}"' EXIT

if command -v sha256sum >/dev/null 2>&1; then
  (
    cd "${data_dir}"
    sha256sum --check prior_v2.5.2.json.sha256 r1_fixed.json.sha256
  )
else
  (
    cd "${data_dir}"
    shasum -a 256 --check prior_v2.5.2.json.sha256 r1_fixed.json.sha256
  )
fi

# Leg 1: the checked-out implementation must still verify the historical
# PRIOR transcript byte-for-byte.
(
  cd "${repository_root}"
  go run ./testdata/legacy_transcript/oracle/main.go \
    ./testdata/legacy_transcript/prior_v2.5.2.json
  go run ./testdata/legacy_transcript/oracle/main.go \
    ./testdata/legacy_transcript/prior_v2.5.2.json \
    ./testdata/legacy_transcript/r1_fixed.json
)

# Leg 2: the historical-module oracle (same parser and equations pinned at the
# historical commit) must verify the R1 transcript.
cp "${data_dir}/historical/go.mod.fixture" "${historical_module}/go.mod"
cp "${data_dir}/historical/go.sum.fixture" "${historical_module}/go.sum"
cp "${data_dir}/oracle/main.go" "${historical_module}/main.go"
(
  cd "${historical_module}"
  go run -mod=readonly ./main.go "${data_dir}/r1_fixed.json"
)

# Leg 3: the HEAD legacy provers must produce a transcript the historical
# verifier accepts. The generator mode of the oracle runs at HEAD with the
# same deterministic streams that produced the checked-in vectors, so the
# proofs it emits are the ones the historical verifier was qualified against;
# verifying that generated document in the historical module closes the
# HEAD-prover -> historical-verifier direction.
(
  cd "${repository_root}"
  go run ./testdata/legacy_transcript/oracle/main.go > "${generated_vector}"
)
if [ ! -s "${generated_vector}" ]; then
  echo "generated legacy vector is empty" >&2
  exit 1
fi
(
  cd "${historical_module}"
  go run -mod=readonly ./main.go "${generated_vector}"
)
# The generated vector is byte-for-byte reproducible from the PRIOR vector
# under the deterministic streams (only provenance differs by construction),
# so assert the equality the pair of documents is meant to make.
(
  cd "${repository_root}"
  go run ./testdata/legacy_transcript/oracle/main.go \
    ./testdata/legacy_transcript/prior_v2.5.2.json \
    "${generated_vector}"
)
