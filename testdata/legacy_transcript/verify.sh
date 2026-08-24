#!/usr/bin/env bash

set -euo pipefail

data_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${data_dir}/../.." && pwd)"
historical_module="$(mktemp -d "${TMPDIR:-/tmp}/tss-legacy-oracle.XXXXXX")"
trap 'chmod -R u+w "${historical_module}" 2>/dev/null || true; rm -rf "${historical_module}"' EXIT

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

(
  cd "${repository_root}"
  go run ./testdata/legacy_transcript/oracle/main.go \
    ./testdata/legacy_transcript/prior_v2.5.2.json
  go run ./testdata/legacy_transcript/oracle/main.go \
    ./testdata/legacy_transcript/prior_v2.5.2.json \
    ./testdata/legacy_transcript/r1_fixed.json
)

cp "${data_dir}/historical/go.mod.fixture" "${historical_module}/go.mod"
cp "${data_dir}/historical/go.sum.fixture" "${historical_module}/go.sum"
cp "${data_dir}/oracle/main.go" "${historical_module}/main.go"
(
  cd "${historical_module}"
  go run -mod=readonly ./main.go "${data_dir}/r1_fixed.json"
)
