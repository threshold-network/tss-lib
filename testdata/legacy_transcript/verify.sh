#!/usr/bin/env bash

set -euo pipefail

data_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${data_dir}/../.." && pwd)"

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

(
  cd "${data_dir}/historical"
  go run -mod=readonly ../oracle/main.go ../r1_fixed.json
)
