# R01 legacy transcript vectors

This directory contains deterministic cross-version qualification evidence for
the transcript-compatible legacy mode. Private values and deterministic random
streams in these files are test fixtures only and must never be used by a live
protocol.

`prior_v2.5.2.json` was generated with
`threshold-network/tss-lib@2e712689cfbe`. `r1_fixed.json` was generated from
the R01 compatibility patch. Each document records the Go toolchain, exact
input-fixture digests, proof-source digest, public inputs, challenges, proof
scalars, and the serialized TSS messages that carry range, Bob/BobWC, and
factor proofs. The adjacent SHA-256 sidecars cover the raw JSON bytes.

The two documents differ only in their provenance object. After deleting that
object and canonicalizing the JSON, every DLN, range, Bob, BobWC, ModProof, and
FactorProof public input, challenge, proof scalar, and serialized message is
byte-for-byte identical. The checked-in raw-document digests are:

- PRIOR: `ff447af7aa603ad55a0915f102eb49f96800feedf52ec171f1e4a10149d6ce7a`
- R1 fixed: `ab614a7daa6f3ada416fe7b4758dcc50c8ac052433aaa27c2ab8363b2d079ff9`

The R1 proof-source digest recorded in its provenance is
`69a2480cadd102d35c0b017f448733c50645e3bc1148b869fe84f03ae4850e79`.

The proof-source digest is SHA-256 over this ordered sequence, concatenating
each repository-relative path, one NUL byte, and the file bytes:

```
crypto/dlnproof/proof.go
crypto/mta/range_proof.go
crypto/mta/proofs.go
crypto/paillier/mod_proof.go
crypto/paillier/factor_proof.go
common/hash.go
common/hash_utils.go
common/random.go
ecdsa/keygen/messages.go
ecdsa/signing/messages.go
```

Run both independent directions from the repository root:

```sh
./testdata/legacy_transcript/verify.sh
```

The first oracle is the checked-out implementation verifying PRIOR-generated
proofs. The second runs the same parser and equations in a nested module pinned
to the historical commit, verifying R1-generated proofs. The checked-in
`historical/go.mod.fixture` and `historical/go.sum.fixture` are copied into a
temporary module for that direction. The `.fixture` suffix is intentional: Go
prunes nested modules from a parent module zip, while ordinary fixture files are
part of the immutable module keep-core downloads. The pinned fixture therefore
makes the historical identity independent of a developer's module cache without
disappearing from the release artifact being qualified.
