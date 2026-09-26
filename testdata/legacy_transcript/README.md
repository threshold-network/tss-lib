# R01 legacy transcript vectors

This directory contains deterministic cross-version qualification evidence for
the transcript-compatible legacy mode. Private values and deterministic random
streams in these files are test fixtures only and must never be used by a live
protocol.

`prior_v2.5.2.json` was generated with
`threshold-network/tss-lib@2e712689cfbe`. `r1_fixed.json` was generated from
the R01 compatibility patch. Each document records the Go toolchain, exact
input-fixture digests, proof-source digest, public inputs, challenges, proof
scalars, and the serialized TSS messages that carry every mandatory family.
In particular, `keygen_round1.wire` is a fixed broadcast containing both DLN
slots and both ModProof slots. `dln.carrier_wire_sha256` and
`mod.carrier_wire_sha256` independently bind their proof records to those shared
wire bytes without duplicating the large message. The fixture places the
qualified proof in each paired slot so the serialized carrier adds no second,
unrecorded proof oracle. Range, Bob/BobWC, and FactorProof retain their own
signing/keygen carrier messages. The adjacent SHA-256 sidecars cover the raw JSON
bytes.

The two documents differ only in their provenance object. After deleting that
object and canonicalizing the JSON, every DLN, range, Bob, BobWC, ModProof, and
FactorProof public input, challenge, proof scalar, and serialized message is
byte-for-byte identical. The checked-in raw-document digests are:

- PRIOR: `41c0e14b086cb3046353298887edb9ba08e2706fd38df572f425ff5954bb9fc9`
- R1 fixed: `5d0ebead52362cda3eb8f7b14afc5e1d161e9bd531bb2b0a79f0c643b35e0b09`

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
