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

## Mixed-binary legacy signing interop harness

`verify.sh`'s oracle proves byte-for-byte proof compatibility from fixed,
pre-recorded transcripts. It never runs an actual historical binary, so it
cannot by itself prove that a *live* historical peer and a live current peer
can complete a real signing exchange together. `verify_mixed_interop.sh`
closes that gap: it drives a genuine two-process ECDSA signing ceremony
between this checked-out (current) implementation and a subprocess running
the pinned historical `threshold-network/tss-lib@2e712689` commit (the same
commit qualified above), exchanging real GG18/GG20 round wire messages.

```sh
./testdata/legacy_transcript/verify_mixed_interop.sh
```

`historical_signer/main.go` is copied into a temporary module built from the
same `historical/go.mod.fixture`/`historical/go.sum.fixture` pin as the
oracle, exactly like `verify.sh`'s pattern. It drives one live historical
`ecdsa/signing.LocalParty` (party index 1, "Bob") over a bounded,
newline-delimited JSON protocol on stdin/stdout: `init`/`deliver`/`quit`
commands in, `message`/`signature`/`error`/`turn_done` events out. No network
access happens at run time; the pinned module must already be in the local
module cache (the same precondition `verify.sh` has always had).

`mixed_interop/main.go` (entry point/orchestration), `mixed_interop/peer.go`
(subprocess wire protocol), `mixed_interop/scenarios.go` (scenario logic and
per-proof verification), and `mixed_interop/homogeneous.go` (the control
scenario) together implement the current-side driver (`go run` from the
repository root, matching the oracle). For a fixed 2-of-20 `keygen_data_0/1`
fixture pair, deterministic seeds, and a fixed message, they drive three
scenarios:

- **reject**: a current party with `tss.ProtocolModeLegacy` and the default
  (off) `SetLegacyHistoricalBobCompatibility` opt asserts that round 3 fails
  closed against the historical peer's live, real Bob/BobWC proof, whose T1
  witness (recovered from the actual wire bytes via
  `SignRound2Message.UnmarshalProofBob`/`UnmarshalProofBobWC`, not a
  hand-picked value) is asserted to exceed the default tight `N + q^6` bound.
  The rejection is additionally constrained structurally — never by parsing
  the error string — to `tss.Error.Round() == 3`, the historical peer's
  party ID present in `tss.Error.Culprits()`, and no round-3 message ever
  emitted by the current party. Independently of the live round-3 failure,
  the harness also re-verifies Bob's and BobWC's proofs *separately* (each
  against its own compat-off/compat-on call to `ProofBob.VerifyLegacy` /
  `ProofBobWC.VerifyLegacy`, using the actual captured wire proof and public
  inputs — Alice's own Paillier key/Ring-Pedersen parameters, her round-1
  ciphertext, Bob's round-2 response, and Bob's `PrepareForSigning`-derived
  EC contribution): both must independently reject at the tight bound *and*
  independently accept at the loose bound. This catches a regression where
  only one of the two proof paths is correctly wired (e.g. Bob accepts the
  widened bound but BobWC is left at the tight one, or vice versa), which an
  aggregate round-3 pass/fail alone cannot distinguish.
- **accept**: the identical exchange with `SetLegacyHistoricalBobCompatibility(true)`
  set before construction; round 3 succeeds and the ceremony provably
  continues through round 8 (both directions), proving the current party
  didn't just tolerate the historical proof but kept advancing the protocol
  with the historical peer afterward. The same independent per-proof
  Bob/BobWC verification above is asserted here too (both accepting at the
  loose bound).
- **homogeneous-control**: two current-implementation parties, no historical
  subprocess at all, complete the identical ceremony shape under the default
  configuration — proof that "reject" above is specific to the historical
  witness range and not a general legacy-mode defect. This scenario is never
  substituted for the cross-version exchanges above.

All three scenarios deliberately stop once a party's own round 8 message
appears (never delivering a round-8-or-later message onward): this
repository's own `round3Fixture` (`ecdsa/signing/round_3_test.go`) and
`historicalBobProofForWitnessY`
(`crypto/mta/legacy_bob_historical_witness_test.go`) already establish the
precedent of driving a 2-of-20 minimal subset of the `test/_ecdsa_fixtures`
keygen fixtures (threshold 1, not the fixture set's real threshold 10) for
this exact class of round-level interop check. That minimal subset is
sufficient for every per-peer MtA/Schnorr check through round 8 (each is a
property of the two parties' own consistent local computation), but round 9's
final aggregate check (`U == T`) verifies a *global* Shamir reconstruction
identity that only holds for a correctly-sized threshold+1 co-signer set.
Reaching a real, live-exchanged round 8 message already proves the historical
Bob/BobWC witness was accepted and every subsequent round 3–8
verification/decommitment step (Bob_end, the Gamma/Schnorr proofs, and both
decommitments) succeeded against a genuine historical binary. Driving a full,
globally-valid signature to completion is possible but requires
`testThreshold+1` (11) correctly-thresholded co-signers rather than an
arbitrary 2-of-20 subset — substantially more harness complexity for a
property (global reconstruction validity) that is orthogonal to the specific
Bob/BobWC compatibility mechanism this harness exists to exercise.

The exact witness scalar values are not byte-reproducible run to run: signing
round 2 (`ecdsa/signing/round_2.go`) draws the Bob and BobWC witnesses from
two goroutines running concurrently against the process-global
`crypto/rand.Reader`, so which goroutine consumes which slice of the
deterministic keystream is scheduler-dependent. Every run nonetheless
deterministically reproduces the *qualitative* property under test — a high
witness that exceeds the tight bound, a closed-by-default rejection, and an
opt-in acceptance that keeps progressing — which is what `verify_mixed_interop.sh`
asserts and fails on.

