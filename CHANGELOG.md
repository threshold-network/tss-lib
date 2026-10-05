# Changelog

All notable changes to this fork (`threshold-network/tss-lib`) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This fork follows the upstream [`bnb-chain/tss-lib`](https://github.com/bnb-chain/tss-lib)
SemVer line for provenance but has not yet published its own tagged release; all changes
below are therefore listed under `[Unreleased]`.
The module path has no `/vN` suffix (the upstream `/v2` path bump was not ported;
see Not ported / deferred), so a Go-consumable release tag must stay on the `v0.x`
or `v1.x` line — for example `v1.4.0-threshold.1` — because the `go` command
rejects `v2`-and-later tags for this module path.

Provenance notation. Each entry carries two kinds of reference:
- **Upstream source** — `BNB #NNN` / `BNB <sha>` is the upstream pull request or commit the
  change was adapted from. Most were **manually adapted**, not cherry-picked, so behavior may
  differ from upstream. `threshold-original` means there is no direct upstream counterpart.
- **Fork PR** — `PR #N` is the `threshold-network/tss-lib` pull request that introduced the
  change into this fork, for traceability.

---

## [Unreleased] — BNB hardening integration

Security and correctness hardening ported or manually adapted from `bnb-chain/tss-lib`,
without replacing Threshold's existing Paillier/NTilde `ModProof`/`FactorProof` remediation.
As of PR #5 this fork targets **ECDSA only** (keygen and signing); EdDSA and ECDSA resharing
were removed (see Removed).

- Threshold base: `2e712689cfbeefede15f95a0ec7112227d86f702`
- BNB upstream head compared: `3f677ff761fcf692edb0243a5d812930844d879a`

This unreleased set is delivered through a stack of fork pull requests. **Every entry below
belongs to PR #2 (the base BNB hardening integration) unless it is tagged with another
`PR #N`.** Composing PRs:
- **PR #2** — base BNB hardening integration.
- **PR #4** — BNB #332 tBTC-relevant hardening backport (stacked on PR #2).
- **PR #5** — removal of EdDSA and ECDSA resharing protocols (stacked on PR #4).
- **PR #6** — remaining BNB cryptographic hardening follow-ups (stacked on PR #5).
- **PR #7** — signing round-9 decommitment validation and related fixes (stacked on PR #6).
- **PR #9** — immutable per-party legacy/security-v2 transcript selection and
  exact historical legacy compatibility (stacked on PR #7).
- **PR #11** — constant-time backport (BNB #328) rebased onto current `master`.
- **PR #12** — decoder length and nullable-input guards.
- **PR #13** — safe-prime worker cancellation and independent save-data subset copies.
- **PR #14** — party updates stop after a fatal lifecycle error.
- **PR #15** — bounded random sampling domains and Paillier challenge widths.
- **PR #16** — ECDSA signing context binding in the security-v2 SSID (stacked on PR #9).
- **PR #17** — constant-time operations enabled by default, extended by PR #23
  (supersedes PRs #8 and #10, which were closed unmerged).
- **PR #18** — protobuf generator version check before regeneration.
- **PR #19** — protobuf runtime and dependency housekeeping (stacked on PR #7).
- **PR #20** — `golang.org/x/crypto` and `x/sys` upgrades; Go 1.25.7 minimum.
- **PR #21** — btcd v0.24.2 and migration to `btcec/v2`.
- **PR #24** — CI runs on every pull request.
- **PR #25** — faster CI feedback plus scheduled race and cache-safety coverage.
- **PR #26** — concurrent local-party lifecycle regression coverage.
- **PR #27** — unequal-width constant-time arithmetic regression coverage.
- **PR #28** — bounded proof-input validation and panic-free proof decoding.
- **PR #29** — native fuzz targets for proof and wire-message decoders.
- **PR #30** — corrected rollout documentation and consistent CI toolchains.
- **PR #31** — constant-time Paillier performance and allocation improvements.
- **PR #32** — live current/historical mixed-binary signing interoperability harness.
- **PR #33** — signing-context, message-boundary, and round-readiness regression coverage.
- **PR #34** — shared proof-verifier resource bounds and `ModProof` context reuse.
- **PR #35** — changelog for the integration follow-ups.
- **PR #36** — publish complete signing-round state before outbound messages.
- **PR #38** — stop caching private-key Paillier decryption state; go directive CI check.
- **PR #39** — signing delivers `*common.SignatureData` instead of a by-value protobuf message.
- **PR #40** — changelog and README completed for the `dev` integration.
- Review fixes `873b8ad`..`fa6ef4d` — pushed directly to `dev` during the review of the
  `dev` -> `master` PR (#37); recorded in that PR's comments.

### ⚠️ Compatibility — read before upgrading

**Security-v2 is a protocol/wire compatibility break.** Its Fiat-Shamir proof
challenges use tagged hashing, session context, and fixed-width message
encoding, so a security-v2 party cannot interoperate with a historical party.

PR #9 adds an explicit incremental-rollout mode. A party in
`ProtocolModeLegacy` reproduces the historical untagged challenges, including
the exact Schnorr ZK/ZKV `HashToN` input ordering and modular reduction, and can
therefore share a legacy ceremony with the pre-upgrade binary **while the
rollout window is active**: a legacy party signing with not-yet-upgraded peers
must additionally select the default-off
`tss.Parameters.SetLegacyHistoricalBobCompatibility(true)` opt-in (see the
toggle entry below), because the default tighter Bob/BobWC verification can
reject their historical `y < N` proofs. A ceremony must
still be homogeneous by transcript mode: mixing legacy and security-v2 in one
run fails cryptographic verification, and there is no negotiation, downgrade,
fallback, or retry between modes. Once every peer is upgraded, the rollout-only
compatibility opt-in is disabled and the fleet is coordinated onto
`ProtocolModeSecurityV2` with a shared per-ceremony session ID.
Keygen (DKG) interop with the pre-upgrade binary is qualified only by the
primitive-level oracle vectors (DLN, ModProof, FactorProof), not by a live
mixed-version keygen run; there is no mixed-version DKG exercise.

Three of the four caller obligations below are enforced at runtime — two by
constructor panic, one by a `Start()` error — and the fourth is an operational
rollout step (see Breaking Changes 1 and 2 and the PR #9 entry below):
1. Select exactly one protocol mode before constructing a local party.
2. In security-v2, set a unique per-ceremony session nonce; in legacy, leave it unset.
3. Pass a positive `fullBytesLen` to every signing constructor.
4. During a mixed-binary legacy signing window, legacy parties call
   `tss.Parameters.SetLegacyHistoricalBobCompatibility(true)` while
   pre-upgrade peers remain; it is then disabled fleet-wide before the
   coordinated cutover to security-v2.

#### PR #9. Explicit dual-mode transcript contract
- **What:** ECDSA keygen/signing parameters require an explicit immutable
  `ProtocolModeLegacy` or `ProtocolModeSecurityV2`. Legacy round code calls the
  historical no-session proof APIs; security-v2 round code calls the tagged,
  session-bound APIs. `schnorr.NewZKProof` / `NewZKVProof` and `Verify` reproduce
  the exact `2e712689` `HashToN` transcript. `New*WithSession` rejects nil and
  non-nil empty sessions, and `VerifyWithSession` returns false for either, so
  an ambiguous empty value can never select a transcript. DLN, range,
  Bob/BobWC, ModProof, and FactorProof keep their existing optional-session
  shape: no argument is legacy; one non-empty argument is security-v2.
  Legacy Bob/BobWC proof generation also restores the historical `2e712689`
  implementation's exact `tau` and relatively-prime Paillier `gamma` sampling
  ranges, and its verifier retains that implementation's honest response range:
  legacy samples `gamma` below `N`, whereas security-v2 samples it below `q^7`;
  applying the latter bound to historical proofs rejects valid mixed-version
  signing transcripts.
- **Break type:** Runtime/source-compatible configuration obligation. A local
  party constructed without selecting a mode fails closed. A mode cannot be
  changed after construction, security-v2 requires a session nonce, and legacy
  refuses one.
- **Motivation:** Preserve byte-compatible pre-cutover ceremonies during an
  incremental binary rollout without weakening the post-cutover session-bound
  transcript or allowing an in-flight downgrade.
- **Provenance:** `threshold-original`, PR #9. Historical oracle:
  `threshold-network/tss-lib@2e712689cfbeefede15f95a0ec7112227d86f702`.
- **Qualification:** `crypto/schnorr/testdata/legacy_transcript_vectors.json`
  records fixed public points, legacy/security-v2 challenges, proof scalars,
  deterministic round-4/round-6 wire messages, source identities/digests, and
  a SHA-256 sidecar. `testdata/legacy_transcript` adds independent bidirectional
  oracles for the historical `2e712689` implementation and this fork's legacy
  path, plus raw vectors for DLN, range, Bob/BobWC, ModProof, and FactorProof,
  including the serialized protocol messages that carry them.
  Cross-verification uses the historical formulas or the module pinned to
  `2e712689`; it does not infer compatibility from two parties running the new
  implementation.

#### PR #9. Legacy historical Bob compatibility toggle (rollout-only, default off)
- **What:** `tss.Parameters.SetLegacyHistoricalBobCompatibility(bool)`
  (getter `LegacyHistoricalBobCompatibility`) is an explicit, per-party opt-in
  that widens only the legacy-mode Bob/BobWC `T1` verifier bound in signing
  round 3, from the default tight `N + q^6` to the exclusive historical
  witness-range bound `(q+1)*N` (derived from the historical `2e712689`
  `BobMid`/`BobMidWC` sampling `T1 = e*y + gamma` with `e < q`, `y < N`,
  `gamma < N`). It is `false` by default, and any call — with `true` or `false` —
  panics unless `ProtocolModeLegacy` has already been selected; the value is
  frozen for the party's lifetime by `FreezeProtocolMode` (or local-party
  construction). With the toggle off, the default legacy verifier remains
  tight and the standalone `ProofBob.Verify`/`ProofBobWC.Verify`/
  `AliceEnd`/`AliceEndWC` public APIs are unchanged.
- **Risk:** Enabling it accepts pre-upgrade `2e712689` Bob/BobWC proofs
  during the mixed-version rollout window and re-exposes the historical
  legacy-mode residual risk of the unbounded-witness design: an adversarial
  peer can bind the wider `y < N` witness range into its response (the
  `y = N - T` wrap family), so only the `T1` magnitude is bounded — the
  cryptographic checks are unchanged. The toggle exists to let a rolling
  upgrade verify not-yet-upgraded peers, not to harden anything: the
  default remains the hardened tight bound, and security-v2 is unaffected.
- **Break type:** None (additive, opt-in). Callers that never set it keep
  the tightened legacy behavior.
- **Provenance:** `threshold-original`, PR #9: the pre-merge
  review identified that the default legacy bound was derived from this
  branch's legacy-mode prover, whose `betaPrm` sampler feeds `y` below
  `q^5`, so it rejects honest historical `y < N` proofs and aborts
  mixed-version legacy signing at `AliceEnd`/`AliceEndWC`.

#### PR #16. ECDSA signing context binding in the security-v2 SSID (wire incompatibility)
- **What:** The security-v2 signing SSID now binds both the message integer and its
  fixed-width encoding (`fullBytesLen`), and the signing constructors copy the message
  integer so later caller mutations cannot change the party's signing context. This
  intentionally changes the security-v2 proof transcript.
- **Break type:** Wire/transcript (security-v2 only): security-v2 signers from before
  and after this change cannot interoperate — deploy and activate this version
  together across every signer in a ceremony (coordinated rollout).
- **Legacy unchanged:** Legacy transcript bytes are unchanged.

### Integration follow-ups

- **Dependency upgrades (PRs #20 and #21):** `golang.org/x/crypto` v0.52.0,
  `golang.org/x/sys` v0.45.0, and btcd v0.24.2 with `btcec/v2` v2.2.0 and
  `btcutil` v1.1.5, at or above the fixed versions of the Dependabot advisories open at
  the time. Compressed public-key parsing, the registered `secp256k1` curve name, and
  coordinate-based JSON/Gob persistence are unchanged; see Breaking Change 10 for the
  concrete curve type.
- **Decoder and lifecycle guards (PRs #12, #13, #14):** decoders check lengths and
  nullable fields before indexed reads or dereferences; a commitment payload is
  required. Safe-prime workers observe cancellation while delivering results.
  `BuildLocalSaveDataSubset` gives each subset its own copies of `Xi` and `ShareID`.
  After the first fatal preparation or round error, a party stores no further messages
  and does not advance; input-validation and storage rejections stay recoverable.
  Keygen checks the commitment part count before hashing and point decoding.
- **Bounded sampling (PR #15):** empty prime and unit sampling domains and structurally
  unsupported Paillier key sizes are rejected; `GenerateXs` masks candidates to the
  modulus width before rejection. 2048-bit challenge output is unchanged.
- **Bounded and panic-free proof input handling (PRs #28 and #34):**
  malformed proof encodings return errors instead of reaching arity or
  nil-value panics. Every exported unknown-order proof verifier rejects
  moduli above 65,536 bits before expensive primality, modular, or challenge
  work. `ModProof` also reuses its fixed constant-time contexts and exponents
  across all 80 iterations without changing proof bytes.
- **Constant-time Paillier performance (PR #31):** encryption uses the
  `Gamma = N+1` identity through constant-time multiplication, bounded exponents
  are padded to their public bound (the Paillier modulus width for `HomoMult`;
  the curve-order width `q.BitLen()` for the `x`, `m`, and `b` exponents of the
  Bob and Alice provers, while `ProofBob`/`ProofBobWC` keep `y` padded to the
  Paillier modulus width — see the caller-observable
  behavior follow-up bullet below), and pooled scratch buffers no longer
  allocate boxed slice headers on each return. Proof bytes and public APIs are
  unchanged.
- **Rollout assurance (PRs #27, #29, #32, #33):** regression, fuzz, and live
  mixed-binary checks cover constant-time width handling, proof and wire
  decoding, both historical Bob/BobWC rejection paths, context mismatch
  rejection, message boundaries, and out-of-order readiness. The mixed-binary
  harness exchanges real current/historical messages through round 8. It does
  not claim final signature completion because the pinned fixture supplies
  only two shares from a threshold-10 key set.
- **Signing state publication (PR #36):** rounds 5 and 7 finish storing their
  local state before emitting the corresponding outbound message. This makes
  message receipt a valid synchronization boundary for concurrent drivers;
  wire bytes and protocol arithmetic are unchanged.
- **Exported arithmetic boundary errors (review fixes `873b8ad`..`fa6ef4d`):** Bob/BobWC and Alice
  proof constructors reject out-of-domain Paillier plaintext witnesses
  before sampling or constant-time work. Compatibility-enabled Bob
  verification rejects nil inputs before deriving its historical bound.
  Paillier encryption, homomorphic multiplication, and decryption reject
  even or degenerate moduli (`paillier.ErrInvalidModulus`) and malformed private keys
  (`paillier.ErrMalformedKey`) through their error returns in both timing modes.
- **Paillier public-key context reuse (review fixes `873b8ad`..`fa6ef4d`; PR #38):**
  the N^2 constant-time context is cached per public key and reused while the key's
  value is unchanged. Entries are keyed by a weak pointer, so they are dropped when the
  key is garbage-collected, and a value snapshot detects later mutation of the exported
  modulus. Public key layouts, by-value copies, and JSON/Gob encodings are unchanged.
  Private-key decryption state is not cached: PR #38 removed that cache because it gave
  no measured `Decrypt` speedup and kept unzeroed copies of `LambdaN`-derived secrets.
- **Proof-local exponent reuse (review fixes `873b8ad`..`fa6ef4d`):** `ModProof` encodes its invariant
  secret exponents once for all 80 iterations and wipes those owned bytes
  at completion. Canonical-operand helpers avoid redundant reductions
  only where callers establish the required bounds; generic reducing
  helpers and the documented variable-time conversion limits remain.
- **Bidirectional live qualification (review fixes `873b8ad`..`fa6ef4d`):** the mixed-binary harness
  requires each accept-run Bob/BobWC proof to reject at the tight bound
  and accept at the compatibility bound. Separate actor flags require
  both peers to emit round 8 without forwarding round-8 messages.
  Reject and accept are fresh exchanges, not identical transcript replays.
- **Boundary regression coverage (review fixes `873b8ad`..`fa6ef4d`):** malformed arithmetic inputs,
  concurrent and mutated-key reuse, and mixed-curve Schnorr constructor
  rejection have consumer-visible regressions. The Go module minimum is
  aligned with the documented Go 1.25.7 requirement; the preferred
  development and CI toolchain remains Go 1.26.8.
- **Caller-observable behavior follow-ups (PR #41):** `paillier.PublicKey.HomoMultWithBitLen(m, c1, bitLen)` is
  added, and `HomoMult(m, c1)` is equivalent to `HomoMultWithBitLen(m, c1, publicKey.N.BitLen())`;
  an out-of-domain message or exponent (`bitLen` below 1, above the modulus width, or
  a message wider than `bitLen` bits) returns `paillier.ErrMessageTooLong` in both timing
  modes. MtA prover witness domains tighten: `BobMid`/`BobMidWC` reject a witness `b`
  outside `[0, q)` and exponentiate it to the bound `q.BitLen()`; `ProveRangeAlice`
  accepts a witness `m` in `[0, q)`; and `ProofBob`/`ProofBobWC` accept `x` in
  `[0, q)` with its exponent padded to `q.BitLen()`, while `y` keeps its original
  Paillier plaintext domain `[0, pk.N)` and its `pk.N.BitLen()` exponent padding
  (unlike `x`, `m`, and `b`, `y` was not narrowed to the curve order). The
  constant-time exponent widths that narrow from the Paillier modulus width to the
  curve-order `q.BitLen()` are the `x`, `m`, and `b` exponents only; proof bytes for
  in-domain witnesses are
  unchanged. The MtA provers return errors instead of panicking on degenerate
  `pk`/`N`/`NTilde`/`X` inputs, `paillier.HomoAdd` now validates the key modulus
  (`paillier.ErrInvalidModulus`) before use, `common.IsUsableUnknownOrderModulus`
  rejects moduli wider than `common.MaxUnknownOrderModulusBitLen` before the
  primality test, `ckd.NewExtendedKeyFromString` picks its parser by curve
  parameters (`crypto.SameCurve`) and returns an error for keys it cannot parse,
  the keygen ring-Pedersen `beta = alpha^-1 mod pq` uses a constant-time inverse
  when constant-time operations are enabled, and the signing constructors copy
  `keyDerivationDelta` so later caller mutations cannot change the party's key.
  CI adds the `Mixed-binary interop` and `Go minimum build` jobs and a
  HEAD-prover → historical-verifier leg to `verify.sh`.

### Breaking changes

#### 1. Session nonce is mandatory in security-v2 and forbidden in legacy
- **What:** ECDSA keygen and ECDSA signing in security-v2 require a positive session nonce. Each
  protocol's `Start()` (round 1) returns an error if `Parameters.SetSessionNonce` /
  `SetSessionNonceBytes` was not called, e.g.
  `"keygen requires tss.Parameters.SetSessionNonce(...) before Start"`
  (`ecdsa/keygen/round_1.go`, `ecdsa/signing/round_1.go`). The nonce is folded into the SSID
  that binds every proof transcript.
- **Break type:** Runtime (previously-succeeding honest callers now error) **and** wire
  (proofs are now SSID-bound, so transcripts differ from pre-upgrade peers).
- **Motivation:** Without a unique per-ceremony SSID folded into every Fiat-Shamir
  challenge, two ceremonies over otherwise-identical inputs derive the same SSID, enabling
  cross-run transcript splicing / proof replay. Fail-closed prevents silently running
  without session binding.
- **Provenance:** `BNB fc38979` (SSID uniqueness, `Parameters.SessionNonce`), with the
  fail-closed-with-no-fallback decision being `threshold-original`. (Note: the threshold
  base had no SSID machinery at all; the "previous zero / `SHA512_256(messageBytes)`
  fallback" described in upstream history never shipped in this fork's base.)
- **Migration:** Select `ProtocolModeSecurityV2`, then before constructing the
  local party call
  `params.SetSessionNonce(<unique positive *big.Int>)` or
  `params.SetSessionNonceBytes(<>=16-byte high-entropy session ID>)`. All parties in a run
  must agree on the same value. A legacy party selects `ProtocolModeLegacy` and
  must not set a nonce.

#### 2. `fullBytesLen` is required at runtime for signing
- **What:** The ECDSA signing constructors (`NewLocalParty`, `NewLocalPartyWithKDD`) accept
  `fullBytesLen` as a **variadic** argument for source compatibility, but exactly one
  **positive** value is now required at construction time and is bounded to
  `[ceil(msg.BitLen()/8), curveOrderBytes]`. Passing none, zero, multiple, or an
  out-of-range value panics in the constructor (`ecdsa/signing/local_party.go`).
- **Break type:** Runtime (the variadic signature still compiles unchanged, but unupdated
  callers panic at runtime).
- **Motivation:** Pins a fixed, ceremony-wide message byte width so leading zero bytes are
  preserved. The previous minimal `big.Int.Bytes()` encoding silently dropped high-order
  zero bytes, so distinct parties could hash different preimages for the "same" message.
- **Provenance:** `BNB #284` (`9acd90b`, `2f294cf`, `6b92e7d`, `c0de534`).
- **Migration:** Pass a positive `fullBytesLen` (the fixed message/hash width, e.g. `32`)
  to every signing constructor call. The value must be identical across all signers.

#### 3. Tagged-hash / session-bound Fiat-Shamir challenges (DLN, Schnorr, MtA, range proof)
- **What:** Challenge derivation for DLN (`crypto/dlnproof`), Schnorr
  (`crypto/schnorr`), MtA `ProofBob`/`ProofBobWC` (`crypto/mta/proofs.go`), and
  `RangeProofAlice` (`crypto/mta/range_proof.go`) now uses length-delimited tagged hashing
  (`common.SHA512_256i_TAGGED`) plus session context in security-v2. The
  no-session legacy path retains the exact historical construction and input
  list; the challenge bytes change only when security-v2 is selected. Per-party
  security-v2 proof contexts also append a fixed-width `uint64` party index so
  party 0 no longer collapses to the bare SSID.
- **Break type:** Wire/protocol in security-v2 (legacy and security-v2 proofs do
  not cross-verify). The explicit legacy mode is byte-compatible with the
  historical transcript.
- **Motivation:** Domain separation binds each proof to its session/sub-protocol context,
  defeating cross-protocol and cross-session proof replay. The MtA path additionally binds
  `NTilde, h1, h2` into the transcript so a malicious verifier cannot swap ring-Pedersen
  parameters.
- **Provenance:** `BNB #252` (`3d95e54`), `BNB #256` (`1a14f3a`), `BNB #257` (`ff989bf`,
  tagged hashing), `BNB b59ed36` (DLN/MtA session context); party-index append is
  `threshold-original`.
- **Migration:** Use legacy for work anchored before the coordinated cutover and
  security-v2 for work anchored at or after it. All parties in one ceremony use
  the same mode. Historical proofs remain re-verifiable through the legacy API.

#### 4. Tagged Fiat-Shamir for Paillier ModProof / FactorProof (active in security-v2)
- **What:** `ModProof`/`ModVerify` and `FactorProof`/`FactorVerify`
  (`crypto/paillier/mod_proof.go`, `factor_proof.go`) gain an optional session tag. When a
  session tag **is** supplied, the challenges are derived from
  `common.SHA512_256i_TAGGED`: the `ModProof` path samples each challenge uniformly in
  `[0, N)` by expand-then-reject (`sampleYModN` under the `fsSessionModProof` tag,
  chaining the previously-derived challenges `y[:i]` into each hash input, which is what
  avoids the challenge bias of a bare modular reduction), and the `FactorProof` path
  takes a 256-bit challenge by design (`SHA512_256i_TAGGED` under the
  `fsSessionFactorProof` tag, reduced mod `2^256`). The session-tagged path is **not**
  wire-compatible with pre-upgrade peers. With **no** session tag the challenge bytes
  are unchanged (backward-compatible default).
- **Break type:** Wire/protocol **only when a session tag is supplied** (in security-v2;
  legacy parties pass no tag and keep their historical challenges).
- **Motivation:** Domain separation for the Paillier proofs without weakening Threshold's
  existing `N`/`NTilde` `ModProof`/`FactorProof` remediation. Threshold's stronger coverage
  was retained; no BNB no-proof escape hatches were introduced.
- **Provenance:** `BNB #252`, `BNB #257`; in-tree round code passes session tags in
  security-v2 only, so the tagged path is active on the security-v2 protocol path.
- **Migration:** Covered by the coordinated upgrade in Breaking Change 1/3.

#### 5. Per-proof-system Fiat-Shamir domain tags (PR #6)
- **What:** DLN, Schnorr, MtA, and Paillier challenges now prepend a per-proof-system domain
  tag (e.g. `dlnproof|`, `zk|`, `zkv|`, via `fsDomainTag*` / `fsSession*`) to the session
  before tagged hashing. This further changes every security-v2 proof transcript relative
  to Breaking Change 3; legacy (no-session) challenges keep the historical untagged
  construction.
- **Break type:** Wire/protocol (security-v2 only; legacy keeps the historical untagged
  challenges) — compounds Breaking Change 3; still a single coordinated upgrade (a PR #6
  node and a PR #2–#5 node will not cross-verify).
- **Motivation:** Distinct domain separation per proof system, so a challenge from one proof
  type can never be reused in another.
- **Provenance:** `BNB #252` / `BNB #256` domain-tag design; PR #6.
- **Migration:** Covered by the coordinated upgrade in Breaking Change 1/3.

#### 6. `ecdsa/signing.PrepareForSigning` returns an error (PR #6)
- **What:** the exported signature changed from `(wi, bigWs)` to `(wi, bigWs, err)`; it now
  validates its inputs and returns an error instead of proceeding on malformed data
  (`ecdsa/signing/prepare.go`).
- **Break type:** Source/compile — downstream callers must handle the third return value.
- **Motivation:** Surface invalid signing-preparation inputs instead of producing corrupt
  signing state.
- **Provenance:** BNB hardening follow-ups; PR #6. (A code search found no current
  `threshold-network/keep-core` callers.)
- **Migration:** Update call sites to handle the returned `error`.

#### 7. Stricter `tss.NewParameters` and `SortPartyIDs` validation (PR #6)
- **What:** `NewParameters` now panics on a party count below 2, a threshold outside
  `[1, partyCount)`, a `PartyID` key congruent to 0 mod q, or two `PartyID`s colliding mod q;
  `SortPartyIDs` panics on duplicate raw party keys (`tss/params.go`, `tss/party_id.go`).
- **Break type:** Runtime — rejects previously-accepted but invalid/degenerate party sets.
  Honest setups with ≥2 distinct, non-colliding parties and a valid threshold are unaffected.
- **Motivation:** Fail fast on malformed party sets that would otherwise corrupt VSS or the
  protocol.
- **Provenance:** `threshold-original` / BNB hardening; PR #6.
- **Migration:** Ensure ceremonies use ≥2 distinct parties, a threshold in `[1, partyCount)`,
  and non-colliding keys (normal configurations already satisfy this).

#### 8. Constant-time cryptographic operations enabled by default
- **What:** Secret-exponent modular exponentiation and modular inverse (Paillier
  Decrypt/Encrypt/HomoMult, the Paillier mod- and factor-proofs, the DLN proof, the
  ring-Pedersen trapdoor setup in keygen, the MtA range and regular proofs, the Schnorr
  proof responses, and ECDSA signing rounds 3-5) now run through a `filippo.io/bigmod`-backed
  constant-time path (`common.NewCTModInt`, `.ExpCT`/`.MulCT`/`.ModInverseCT`) instead of
  `math/big`, closing the timing side-channel described in
  [golang/go#20654](https://github.com/golang/go/issues/20654) for the operations listed above.
  (The response timing of `crypto/mta`'s Paillier-decrypt path is not normalized — see the
  known residual gap below and the COVERAGE comment in `common/constant_time.go`.) Unlike upstream, where
  `EnableConstantTimeOps` is opt-in and nothing in-tree ever calls it, this fork enables it
  unconditionally by defaulting `constantTimeEnabled` to `1` in `common/constant_time.go` —
  every consumer gets the fix with no code change required. Coverage also broadened from
  secret-exponent-only to secret-operand operations: `MulCT` sites (k·gamma, k·w, m·k,
  rx·sigma, c·x, c·s, c·l) protect both multiplicands, not just the exponent.
- **Sites extended by PR #23, for audit traceability against BNB #328:**
  | File | Function | CT op | Secret operand |
  |------|----------|-------|----------------|
  | `crypto/schnorr/schnorr_proof.go` | `NewZKProofWithSession` | `MulCT(c, x)` → `t = a + c·x` | `x` (discrete log) |
  | `crypto/schnorr/schnorr_proof.go` | `NewZKVProofWithSession` | `MulCT(c, s)`, `MulCT(c, l)` → `t = a + c·s`, `u = b + c·l` | `s`, `l` |
  | `ecdsa/signing/round_3.go` | `round3.Start` | `MulCT(k, gamma)`, `MulCT(k, w)` → `thelta`, `sigma` | `k`, `gamma`, `w` |
  | `ecdsa/signing/round_4.go` | `round4.Start` | `ModInverseCT(theta)` → `thetaInverse` | `theta` |
  | `ecdsa/signing/round_5.go` | `round5.Start` | `MulCT(m, k)`, `MulCT(rx, sigma)` → `si` | `k`, `sigma` (`m` is the public message hash; `rx = R.X()` is derived from public values by round 5, so its mod-N reduction is not a secret-dependent operation) |
- **Known residual gap (read before relying on "constant-time enabled"):** in
  `crypto/mta.AliceEnd`/`AliceEndWC` (signing rounds 2-3), the Paillier exponentiation
  inside `Decrypt` uses the constant-time path, but the surrounding `math/big`
  conversion, `L(u)` division, and reduction are variable-time, and response time is not
  normalized. Upstream adds a ~200ms sleep-based normalizer that this fork deliberately
  did not port (latency cost); the gap is disclosed in the COVERAGE comment in
  `common/constant_time.go`.
  Two further gaps are outside the bigmod path even where the operation
  itself is constant-time: the one-time per-proof MtA blind exponents
  (`alpha`, `rho`, `rhoPrm`, `sigma`, `gamma`, `tau`, and the `beta^N` term
  in `crypto/mta`) stay on `math/big` — they are fresh per proof, but each
  masks a secret witness in a published response (for example S1 = e*x +
  alpha in the Bob proof), so a timing leak of a blind can leak the witness;
  leaving them on `math/big` is a documented pragmatic deferral, not a
  safety claim — and EC scalar
  multiplications on `tss.S256()` use the btcec/v2 (Decred) variable-time
  routines. Neither is claimed covered by this PR; both are in scope for the
  pre-mainnet side-channel review.
- **Break type:** Performance only. Same mathematical result on every path (see the
  constant-time equivalence tests added alongside each hardened package); no wire, source,
  or runtime-input behavior changes. A microbenchmark
  (`go test ./common/... -bench 'BenchmarkExp(CT|Standard)' -benchtime=2s`) measured constant-time
  modexp at parity with the standard path on this fork's test hardware (~2.7ms vs ~2.8ms per op,
  n≈900 CT samples, n≈800 standard samples). The 256-bit-class `MulCT` and `ModInverseCT`
  operations this PR's Schnorr/signing-rounds extension actually uses are measured by the
  paired `BenchmarkMulCT`/`BenchmarkMulStandard` and
  `BenchmarkModInverseCT`/`BenchmarkModInverseStandard` benchmarks (256-bit prime modulus):
  `MulCT` runs at roughly 2x the standard `math/big` multiply (≈2.3µs vs ≈1.1µs per op on
  this fork's test hardware) and `ModInverseCT` runs at roughly 15-20x the standard
  `math/big` modular inverse (≈79µs vs ≈4.5µs per op) because the constant-time inverse is a
  full 256-bit Fermat modexp where the standard path uses the extended-Euclidean algorithm.
  Both are CPU-only regressions on the signing hot path, bounded and documented; the CPU-cost
  concern that motivated the original deferral did not materialize for `MulCT`, and the
  `ModInverseCT` cost is the explicit price of the constant-time guarantee.
  End to end, 2048-bit Paillier `Decrypt` takes about 70 ms on the constant-time path
  versus about 33 ms on `math/big` (about 2.1x, after PR #31), and a 10-member keep-core
  signing ceremony measured about 1.3x slower than with the pre-hardening tss-lib.
- **Motivation:** `math/big` is explicitly not constant-time; a secret-dependent modexp or
  modinverse can leak key material through timing. Shipping this opt-in-only (as upstream
  does) means the fix does nothing until every downstream caller remembers to enable it —
  the exact failure mode this fork avoids by enabling it by default.
- **Provenance:** `BNB #328` (`3709c25`, `7a10240`, `0735081`, merged at `3f677ff`). Upstream's
  series additionally touches `crypto/schnorr/schnorr_proof.go` and
  `ecdsa/signing/round_3.go`/`round_4.go`/`round_5.go`, which this fork's initial backport
  did not — extended here to match, with a new `crypto/schnorr/constant_time_equiv_test.go`.
  The unconditional-enable decision is `threshold-original`. Landed via PR #17, extended here
  by PR #23.
- **Migration:** None required — automatic. A caller who has independently benchmarked their
  own deployment and explicitly accepts the timing risk may call
  `common.DisableConstantTimeOps()`; not recommended for production custody use.
- **Test refactor:** `crypto/schnorr/constant_time_equiv_test.go` migrated from the legacy
  `math/rand.NewSource` API to `math/rand/v2.NewPCG` via a small `io.Reader` adapter.
  Behaviour, determinism, and bit-exact CT/non-CT equivalence assertions are unchanged;
  the seed `(1, 1)` now feeds a v2 PCG instead of the legacy additive-lagged-Fibonacci
  generator.

#### 9. Signing results are delivered by pointer (PR #39)
- **What:** `signing.NewLocalParty` and `NewLocalPartyWithKDD` take
  `end chan<- *common.SignatureData` instead of `chan<- common.SignatureData`. The
  party sends a deep copy (`proto.Clone`) that the receiver owns.
- **Break type:** Source/API (compile-time). Wire bytes and signatures are unchanged.
- **Motivation:** `common.SignatureData` is a protobuf message that embeds a mutex, so
  delivering it by value made every receiver copy a lock (`go vet` copylocks).
- **Provenance:** `BNB fbb0ef7` (the same API), with the clone on send as a
  `threshold-original` difference. Previously deferred as unneeded churn; adopted
  before the first tagged release so callers absorb one breaking release, not two.
- **Migration:** `endCh := make(chan *common.SignatureData, 1)`; the received value is
  a `*common.SignatureData`.

#### 10. `tss.S256()` returns a different concrete curve type (PR #21)
- **What:** `tss.S256()` still returns an `elliptic.Curve` named `secp256k1`, but its
  concrete type is now btcec/v2's alias of Decred `secp256k1/v4.KoblitzCurve` instead of
  the legacy `btcec.KoblitzCurve`.
- **Break type:** Source/runtime for callers that type-assert the curve, import legacy
  `btcec`, or compare curve objects (for example `reflect.DeepEqual` on
  `ecdsa.PublicKey`, which compares the `Curve` field). Point coordinates, compressed key
  parsing, and JSON/Gob encodings are unchanged.
- **Motivation:** The btcd version previously required has published advisories; the
  fixed releases removed the legacy `btcec` package.
- **Provenance:** `threshold-original`, PR #21.
- **Migration:** Use the `elliptic.Curve` interface. Callers holding keys from another
  secp256k1 implementation should compare keys by coordinates or encoded bytes, or rebuild
  them on one curve object.
- **Also in this change:** `ckd.NewExtendedKeyFromString` picks its public-key
  parser by curve parameters (`crypto.SameCurve` against `btcec.S256`) instead of
  the concrete-type assertion, and returns an error for curves that cannot
  parse the key data instead of a nil-coordinate key.

#### 11. Keygen message decoders return errors (PR #28)
- **What:** `KGRound2Message1.UnmarshalFactorProof`, `UnmarshalFactorProofTilde`, and
  `KGRound3Message.UnmarshalProofInts` return `(value, error)` instead of a bare value.
- **Break type:** Source/compile for direct callers; in-tree rounds are updated.
- **Motivation:** A malformed peer encoding now produces an attributable error instead of
  a panic or a nil value used later.
- **Provenance:** `threshold-original`, PR #28.
- **Migration:** Handle the returned `error`.

#### 12. Go 1.25.7 minimum (PR #20)
- **What:** `go.mod` declares `go 1.25.7` with `toolchain go1.26.8`.
- **Break type:** Build. Builders with `GOTOOLCHAIN=local` and an older Go (including
  official `golang:1.24` images, which default to `GOTOOLCHAIN=local`) fail to build
  dependents.
- **Motivation:** Aligns with keep-core's toolchain and the upgraded `golang.org/x`
  dependencies.
- **Provenance:** `threshold-original`, PR #20; minimum restored to 1.25.7 by `fa6ef4d`.
- **Migration:** Build with Go 1.25.7 or newer, or set `GOTOOLCHAIN=auto`.

> Source/compile breaks in this set: `ecdsa/signing.PrepareForSigning` gained an `error`
> return (Breaking Change 6), the signing end channel carries `*common.SignatureData`
> (Breaking Change 9), and three keygen message decoders return errors (Breaking Change 11).
> PR #5's protocol removal deleted the exported `tss.ReSharingParameters` /
> `tss.NewReSharingParameters`, `crypto.ECPoint.EightInvEight`, and
> `ecdsa/resharing.NewDGRound1Message` API (see Removed). Every session / `fullBytesLen`
> parameter was added as a trailing variadic argument, so other call sites compile
> unchanged; those breaks are runtime/wire. Verified by diffing `go doc` exported
> signatures between the threshold base `2e712689` and `dev`. Breaking Changes 10
> and 12 are type-identity and toolchain breaks, not signature changes, and sit
> outside that diff.

### Removed

#### EdDSA protocols (PR #5)
- The `eddsa/keygen`, `eddsa/signing`, and `eddsa/resharing` packages and their protobuf
  definitions (`protob/eddsa-*.proto`) were deleted; this fork now targets ECDSA only (the
  tBTC use case). The `Ed25519` curve registration and `tss.Edwards()` helper
  (`tss/curve.go`), the EdDSA cofactor helper `crypto.ECPoint.EightInvEight()`, the EdDSA
  keygen test fixtures, and the `github.com/agl/ed25519` and
  `github.com/decred/dcrd/dcrec/edwards/v2` dependencies (with the `binance-chain/edwards25519`
  replace) were removed accordingly; `protob/message.proto`'s resharing routing fields were
  re-commented as legacy. Removing the exported `EightInvEight` method is a source/compile
  break for any caller of it. The EdDSA-specific hardening from PR #2 — full-length round-3
  message hashing, the EdDSA keygen `NewECPoint` nil-pointer fix, EdDSA signing session-nonce
  fail-closed — is moot on this fork and has been dropped from the entries above.
  _Provenance: `threshold-original`, PR #5._

#### ECDSA resharing protocol (PR #5)
- The `ecdsa/resharing` package, its protobuf (`protob/ecdsa-resharing.proto`), the
  `DGRound1Message` SSID wire field, the exported `NewDGRound1Message` constructor, and the
  exported `tss.ReSharingParameters` type with its `tss.NewReSharingParameters` constructor and
  methods (`OldParties`, `OldPartyCount`, `NewParties`, `NewPartyCount`, `NewThreshold`,
  `OldAndNewParties`, `OldAndNewPartyCount`, `IsOldCommittee`, `IsNewCommittee`) were deleted.
  Removing these exported symbols is a source/compile break for any resharing caller. The
  resharing SSID-broadcast wire break and the `NewDGRound1Message` source/compile break
  documented for PR #2 therefore no longer apply, and the session-nonce fail-closed requirement
  (Breaking Change 1) no longer covers resharing. _Provenance: `threshold-original`, PR #5._

### Security & correctness hardening (non-breaking)

These tighten validation against malformed or malicious input, or fix latent bugs, without
rejecting input that an honest caller would previously have produced.

- **MtA / range / factor / mod proof boundary checks:** GCD, interval, lower/upper-bound,
  non-one/non-zero, ciphertext-coprimality, and curve-mismatch checks now reject malformed
  or adversarial proofs (returning errors instead of panicking on, e.g., a nil `U` or a
  cross-curve point). Honest proofs are unaffected. The MtA `betaPrm` sampling range was
  narrowed (`q^5` instead of `N`) to match the new verifier bounds; this changes
  intermediate ciphertext/proof wire values but preserves the `alpha + beta ≡ a·b mod q`
  MtA output. _Provenance: `BNB #252`, `BNB #289` (`5d01446`)._
- **VSS commitment-vector length check:** `feldman_vss.Verify` now requires
  `len(vs) == threshold+1`, turning a potential out-of-range panic on a short/long
  adversarial commitment vector into a clean `false`. _Provenance: `BNB #291` (`843de68`)._
- **VSS reconstruction off-by-one fix:** `feldman_vss.ReConstruct` now requires
  `threshold+1` shares (was `threshold`) and guards the empty-slice case. The previous
  behavior silently reconstructed an **incorrect** secret from `threshold` shares.
  Behavior change: a caller passing exactly `threshold` shares now receives
  `ErrNumSharesBelowThreshold` instead of a wrong value. No in-tree non-test caller is
  affected. _Provenance: `BNB #324` (`4878da5`)._
- **ECDSA `SignatureData.M` is now full-length-padded:** ECDSA signing finalize emits the
  message and computes the verify preimage with `FillBytes(fullBytesLen)` instead of minimal
  `m.Bytes()` (`ecdsa/signing/finalize.go`). This is an output-format change only — ECDSA
  scalar math uses `m` as an integer, so it is not an interop break — but an operator
  diffing the emitted `data.M` across the upgrade will see padded bytes. _Provenance:
  `BNB #284`._
- **Canonical EC coordinate rejection:** EC point construction/deserialization
  (`crypto/ecpoint.go`, backing `NewECPoint`, `GobDecode`, `UnmarshalJSON`) now rejects
  coordinates outside `[0, P)`. Honest callers never produce out-of-range coordinates;
  this hardens against malicious peer input. _Provenance: `BNB 685c2af`._
- **`round.ok` accumulation fix:** all non-terminal ECDSA keygen and signing rounds now
  accumulate per-party readiness across the whole message set instead of bailing on the
  first not-ready party, fixing inconsistent bookkeeping under out-of-order message
  delivery. Internal only; no wire or API change. _Provenance: `BNB #282` (`409542e`)._
- **`BaseParty.String()` nil guard:** returns `"No more rounds"` instead of panicking after
  completion. _Provenance: `BNB #276` (`f3aad28`)._
- **Panic/DoS guards on EC point operations (PR #4):** `ECPoint.ScalarMult`,
  `ScalarBaseMult`, `Add`, `SetCurve`, and `isOnCurve` return nil/error on
  nil or invalid inputs instead of panicking (`crypto/ecpoint.go`). Signatures unchanged;
  honest callers never pass nil. _Provenance: `BNB #332`, PR #4._
- **Schnorr verifier pre-checks (PR #4):** `Verify`/`VerifyWithSession` reject nil/invalid
  public points, zero or out-of-range scalars, a zero challenge, and nil scalar-mult results
  before use (`crypto/schnorr/schnorr_proof.go`). Challenge derivation is unchanged;
  malicious/degenerate input only. _Provenance: `BNB #332`, PR #4._
- **DLN verifier canonical `Alpha` check (PR #4):** `Verify` requires each `Alpha` to be
  canonically in `(1, N)` instead of accepting values that only landed in range after
  reduction mod `N`, and guards nil `h1`/`h2`/`N`/`Alpha`/`T` (`crypto/dlnproof/proof.go`).
  Honest provers already produce canonical `Alpha`. _Provenance: `BNB #332`, PR #4._
- **Paillier FactorProof response bounds (PR #4):** the verifier rejects `W1`, `W2`,
  `Sigma`, and `V` outside their absolute bounds (keeping the existing inclusive `Z1`/`Z2`
  style) before verification (`crypto/paillier/factor_proof.go`). Honest proofs pass.
  _Provenance: `BNB #332`, PR #4._
- **MtA / range-proof bounds and nil guards (PR #4):** `ProofBob`/`ProofBobWC`/
  `RangeProofAlice` verifiers reject nil moduli/inputs, tighten the `S2`/`T2` upper bounds to
  exclusive, and add an explicit nil-result check after `xE.Add(pf.U)` (`crypto/mta/*.go`).
  Honest proofs pass. _Provenance: `BNB #332`, PR #4._
- **VSS share-verification guards (PR #4):** `Verify` rejects nil, zero, and out-of-range
  shares and verifier points (and validates each commitment point) before scalar
  multiplication (`crypto/vss/feldman_vss.go`). _Provenance: `BNB #332`, PR #4._
- **ECDSA keygen round-1 modulus-width check (PR #4):** `KGRound1Message.ValidateBasic`
  rejects Paillier `N` / `NTilde` that are not exactly 2048 bits, failing fast on malformed
  peer messages and mirroring the pre-existing round-2 contract. Honest 2048-bit keys are
  unaffected. _Provenance: `BNB #332`, PR #4._
- **ECDSA signing round-9 decommitment guard fix (PR #4):** corrected the de-commitment
  validation from `!ok && len(values) != 4` to `!ok || len(values) != 4` (extracted as
  `decommitFour`), closing a soundness/DoS gap where a malformed or oversized de-commitment
  could be read as attacker-chosen point coordinates or cause an out-of-range panic
  (`ecdsa/signing/round_9.go`). _Provenance: `BNB #332`, PR #4._
- **ECDSA signing round-4 nil theta-inverse guard (PR #4):** a non-invertible theta
  (`ModInverse` returning nil) is rejected with a clean error instead of propagating nil
  (`ecdsa/signing/round_4.go`). _Provenance: `BNB #332`, PR #4._
- **Shared cryptographic input validators (PR #6):** `common/validation.go` adds reusable
  canonical checks for unknown-order moduli, generators, and Paillier ciphertexts, wired into
  the proof verifiers and round handlers. _Provenance: `BNB #252`/`BNB #332`, PR #6._
- **VSS reconstruction input validation (PR #6):** `feldman_vss` rejects malformed
  reconstruction inputs and out-of-bound parameters before use (`crypto/vss/feldman_vss.go`).
  _Provenance: `BNB #332`, PR #6._
- **Idempotent message redelivery (PR #6):** keygen/signing message storage treats an
  identical redelivery from a party as a no-op while rejecting a content-different replay,
  preventing duplicate-message state corruption (`tss/message.go`). _Provenance: `threshold-original`, PR #6._
- **Review follow-up correctness fixes (PR #6):** Schnorr verification accepts unregistered
  generic curves; `common.GetRandomInt`'s zero-inclusive range is corrected; message wire
  bytes are made deterministic; large-modulus `sampleYModN` block indexing is fixed; and
  canonical-generator checks were added in `crypto/paillier`, and
  `crypto/commitments` validates decommitment payloads for part count and nil parts.
  _Provenance: `BNB #332` + `threshold-original`, PR #6._
- **ECDSA signing round-9 decommitment curve-point validation (PR #7):** decommitted
  `Uj`/`Tj` coordinates are now validated as canonical curve points (`crypto.NewECPoint`)
  before any group operation, with failures attributed to the sending party
  (`ecdsa/signing/round_9.go`). Previously off-curve coordinates went straight into
  `elliptic.Curve.Add`, which panics for Go's stdlib curves and yields undefined coordinates
  for btcec — turning a malformed decommitment into a crash or an unattributed `U != T` abort
  that blamed the honest reporter. Layered on PR #4's `decommitFour` length guard. Honest
  decommitments are unaffected. _Provenance: `BNB #332`, PR #7._
- **ECDSA signing round-1 message-range validation (PR #7):** signing `Start()` now rejects a
  nil, negative, or `>= curve order` hashed message instead of panicking on `Cmp` (nil) or
  surfacing later as an unattributed finalize verification failure (negative)
  (`ecdsa/signing/round_1.go`). Honest callers passing a hash in `[0, N)` are unaffected.
  _Provenance: `threshold-original`, PR #7._
- **Paillier FactorVerify distinct-generator check (PR #7):** `FactorVerify` rejects equal
  Pedersen bases (`s == t`), under which the binding degenerates, mirroring the
  distinct-generator policy already enforced by DLN and MtA proofs
  (`crypto/paillier/factor_proof.go`). Honest setups use distinct generators.
  _Provenance: `threshold-original`, PR #7._

### Added

- `common.SHA512_256i_TAGGED` and `common.HashToNTagged` — length-delimited,
  domain-separated tagged hashing primitives. `common.HashToNTagged` is exported
  but not yet used by the in-tree Paillier proofs, which derive their
  session-tagged challenges via `common.SHA512_256i_TAGGED` plus
  expand-then-reject sampling or a 256-bit modular reduction. _Provenance: `BNB #257`._
- `tss.Parameters.SessionNonce`, `SetSessionNonce`, `SetSessionNonceBytes` — session-nonce
  API. `SetSessionNonce` rejects non-positive nonces; `SetSessionNonceBytes` requires a
  session ID of at least 16 bytes. _Provenance: `BNB fc38979`._
- `common.IsInInterval`, `common.AppendUint64ToBytesSlice` (used for per-party
  transcript context), `common.AppendBigIntToBytesSlice`, and `tss.SameCurve` —
  helpers backing the hardened range checks and session/transcript context
  construction. `common.IsInInterval`, `common.AppendBigIntToBytesSlice`, and
  `tss.SameCurve` are currently unused by library code (production range checks
  use `common.IsInIntervalPositive`, and production curve checks use
  `crypto.SameCurve`); the exported symbols are kept to avoid breaking consumers.
- `schnorr.NewZKProofWithSession`, `NewZKVProofWithSession`, `VerifyWithSession` — session-
  aware Schnorr proof overloads. The original signatures retain their source
  shape and call the historical `HashToN` challenge directly; the
  `WithSession` APIs are security-v2-only, require a non-empty session, and
  never interpret a nil or empty session as legacy.
- `mta.ErrRangeProofVerify` (PR #4) — sentinel error letting ECDSA signing round 2 attribute
  a peer's MtA range-proof rejection to the offending party (`crypto/mta/share_protocol.go`,
  `ecdsa/signing/round_2.go`). _Provenance: `BNB #332`, PR #4._
- `common.EnableConstantTimeOps`, `DisableConstantTimeOps`, `IsConstantTimeEnabled`,
  `NewCTModInt`, `NewCTModIntWithPhi`, and the `CTModInt` type with `ExpCT`/`MulCT`/
  `ModInverseCT` — constant-time modular arithmetic backed by `filippo.io/bigmod`, enabled
  unconditionally by this fork's default (`constantTimeEnabled = 1` in
  `common/constant_time.go`). _Provenance: `BNB #328`, PR #17, PR #23_.
- `tss.ProtocolMode` with `ProtocolModeLegacy` / `ProtocolModeSecurityV2`, and
  `Parameters.SetProtocolMode`, `ProtocolMode`, `FreezeProtocolMode`,
  `SetLegacyHistoricalBobCompatibility`, `LegacyHistoricalBobCompatibility` — explicit
  per-party transcript selection and the rollout-only compatibility opt-in. _PR #9._
- `mta.AliceEndLegacy`, `AliceEndWCLegacy`, `ProofBob.VerifyLegacy`,
  `ProofBobWC.VerifyLegacy` — session-less legacy verification with the optional
  historical witness bound. _PR #9._
- `common.GetCTModInt` (cached constant-time context per modulus, PR #23);
  `CTModInt.ExpCTWithBitLen` (PR #17); `CTModInt.ExpCTWithBytes`,
  `ExpCTCanonicalWithBitLen`, `ExpCTCanonicalWithBytes`, `MulCTCanonical` (review fixes
  `873b8ad`..`fa6ef4d`).
- `common.MinUnknownOrderModulusBitLen` (2048), `MaxUnknownOrderModulusBitLen` (65536),
  and `ExceedsUnknownOrderModulusCeiling` — the shared unknown-order modulus width
  policy. _PR #34._
- `paillier.ErrInvalidModulus` and `paillier.ErrMalformedKey` — sentinel errors for
  invalid Paillier keys (review fixes `873b8ad`..`fa6ef4d`).
- `paillier.PublicKey.HomoMultWithBitLen(m, c1, bitLen)` — homomorphic multiplication
  with an explicit public exponent bound; `HomoMult(m, c1)` is equivalent to it at the
  modulus-width bound. In constant-time mode the exponent is padded to `bitLen`, in
  `math/big` mode `bitLen` only gates validation; out-of-domain messages return
  `paillier.ErrMessageTooLong`. _Provenance: `threshold-original`, PR #41._

### Notes

- `common.RejectionSample` keeps the upstream name for porting clarity but is a modular
  reduction, not a looping rejection sampler.
- Threshold's Paillier/NTilde `ModProof` and `FactorProof` remediation
  (GHSA-h24c-6p6p-m3vx) was retained; the upstream modproof checker (`BNB #323`) was
  already covered.

### Not ported / deferred

- Module path bumps to `/v2`, `/v3` (`BNB faf1884`, `c23246e`) — skipped to preserve
  Threshold compatibility; the module path remains `github.com/bnb-chain/tss-lib`.
- Dependency / random-source API churn and repository/CI/metadata housekeeping
  (`BNB b8d526d`, `8abf1d5`, `6c233c6`, `87f7e12`, `7113b68`, `d0325a1`, `dca2ac4`).
- Response-time normalization for `crypto/mta.AliceEnd`/`AliceEndWC` Paillier decryption.
  Upstream wraps it in a sleep-based normalizer (`NewTimingProtection`, ~200ms target +
  jitter); it was deliberately not added because it would delay every MtA share round by
  about 200ms. The decryption exponentiation itself is constant-time; the surrounding
  `math/big` arithmetic is not (see Breaking Change 8 and the COVERAGE comment in
  `common/constant_time.go`).

### Residual risks
- Applications using `ProtocolModeSecurityV2` **must** call
  `SetSessionNonce`/`SetSessionNonceBytes` with a unique per-ceremony value
  before constructing keygen or signing parties; those protocols fail closed
  without it. Legacy parties leave the nonce unset — setting one in
  `ProtocolModeLegacy` is rejected at party construction.

[Unreleased]: https://github.com/threshold-network/tss-lib/compare/2e712689...HEAD
