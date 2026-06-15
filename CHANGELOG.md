# Changelog

All notable changes to this fork (`threshold-network/tss-lib`) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This fork follows the upstream [`bnb-chain/tss-lib`](https://github.com/bnb-chain/tss-lib)
SemVer line for provenance but has not yet published its own tagged release; all changes
below are therefore listed under `[Unreleased]`.

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

### ⚠️ Compatibility — read before upgrading

**This release is a protocol/wire compatibility break and must be rolled out as a
coordinated protocol upgrade.** Fiat-Shamir proof challenges now use tagged hashing,
session context, and fixed-width message encoding. Parties running pre-upgrade code
**cannot** interoperate with upgraded parties in the same keygen or signing ceremony,
even though the Go API remains source-compatible.

Do not mix pre- and post-upgrade parties in one ceremony; all participants must run the
upgraded build simultaneously.

Two new caller obligations are enforced at runtime (see Breaking Changes 1 and 2):
1. Set a per-ceremony session nonce before `Start()`.
2. Pass a positive `fullBytesLen` to every signing constructor.

### Breaking changes

#### 1. Session nonce is now mandatory and fails closed
- **What:** ECDSA keygen and ECDSA signing now require a positive session nonce. Each
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
- **Migration:** Before `Start()`, on the constructing goroutine, call
  `params.SetSessionNonce(<unique positive *big.Int>)` or
  `params.SetSessionNonceBytes(<>=16-byte high-entropy session ID>)`. All parties in a run
  must agree on the same value.

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
  (`common.SHA512_256i_TAGGED`) plus optional session context. **The challenge bytes change
  unconditionally** — even on the default/nil-session path — because the underlying hash
  construction itself changed. Per-party proof contexts also append a fixed-width `uint64`
  party index so party 0 no longer collapses to the bare SSID.
- **Break type:** Wire/protocol (old and new proofs do not cross-verify).
- **Motivation:** Domain separation binds each proof to its session/sub-protocol context,
  defeating cross-protocol and cross-session proof replay. The MtA path additionally binds
  `NTilde, h1, h2` into the transcript so a malicious verifier cannot swap ring-Pedersen
  parameters.
- **Provenance:** `BNB #252` (`3d95e54`), `BNB #256` (`1a14f3a`), `BNB #257` (`ff989bf`,
  tagged hashing), `BNB b59ed36` (DLN/MtA session context); party-index append is
  `threshold-original`.
- **Migration:** Coordinated network-wide upgrade; no mixed old/new parties. Any persisted
  pre-upgrade proofs are not re-verifiable.

#### 4. Tagged Fiat-Shamir for Paillier ModProof / FactorProof (active on the protocol path)
- **What:** `ModProof`/`ModVerify` and `FactorProof`/`FactorVerify`
  (`crypto/paillier/mod_proof.go`, `factor_proof.go`) gain an optional session tag. When a
  session tag **is** supplied they use tagged hashing (`common.HashToNTagged`, sized to the
  modulus to avoid challenge bias) and are **not** wire-compatible with pre-upgrade peers.
  With **no** session tag the challenge bytes are unchanged (backward-compatible default).
- **Break type:** Wire/protocol **only when a session tag is supplied**.
- **Motivation:** Domain separation for the Paillier proofs without weakening Threshold's
  existing `N`/`NTilde` `ModProof`/`FactorProof` remediation. Threshold's stronger coverage
  was retained; no BNB no-proof escape hatches were introduced.
- **Provenance:** `BNB #252`, `BNB #257`; the in-tree round code now passes session tags,
  so in practice this is active on the protocol path.
- **Migration:** Covered by the coordinated upgrade in Breaking Change 1/3.

#### 5. Per-proof-system Fiat-Shamir domain tags (PR #6)
- **What:** DLN, Schnorr, MtA, and Paillier challenges now prepend a per-proof-system domain
  tag (e.g. `dlnproof|`, `zk|`, `zkv|`, via `fsDomainTag*` / `fsSession*`) to the session
  before tagged hashing. This further changes every proof transcript relative to Breaking
  Change 3.
- **Break type:** Wire/protocol — compounds Breaking Change 3; still a single coordinated
  upgrade (a PR #6 node and a PR #2–#5 node will not cross-verify).
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

> Source/compile breaks in this set: `ecdsa/signing.PrepareForSigning` gained an `error` return
> (Breaking Change 6, PR #6), and PR #5's protocol removal deleted the exported
> `tss.ReSharingParameters` / `tss.NewReSharingParameters`, `crypto.ECPoint.EightInvEight`, and
> `ecdsa/resharing.NewDGRound1Message` API (see Removed). Otherwise every session /
> `fullBytesLen` parameter was added as a trailing variadic argument, so all remaining call
> sites compile unchanged; those breaks are runtime/wire. Verified by diffing exported
> signatures between base and HEAD.

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
  canonical-generator checks were added in `crypto/commitments` and `crypto/paillier`.
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

- `common.SHA512_256i_TAGGED` and `common.HashToNTagged` — length-delimited, domain-
  separated tagged hashing primitives. _Provenance: `BNB #257`._
- `tss.Parameters.SessionNonce`, `SetSessionNonce`, `SetSessionNonceBytes` — session-nonce
  API. `SetSessionNonce` rejects non-positive nonces; `SetSessionNonceBytes` requires a
  session ID of at least 16 bytes. _Provenance: `BNB fc38979`._
- `common.IsInInterval`, `common.AppendUint64ToBytesSlice`,
  `common.AppendBigIntToBytesSlice` (the last currently unused), and `tss.SameCurve` —
  helpers backing the hardened range checks and session/transcript context construction.
- `schnorr.NewZKProofWithSession`, `NewZKVProofWithSession`, `VerifyWithSession` — session-
  aware Schnorr proof overloads (the original signatures are retained and delegate with a
  nil session).
- `mta.ErrRangeProofVerify` (PR #4) — sentinel error letting ECDSA signing round 2 attribute
  a peer's MtA range-proof rejection to the offending party (`crypto/mta/share_protocol.go`,
  `ecdsa/signing/round_2.go`). _Provenance: `BNB #332`, PR #4._

### Notes

- `common.RejectionSample` keeps the upstream name for porting clarity but is a modular
  reduction, not a looping rejection sampler.
- Threshold's Paillier/NTilde `ModProof` and `FactorProof` remediation
  (GHSA-h24c-6p6p-m3vx) was retained; the upstream modproof checker (`BNB #323`) was
  already covered.

### Not ported / deferred

- Module path bumps to `/v2`, `/v3` (`BNB faf1884`, `c23246e`) — skipped to preserve
  Threshold compatibility; the module path remains `github.com/bnb-chain/tss-lib`.
- `SignatureData` channel-to-pointer change (`BNB fbb0ef7`) — public API churn not needed
  for hardening.
- Optional constant-time framework (`BNB #328`) — adds a dependency and broad
  Paillier/MtA rewrites, default-disabled upstream; deferred to a separate follow-up with
  benchmarking and side-channel review.
- Dependency / random-source API churn and repository/CI/metadata housekeeping
  (`BNB b8d526d`, `8abf1d5`, `6c233c6`, `87f7e12`, `7113b68`, `d0325a1`, `dca2ac4`).

### Residual risks

- Applications **must** call `SetSessionNonce`/`SetSessionNonceBytes` before keygen and
  signing; those protocols fail closed without it.
- The optional constant-time work is not integrated.

[Unreleased]: https://github.com/threshold-network/tss-lib/compare/2e712689...HEAD
