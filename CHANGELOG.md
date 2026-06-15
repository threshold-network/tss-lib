# Changelog

All notable changes to this fork (`threshold-network/tss-lib`) are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This fork follows the upstream [`bnb-chain/tss-lib`](https://github.com/bnb-chain/tss-lib)
SemVer line for provenance but has not yet published its own tagged release; all changes
below are therefore listed under `[Unreleased]`.

Provenance notation:
- `BNB #NNN` / `BNB <sha>` — adapted from the named upstream pull request or commit. Most
  were **manually adapted**, not cherry-picked, so behavior may differ from upstream.
- `threshold-original` — introduced in this fork with no direct upstream counterpart.

---

## [Unreleased] — BNB hardening integration

Security and correctness hardening ported or manually adapted from `bnb-chain/tss-lib`,
without replacing Threshold's existing Paillier/NTilde `ModProof`/`FactorProof` remediation.

- Threshold base: `2e712689cfbeefede15f95a0ec7112227d86f702`
- BNB upstream head compared: `3f677ff761fcf692edb0243a5d812930844d879a`

### ⚠️ Compatibility — read before upgrading

**This release is a protocol/wire compatibility break and must be rolled out as a
coordinated protocol upgrade.** Fiat-Shamir proof challenges now use tagged hashing,
session context, and fixed-width message encoding. Parties running pre-upgrade code
**cannot** interoperate with upgraded parties in the same keygen, signing, or resharing
ceremony, even though the Go API remains source-compatible for nearly all call sites.

Do not mix pre- and post-upgrade parties in one ceremony. All participants (and, for
resharing, **both** committees) must run the upgraded build simultaneously.

Two new caller obligations are enforced at runtime (see Breaking Changes 1 and 2):
1. Set a per-ceremony session nonce before `Start()`.
2. Pass a positive `fullBytesLen` to every signing constructor.

### Breaking changes

#### 1. Session nonce is now mandatory and fails closed
- **What:** ECDSA keygen, ECDSA signing, ECDSA resharing, EdDSA keygen, and EdDSA signing
  now require a positive session nonce. Each protocol's `Start()` (round 1) returns an
  error if `Parameters.SetSessionNonce` / `SetSessionNonceBytes` was not called, e.g.
  `"keygen requires tss.Parameters.SetSessionNonce(...) before Start"`
  (`ecdsa/keygen/round_1.go`, `ecdsa/signing/round_1.go`,
  `ecdsa/resharing/round_1_old_step_1.go`, `eddsa/keygen/round_1.go`,
  `eddsa/signing/round_1.go`). The nonce is folded into the SSID that binds every proof
  transcript. **EdDSA resharing is intentionally excluded** — it has no SSID-bound
  transcript in this port (see Residual risks).
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
- **What:** ECDSA and EdDSA signing constructors (`NewLocalParty`, `NewLocalPartyWithKDD`)
  accept `fullBytesLen` as a **variadic** argument for source compatibility, but exactly
  one **positive** value is now required at construction time and is bounded to
  `[ceil(msg.BitLen()/8), curveOrderBytes]`. Passing none, zero, multiple, or an
  out-of-range value panics in the constructor (`ecdsa/signing/local_party.go`,
  `eddsa/signing/local_party.go`).
- **Break type:** Runtime (the variadic signature still compiles unchanged, but unupdated
  callers panic at runtime).
- **Motivation:** Pins a fixed, ceremony-wide message byte width so leading zero bytes are
  preserved. The previous minimal `big.Int.Bytes()` encoding silently dropped high-order
  zero bytes, so distinct parties could hash different preimages for the "same" message.
- **Provenance:** `BNB #284` (`9acd90b`, `2f294cf`, `6b92e7d`, `c0de534`).
- **Migration:** Pass a positive `fullBytesLen` (the fixed message/hash width, e.g. `32`)
  to every signing constructor call. The value must be identical across all signers.

#### 3. EdDSA round-3 hashes the full-length message
- **What:** EdDSA signing round 3 now hashes the message left-padded to `fullBytesLen`
  (`m.FillBytes`) instead of the minimal `m.Bytes()` when deriving `lambda`
  (`eddsa/signing/round_3.go`). This changes each signer's `s` share, hence the final
  signature scalar, whenever `fullBytesLen` exceeds the message's minimal byte length.
- **Break type:** Wire/protocol (cross-version EdDSA signers compute incompatible shares
  and produce an invalid aggregate signature).
- **Motivation:** Canonical fixed-width message encoding; removes the leading-zero
  ambiguity of minimal encoding.
- **Provenance:** `BNB #284`.
- **Migration:** Upgrade all EdDSA signers in lockstep with an identical `fullBytesLen`.

#### 4. Tagged-hash / session-bound Fiat-Shamir challenges (DLN, Schnorr, MtA, range proof)
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

#### 5. Tagged Fiat-Shamir for Paillier ModProof / FactorProof (active on the protocol path)
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
- **Migration:** Covered by the coordinated upgrade in Breaking Change 1/4.

#### 6. ECDSA resharing broadcasts and validates an SSID (`DGRound1Message`)
- **What:** `DGRound1Message` gains a new wire field `bytes ssid = 4`
  (`protob/ecdsa-resharing.proto`). The new committee rejects any DGRound1 broadcast whose
  SSID does not equal its locally-derived SSID, with culprit attribution
  (`ecdsa/resharing/round_1_old_step_1.go`), and `ValidateBasic` now requires a 32-byte
  SSID (`ecdsa/resharing/messages.go`). The exported constructor `NewDGRound1Message` gains
  a required `ssid []byte` parameter.
- **Break type:** Wire/protocol (old and new resharing parties cannot interoperate) **and
  source/compile** — this is the **only** exported signature in the whole integration that
  changed in a source-breaking way; external callers constructing `DGRound1Message`
  directly must update.
- **Motivation:** Lets the new committee detect a corrupted old-committee party that
  broadcasts an inconsistent SSID (committee-substitution / context-disagreement
  detection).
- **Provenance:** `threshold-original`, derived from the `BNB fc38979` session work.
- **Migration:** Upgrade both committees in lockstep; set a session nonce (Breaking Change
  1); update any direct `NewDGRound1Message` callers to pass `ssid`.

> Aside from `NewDGRound1Message` (Breaking Change 6), every session / `fullBytesLen`
> parameter was added as a trailing variadic argument, so all other existing call sites
> compile unchanged. The breaks above are runtime/wire, not compile-time. This was verified
> by diffing every exported signature between the base and HEAD.

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
- **`round.ok` accumulation fix:** all non-terminal ECDSA/EdDSA keygen, signing, and
  resharing rounds now accumulate per-party readiness across the whole message set instead
  of bailing on the first not-ready party, fixing inconsistent bookkeeping under
  out-of-order message delivery. Internal only; no wire or API change. _Provenance:
  `BNB #282` (`409542e`)._
- **Nil-guards:** `BaseParty.String()` returns `"No more rounds"` instead of panicking
  after completion (`BNB #276`, `f3aad28`); the EdDSA resharing round-1 party-0 broadcast
  and EdDSA keygen `NewECPoint`-error path are guarded against nil dereference
  (`BNB #282`, `BNB 5d0d0f3`).

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

- Applications **must** call `SetSessionNonce`/`SetSessionNonceBytes` before keygen,
  signing, and ECDSA resharing; those protocols fail closed without it.
- EdDSA resharing has no SSID-bound proof transcript in this port.
- The optional constant-time work is not integrated.

[Unreleased]: https://github.com/threshold-network/tss-lib/compare/2e712689...HEAD
