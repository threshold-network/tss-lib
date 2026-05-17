# BNB Hardening Integration Report

## Scope

- Threshold base: `2e712689cfbeefede15f95a0ec7112227d86f702`
- BNB upstream head compared: `3f677ff761fcf692edb0243a5d812930844d879a`
- Common ancestor: `afbe264b44b63155a864dbe0171040c66e442963`
- Goal: port applicable security and correctness hardening without replacing Threshold's Paillier/NTilde remediation or weakening `ModProof`/`FactorProof`.

## Compatibility Notice

This is a protocol/wire compatibility break for proof transcripts. Proofs whose Fiat-Shamir challenges now use tagged hashing or session context will not verify across mixed old/new versions, even where the Go API remains source-compatible through variadic arguments. Operators should roll this out as a coordinated protocol upgrade rather than mixing parties from before and after this PR in the same keygen, signing, or resharing ceremony.

## Ported Or Manually Adapted

- `3d95e54` / PR `#252`, ECDSA protocol security updates: manually adapted tagged challenges, MtA/range-proof validation, session-context plumbing, and proof boundary checks while preserving Threshold's existing Paillier/NTilde proof model.
- `1a14f3a` / PR `#256`, ECDSA proof session byte: manually adapted proof-session APIs for DLN, Schnorr, MtA, Paillier mod proof, and factor proof. Public callers remain source-compatible through variadic session parameters, but generated proof transcripts are not wire-compatible with old versions.
- `ff989bf` / PR `#257`, tagged hash encoding: ported length-delimited tagged hashing as `common.SHA512_256i_TAGGED`.
- `f3aad28` / PR `#276`, nil `String()` panic: ported `BaseParty.String()` nil-round guard.
- `409542e` / PR `#282`, round update correctness: ported the `round.ok` accumulation fix for all non-terminal ECDSA/EdDSA keygen, signing, and resharing rounds, plus the resharing party-0 broadcast nil guard.
- `9acd90b`, `2f294cf`, `6b92e7d`, `c0de534` / PR `#284`, leading-zero message signing: manually adapted for ECDSA and EdDSA with backward-compatible variadic `fullBytesLen` parameters. EdDSA now also hashes the full-length message bytes in round 3.
- `843de68` / PR `#291`, VSS threshold-size validation: ported `len(vs) == threshold+1` verification and added test coverage.
- `5d01446` / PR `#289`, range-proof update: ported MtA range-proof GCD, interval, lower-bound, non-one, and tagged challenge checks.
- `4878da5` / PR `#324`, VSS reconstruction fix: ported `threshold+1` reconstruction requirement and updated ECDSA/EdDSA keygen fixture tests.
- `b59ed36`, session context for DLN and MtA proofs: manually adapted with optional session contexts and focused replay/session-mismatch tests.
- `fc38979`, GG20 SSID uniqueness: ported `tss.Parameters.SessionNonce` / `SetSessionNonce` and ECDSA/EdDSA keygen/signing/resharing SSID derivation. Signing defaults to message hash as nonce; keygen/resharing support caller-provided nonce and otherwise preserve BNB's zero fallback.
- `685c2af`, canonical EC coordinates: ported rejection of EC coordinates outside `[0, P)`.
- `5d0d0f3`, EdDSA nil-pointer fix: ported by checking `NewECPoint` errors before `EightInvEight()`.
- Post-review cleanup: party-specific proof contexts now append fixed-width uint64 party indexes so party 0 does not collapse to the bare SSID, and signing default SSID nonces are derived from full message bytes when `fullBytesLen` is provided.

## Already Covered Or Superseded

- `c84c096` / PR `#323`, modproof checker: Threshold's Paillier proof implementation already had the key Jacobi/non-prime validation from its GHSA-h24c-6p6p-m3vx remediation. Threshold's stronger `ModProof` coverage for both Paillier `N` and `NTilde` was kept.
- `e0e4299`, EdDSA keygen error aggregation: current Threshold code already had the corrected behavior.
- `0629cff`, `773b6af`, `b7b73a0`, `27922e0`, `4c83ace`, `c8136c9`, `8a87b22`, `f67a429`, `002397d`, `28d0622`, `bddf60d`: style, comment, logging, gofmt, minor optimization, or merge-only changes with no security behavior to port.

## Skipped

- `faf1884`, `c23246e`: module path bumps to `/v2` and `/v3`; skipped to preserve Threshold compatibility.
- `fbb0ef7`: changes `SignatureData` channels to pointers; skipped as public API churn not required for the hardening.
- `b8d526d`, `8abf1d5`, `6c233c6`, `87f7e12`: dependency and random-source API churn; skipped except where existing Threshold APIs already supported the needed behavior.
- `7113b68`, `d0325a1`, `dca2ac4`: repository metadata, CI, or security-report housekeeping.
- `3709c25`, `7a10240`, `0735081`, `3f677ff` / PR `#328`: broad optional constant-time framework. Not ported in this pass because it adds a new dependency, broad Paillier/MtA rewrites, and is default-disabled upstream. Treat as a separate follow-up security project with benchmarking and side-channel review.
- Merge-only commits `b15a0cf`, `c76a1a5`, `b79b349`, `d6e2aa9`, `ba5b734`: no direct changes to port beyond their constituent commits above.

## Semantic Differences From BNB

- Threshold's Paillier/NTilde `ModProof` and `FactorProof` remediation was retained. No BNB no-proof escape hatches were introduced.
- Session parameters were added as variadic arguments to preserve existing public call sites. This is API source-compatible for callers, but not wire-compatible for proof transcripts.
- Keygen and resharing SSIDs are locally derived and use `Parameters.SessionNonce()` when set. This avoids protobuf/module churn, but callers must provide a unique agreed nonce for keygen/resharing sessions that need cross-session replay resistance.
- ECDSA resharing SSID binding was adapted without adding BNB's newer wire-level SSID message fields.
- `common.RejectionSample` keeps BNB's function name for porting clarity, but this implementation is modular reduction rather than a looping rejection sampler.
- Constant-time operations are not included and remain a residual follow-up.

## Tests

- `go test ./crypto/... ./ecdsa/keygen ./ecdsa/signing ./eddsa/signing` passed.
- `go test ./eddsa/keygen ./eddsa/resharing` passed after updating EdDSA VSS threshold tests and resharing nil guard.
- `go test ./ecdsa/resharing` passed after the analogous resharing guard.
- `go test ./common ./crypto/paillier ./crypto/mta ./ecdsa/keygen ./ecdsa/resharing ./ecdsa/signing ./eddsa/keygen ./eddsa/signing ./eddsa/resharing` passed after review fixes.
- `go test ./...` passed.
- `go vet ./...` passed.

Added or updated focused tests cover:

- DLN, Schnorr, Paillier mod proof, factor proof, and MtA range proof session mismatch/replay failures.
- Non-invertible malformed factor-proof bases returning errors instead of panicking.
- MtA range-proof malformed ciphertext and proof-value boundary failures.
- ProofBobWC malformed lower-bound, zero-value, and curve-mismatch failures.
- ProofBob and ProofBobWC session mismatch/replay failures.
- VSS `threshold+1` verification/reconstruction behavior.
- Non-canonical EC coordinate rejection.
- ECDSA and EdDSA leading-zero message signing.

## Residual Risks

- Applications must call `SetSessionNonce` for keygen/resharing if they need unique SSIDs across otherwise identical party sets.
- The optional constant-time upstream work is not integrated.
- Resharing SSID binding is adapted locally rather than wire-compatible with BNB's latest protocol messages.
