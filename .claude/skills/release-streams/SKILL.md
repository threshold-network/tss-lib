---
name: release-streams
description: How changes in tss-lib reach a release. Use before opening or retargeting a PR, choosing a PR base branch, filling in the PR template's "Breaking change", "Release stream" or "Security" fields, merging a PR into a release line, closing a duplicate fix, writing a CHANGELOG entry, choosing a caller selection for a breaking change, or updating a stream parent PR (label `release-stream-parent`).
---

# Release streams

Rules: `docs/release-policy.md`. Process: `docs/release-streams.md`. Build, tag and publish:
`docs/release-process.md`. If this skill disagrees with those files, they win: fix this file in
the same PR.

## 1. Classify the change

Exactly one class per PR (policy table "Compatibility classes"):

| Class | Test | Template "Breaking change" |
|---|---|---|
| R | local behavior only: validation, errors, performance, constant-time arithmetic with identical results | No |
| P | changes which peer messages or proofs a party accepts; needs a named condition and evidence that honest messages from the previous release still verify | No (without that evidence, treat as A) |
| A | a ceremony parameter every party must agree on, for example the session nonce | Yes, coordinated activation |
| X | protocol messages, proof transcripts, Fiat-Shamir challenges, session binding, key-share or pre-parameter serialization, or a public Go API break for keep-core | Yes, cutover |
| T | CI, docs, tests | Not applicable |

- A dependency bump that changes a value a peer computes and must agree on is A or X. One that only changes local behavior is R.
- Two classes in one PR: split it.

## 2. Pick the stream and the base branch

1. Read "Current cycle" in `docs/release-policy.md`.
2. List the streams: `gh pr list --label release-stream-parent`. Each parent's head branch is the stream's line.
3. R and evidenced-P work goes to the next library release (`dev` into `master`); A and X go into the breaking release, off by default; T goes to the branch that owns the file.
4. Do not open a new stream. A new stream needs both release owners.
5. Check for an existing PR with the same fix (`gh pr list --search "<keywords>" --state all`). If one exists on the same line, extend it instead.

## 3. Fill in the PR

- Start the body from `.github/pull_request_template.md`. Tick exactly one "Breaking change" box and one "Security" box; the `required-answers` check enforces it.
- Breaking (A/X): name the caller selection that switches the change on (for example `tss.ProtocolModeSecurityV2`), keep it off by default, and add or point to a mixed-version test that shows old and new parties still interoperate until keep-core selects it.
- Add the `CHANGELOG.md` line under `[Unreleased]` with the PR number. Security lines describe behavior only.
- Never put embargoed detail or finding text in a PR, commit message, test name or CI log.

## 4. After a child PR merges, closes or opens

1. Fetch live state: `gh pr view <parent> --json body`, and the stream's merged and open PRs.
2. Update the parent body's `## Stream tracking` section: "Merged into this stream" row (PR, branch, date), closed-without-merge note, "Open PRs, in merge order", breaking-change table if it changed.
3. Before saving, check the body locally against the two `required-answers` patterns (exactly one match each). A conflicting PR runs no checks.
4. Save with `gh pr edit <parent> --body-file <file>`.

## 5. Merging

- Merge only after a non-author approval and green CI.
- Stacks: bottom-up; retarget children before their base merges; never delete a branch that is the base of an open PR.
- Update branches with merge commits; never force-push a release line. This repository merges with merge commits only.
- Close a duplicate only after porting what it has that the canonical PR lacks; comment with the canonical PR number.

## 6. Release steps that need a human go

Stop and hand over to a release owner for: renaming the `[Unreleased]` heading to the version, the
release tag, and the keep-core pin change. An agent may prepare the changelog PR and check that
every breaking change on the branch is off by default with a passing mixed-version test, then must
stop before the tag. Steps: `docs/release-process.md`.
