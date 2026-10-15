<!-- pr-template: v1 -->

## Summary

<!-- What changes and why, in two or three sentences. -->

## Linked issues

<!-- "Closes #N" or "Refs #N". For a security fix, also give the finding ID. -->

## Breaking change

<!-- Required: tick exactly one. A CI check (required-answers) rejects the PR otherwise. -->

- [ ] **No** - existing consumers and peers on the previous version still interoperate.
- [ ] **Yes, coordinated activation** - all parties of a ceremony must switch together at an agreed point (for example a new mandatory session parameter).
- [ ] **Yes, cutover** - protocol messages, proof transcripts or Fiat-Shamir challenges, session binding, or key-share or pre-parameter serialization change, so old and new parties cannot complete one ceremony. Public Go API breaks for the keep-core consumer also count.
- [ ] **Not applicable** - CI, docs, tests or tooling only; no runtime effect on ceremonies.

<!--
If "Yes": name the message, transcript, challenge, serialization or API surface that changes, the caller selection that switches the change on, and why the change cannot be made backward compatible.
Breaking changes ship off by default: the library keeps the previous behavior unless a caller selects the new one. keep-core switches the change on for the fleet at one agreed point. The rules are in docs/release-policy.md.
-->

## Release stream

<!-- Tick the stream this change ships in. The rules are in docs/release-policy.md. -->

- [ ] Next library release (`dev` into `master`)
- [ ] Embargoed security fix (coordinate through private vulnerability reporting)
- [ ] CI, docs or tests only

## Security

<!-- Required: tick exactly one. A CI check (required-answers) rejects the PR otherwise. -->

- [ ] **Not security-related**
- [ ] **Security fix** - severity: <!-- critical / high / medium / low -->, finding ID: <!-- ID -->, embargoed until: <!-- date or condition -->

## Testing

<!-- Commands you ran and their results; which new test fails without the change. -->

## Rollback

<!-- How to undo this: re-pin the previous library version in keep-core, revert the commit, or both. "Not applicable" for CI or docs. -->

## Checklist

- [ ] No secrets, private keys or private endpoints in the code, logs or this description.
- [ ] Title follows Conventional Commits (`type(scope): description`).
- [ ] Docs and changelog updated where behavior changes.
