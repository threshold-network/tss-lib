# Release process: build and tag a release

[release-policy.md](release-policy.md) sets the rules and [release-streams.md](release-streams.md) the day-to-day process. This document is the step list to cut and tag a release.

A release owner performs the tag steps. An agent may prepare steps 1 and 2, and must stop before step 3.

## Preconditions

- Every PR of the stream has merged into the stream branch (`dev`), and CI on that branch is green.
- The parent PR (label `release-stream-parent`) lists the release and its breaking changes, and every breaking change is switched off by default.
- Every breaking change on the branch has its mixed-version test (`testdata/legacy_transcript`), and the test passes.

## 1. Move `[Unreleased]` to the version heading

`CHANGELOG.md` holds every change under `## [Unreleased]`. The release workflow reads a versioned heading, so rename the heading in a PR into `dev`:

```markdown
## [1.4.0] - 2026-10-15
```

Move the `[Unreleased]` link target at the bottom of the file as well, so the new version compares from the previous tag and `[Unreleased]` compares from the new tag:

```markdown
[Unreleased]: https://github.com/threshold-network/tss-lib/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/threshold-network/tss-lib/compare/2e712689...v1.4.0
```

Then add a fresh empty `## [Unreleased]` section at the top of the change list.

## 2. Merge the stream branch into `master`

Merge the stream branch into `master` through the parent PR. Use a merge commit (this repository does not squash or rebase). The merge commit is the release commit.

## 3. Tag the release commit (release owner)

Tags live on `master` and never move. Tag the merge commit from step 2:

```bash
git checkout master
git pull --ff-only origin master
git tag v1.4.0 <merge-commit-sha>
git push origin v1.4.0
```

The version is a plain `v1.x.y`: no pre-release suffix and no `v2` or later (the module path has no `/vN`). See the policy for the reason.

## 4. The workflow publishes the release

A pushed `v*` tag starts `.github/workflows/release.yml`. It extracts the `## [<version>]` section from `CHANGELOG.md` and creates the GitHub Release with that text as the body. It fails the run if the section is missing, so step 1 must be done first. The run does not build artifacts: the release is the tagged source and the notes.

## 5. Check the release

Open the Releases page and confirm the new release shows the version and the changelog section. If the workflow failed, the tag stays in place (a tag is never deleted); fix `CHANGELOG.md` and re-run the workflow, or, if the notes are still wrong, cut the next patch version.

## 6. Repin the consumer

keep-core pins this library by version in `go.mod`. After the release, update the pin to the new tag and open the pin PR there. That PR carries the cutover decision for the fleet.

## Rollback

A tag is never moved or deleted (a ruleset enforces this). To undo a bad release, tag the next patch version (`v1.4.1`) with the fix. To take a bad release out of the fleet, repin keep-core to the previous version.
