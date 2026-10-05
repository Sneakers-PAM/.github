# Contributing to Sneakers-PAM

Thanks for helping. Every Sneakers-PAM repository follows this workflow.

## Workflow

1. Open an issue from a template (blank issues are disabled). For multi-step work, use a
   parent issue with ordered sub-issues, and put it on the active milestone.
2. Branch from `main` as `<type>/<issue#>-<slug>` (for example `feat/12-add-listener`).
3. Commit using Conventional Commits (`type(scope): description`). No attribution
   trailers, and no emoji in source or commit messages (emoji are fine in Markdown).
4. Open a PR with a Conventional Commit title. Fill in the PR template and reference the
   issue: `Closes #N` when the PR fully resolves it, `Refs #N` when it only does part.
   Add a closing summary before merge.
5. PRs squash-merge once CI is green.

Keep one concern per PR, even small ones. `main` is the only long-lived branch.

## Developer Certificate of Origin (DCO)

Every commit must be signed off:

```
git commit -s -m "type(scope): description"
```

This adds a `Signed-off-by` trailer certifying that you wrote the change, or otherwise
have the right to submit it, under the terms of the
[Developer Certificate of Origin](https://developercertificate.org/). CI checks every
commit in a PR, and a PR with any unsigned commit will not be merged. There is no CLA.

## Licence

Sneakers-PAM is licensed under [Apache-2.0](../LICENSE). By contributing you agree that your
contribution is licensed under the same terms. Source files carry an SPDX licence header.

## Local setup

Install the governance hooks once per clone, where the repository provides them. They
enforce Conventional Commits and the DCO sign-off before you push; CI enforces the same.

## Conduct

Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).
