# Contributing to Sneakers-PAM

This repository follows the Sneakers-PAM standard workflow.

## Workflow

1. Open an issue from a template (free-form issues are disabled). For multi-step work,
   use a parent issue with ordered sub-issues, and put it on the active milestone.
2. Branch from `main` as `<type>/<issue#>-<slug>` (for example `feat/12-add-listener`).
3. Commit using Conventional Commits (`type(scope): description`). No attribution
   trailers, no emoji in source or commit messages (emoji are fine in Markdown).
4. Open a PR with a Conventional Commit title. Fill the PR template, reference the issue
   (`Closes #N`), and add a closing summary before merge.
5. PRs merge by squash, once CI is green.

Keep one concern per PR, even small ones.

## Developer Certificate of Origin (DCO)

Every commit must be signed off:

```
git commit -s -m "type(scope): description"
```

This adds a `Signed-off-by` trailer certifying that you wrote the change, or otherwise
have the right to submit it, under the terms of the
[Developer Certificate of Origin](https://developercertificate.org/). A PR with any
unsigned commit will not be merged.

## Local setup

Install the governance hooks once per clone, where the repository provides them. They
enforce Conventional Commits and the DCO sign-off before you push; CI enforces the same.
