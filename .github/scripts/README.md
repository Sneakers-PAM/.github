# Scrub 1 tools

`scrub.py` holds the generic identifier and DCO checks behind the org's reusable workflow,
`.github/workflows/scrub.yml`. It reads no term list: every pattern is generic.

This repo's own `.github/workflows/checks.yml` runs actionlint and every self-test here
(`scrub_test.py` and each `*_test.sh`) on each pull request, and runs `scrub.yml` over this repo's
commits with the `scrub.py` from the commit under test. To run the same checks locally, with
actionlint and buf on the `PATH`:

```bash
actionlint
python3 .github/scripts/scrub_test.py
for t in .github/scripts/*_test.sh; do bash "$t"; done
```

## Run it locally

```bash
python3 .github/scripts/scrub.py identifiers --base origin/main --head HEAD
python3 .github/scripts/scrub.py dco --base origin/main --head HEAD
python3 .github/scripts/scrub_test.py
```

Leave out `--base` to scan the whole history.

## What it checks

- **identifiers** flags `private-ip`, `email`, `home-path` and `fqdn` matches. It reads:
  - each non-merge commit's added lines, plus the net `base...head` diff (which covers merges);
  - the touched paths;
  - every commit message, author and committer, merges included;
  - the PR title and body.

  Files are listed with NUL-separated plumbing and read by blob id, so an odd path (a tab, quote,
  backslash or newline in the name) can't hide its content; a blob that can't be read fails the
  run (exit 2). Diffs always run with `--text`, so `.gitattributes` can't hide a file. A file whose content has
  a NUL byte is treated as binary, and its ASCII, UTF-16LE and UTF-16BE string runs are scanned.
- **dco** requires `Signed-off-by: Name <email>` on every non-merge commit.

## What range the workflow reads

`scrub.yml` gives gitleaks, `identifiers` and `dco` the same range:

- **pull_request:** the PR's own commits plus the merge result, `<first parent>..<test merge>` of the
  `refs/pull/<n>/merge` commit GitHub checks out (or `base..head` when the run has no test merge).
  A commit on another branch never fails a PR. A PR with no resolvable range fails (exit 2) instead
  of falling back to a full-history scan.
- **merge_group:** the group's `base..head`.
- **push to the default branch, schedule, manual run:** the full history of the checked-out commit.
  That's its ancestors only; nothing ever reads `--all`.
- **push to any other branch:** `before..after` (the full history on a new branch's first push).

`scrub_scope_test.sh` runs the workflow's own step scripts against throwaway repos to pin this down.

A caller that also runs `gitleaks detect --source .` (or `gitleaks git .`) itself, with no
`--log-opts`, after a `fetch-depth: 0` checkout reads `git log --all`: every fetched branch. One bad
branch then fails every open PR. The scrub already runs gitleaks over the right range, so such a step
can simply be removed.

## Allowing a match

- `scrub:allow=<class>[,<class>]` on a line of a file allows those classes on that line only, for
  example `# scrub:allow=private-ip`. A bare `scrub:allow` allows nothing.
- Markers are never honoured in commit messages, author lines, paths or PR text.
- Files under the top-level `docs/examples/` may hold private addresses; every other check still
  applies there.
- The RFC 5737 and RFC 3849 documentation ranges, emails at example.com, example.org and
  example.net (and their subdomains), host names under any example.* domain, GitHub noreply
  addresses, the built-in public domains and the project's own domain, `sneakers-pam.com` (as a host
  name, subdomains included; emails at it are still flagged), always pass. Callers add other domains
  with the workflow's `allowed-domains` input. Placeholder hosts in code and tests stay on
  `example.org`.

Every honoured allow is reported as a warning, both in the log and in the job summary.

## Limits

Compressed content isn't unpacked: zip, docx/xlsx, jar, gz and tar.gz, PNG zTXt/iTXt chunks, PDF
streams and the like. Scrub 2, the independent reviewer pass, reviews those files.
Scrub 1 is a pattern check; it doesn't catch names, short host names, ticket keys or codenames.
Scrub 2 does that too.

# DCO

`.github/workflows/dco.yml` runs `dco-check.sh <base> <head>`, which fails when any non-merge commit
in `base..head` has no `Signed-off-by: Name <email>` trailer. Merge commits are skipped. `scrub.yml`
already checks sign-offs, so a repo that calls the scrub doesn't need it. It's for a repo that
doesn't, called on pull requests and merge groups:

```yaml
  dco:
    if: github.event_name != 'push' && github.event.pull_request.draft != true
    uses: Sneakers-PAM/.github/.github/workflows/dco.yml@main
```

```bash
bash .github/scripts/dco-check.sh origin/main HEAD
bash .github/scripts/dco-check_test.sh
```

# Go build and test

`.github/workflows/go.yml` is the shared form of the Build & Test job each Go service carries in its
own `job-go-lang-ci.yaml`: generated code current, buf lint and breaking (only when the repo has a
`buf.yaml`), gofmt, go mod tidy, build, vet and `go test -race -count=1 -cover`. buf is pinned and
checked against its SHA-256, the protoc plugins (protoc-gen-go v1.36.11 and protoc-gen-go-grpc v1.6.2,
the service repos' pins) come through the Go checksum database, and the actions are pinned by commit.

```yaml
  go:
    if: github.event_name == 'pull_request' && github.event.pull_request.draft != true
    permissions:
      contents: read
    uses: Sneakers-PAM/.github/.github/workflows/go.yml@main
    with:
      setup-script: scripts/ci-services.sh
```

- `setup-script` is the repo's own script. It starts what the tests need (Postgres, Kratos, an LDAP
  server) with `docker run` and appends settings such as a test DSN to `$GITHUB_ENV`. Leave it out
  when the tests need no containers.
- The status check becomes `go / Build & Test`, so the repo's ruleset swaps the required
  `🧪 Build & Test` for it in the same change.
- Repo-specific steps (the workloadauth copy check, image builds, cross-builds, chart checks) stay
  in the repo's own workflow.

Which repos could switch (none is moved yet):

| Repo | Fit |
|---|---|
| sneakers-gateway, sneakers-notify, sneakers-sshbroker | direct: no test containers |
| sneakers-mcp | direct; its cross-build step stays in its own workflow |
| sneakers-audit, sneakers-vault | with a `setup-script` that starts Postgres (vault also keeps its image job) |
| sneakers-connector, sneakers-identity | with a `setup-script` that starts the LDAP server or Kratos as well |
| sneakers-release | stays on its own workflow (image and chart checks) |

# Quality

`.github/workflows/quality.yml` runs the heavier Go tools on a PR as **advisory** checks: their
findings show on the PR while it's under review, and they never fail it or block its merge. The
service repos already require gosec and govulncheck through their own workflows; this is an extra a
repo opts into with one job in its `checks.yml`:

```yaml
  quality:
    if: github.event_name == 'pull_request' && github.event.pull_request.draft != true
    permissions:
      contents: read
    uses: Sneakers-PAM/.github/.github/workflows/quality.yml@main
```

It takes two optional inputs: `timeout-minutes` (each job's timeout, default 15) and `tools-ref`
(the ref of this repo to take `quality-report.sh` from, default `main`). Each tool runs in its own
job, side by side:

| Check | Tool |
|---|---|
| `quality / Lint (advisory)` | golangci-lint, with the repo's `.golangci.yml` when there is one |
| `quality / SAST (advisory)` | gosec, generated files skipped |
| `quality / Vulnerabilities (advisory)` | govulncheck: known vulnerabilities the code reaches in its dependencies |
| `quality / Modernize (advisory)` | the Go `modernize` analyzer, test files included |

The tool step continues on error, so findings never fail the job. `quality-report.sh` turns the
tool's output into warning annotations (the first 50) and a section of the job summary with the
full output and the count. Each job continues on error too, so even a failed install leaves the
caller's run green; the summary then says the tool didn't run. Never add these checks to a
ruleset's required status checks.

golangci-lint and gosec are release binaries checked against their SHA-256; govulncheck and
modernize come through `go install` and the Go checksum database.

```bash
bash .github/scripts/quality-report_test.sh
```

feeds canned tool output to `quality-report.sh` and checks the annotations and summary it writes.
It needs none of the tools.

# Proto sync

`proto-sync.sh` holds the checks behind `.github/workflows/proto-sync.yml`. A service never imports
another service's Go module: it pins each callee's commit in `proto-refs.env`
(`SNEAKERS_<NAME>_REF=<commit>`, for `Sneakers-PAM/sneakers-<name>`), and its
`scripts/proto-generate.sh` fetches the callee's `proto/` at that commit and generates the client
stubs into its own `gen/`.

## Run it locally

From the root of the calling repo, with `buf` on the `PATH`:

```bash
bash <this repo>/.github/scripts/pin-check.sh
bash <this repo>/.github/scripts/gomod-guard.sh
bash <this repo>/.github/scripts/proto-sync.sh check
bash <this repo>/.github/scripts/proto-sync.sh refresh
```

`pin-check.sh` needs `gh`, signed in or with `GH_TOKEN` set. The self-tests run from anywhere:

```bash
bash .github/scripts/pin-check_test.sh
PIN_CHECK_LIVE=1 bash .github/scripts/pin-check_test.sh   # also against real Sneakers-PAM commits
bash .github/scripts/gomod-guard_test.sh
bash .github/scripts/proto-sync_test.sh
```

## What it checks

The `check` job (on a PR) runs two guards first, in every calling repo, with or without pins:

- **pin-check.sh** fails when a `SNEAKERS_<NAME>_REF` pin isn't reachable from the owner's `main`,
  asking GitHub's compare API (`repos/Sneakers-PAM/<repo>/compare/<pin>...main`). Status `ahead`
  or `identical` passes; `behind`, `diverged` and a 404 (no such repo or commit) fail. A
  squash-merged PR head still resolves on codeload until GitHub drops it, so a pin off `main`
  works for a while and then breaks with no warning. Pin the owner's merge commit instead.
- **gomod-guard.sh** fails when any `go.mod` below the root (hidden directories and `vendor/`
  aside) has a `replace` directive, or requires a `github.com/Bugs5382/*` or
  `github.com/Sneakers-PAM/*` module at a pseudo-version (`v0.0.0-<timestamp>-<commit>`,
  `vX.Y.Z-0.<timestamp>-<commit>` and the pre-release form). Only tagged releases are committed.

To build and test against a local checkout of a package, use a git-ignored `go.work` beside the
service's `go.mod` instead (`go work init . ../go-<pkg>`, or `use . ../go-<pkg>` in the file).
Every Go repo ignores `go.work` and `go.work.sum`. Local callee protos come from the
`SNEAKERS_<SVC>_PROTO_DIR` overrides of the service's `scripts/proto-generate.sh`, never from an
edited pin.

Then, for each pin:

- **check** (on a PR) fails when a pin isn't on the owner's `main`, or when `buf breaking` finds
  that the owner's `main` breaks the protos at the pin. It only warns when `main`'s `proto/` has
  moved past the pin without a break, so an owner's additive change doesn't turn every caller's
  open PRs red.
- **refresh** (on the schedule) points every stale pin at the owner's `main`: a pin is stale when
  it isn't on `main` (a squash merge leaves the PR head off it) or when `proto/` differs. The
  workflow then reruns `scripts/proto-generate.sh` and opens or updates one PR from
  `chore/proto-refs`. CI doesn't start on a PR the workflow token opens, so a maintainer closes and
  reopens it. The org setting "Allow GitHub Actions to create and approve pull requests" must be on.
