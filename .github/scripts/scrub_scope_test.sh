#!/usr/bin/env bash
# Self-test for the scan scope of .github/workflows/scrub.yml. It runs that
# workflow's own step scripts (the range, gitleaks, identifier and DCO steps),
# read from the workflow, against throwaway local repos. Needs gitleaks at the
# version the workflow pins, and python3 with PyYAML.
#
# The test key and the test address are built at run time, so no file in this
# repo holds anything the scanners would match.
#
# Run from anywhere:
#   bash .github/scripts/scrub_scope_test.sh
set -euo pipefail

scripts_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tools="$(cd "$scripts_dir/../.." && pwd)"
workflows="$tools/.github/workflows"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail=0
expect_exit() {
  if [[ "$2" == "$3" ]]; then echo "ok   $1"; else echo "FAIL $1 (want $2, got $3)"; fail=1; fi
}
expect_contains() {
  if grep -qF -- "$2" "$3"; then echo "ok   $1"; else echo "FAIL $1 (missing: $2)"; fail=1; fi
}
expect_lacks() {
  if grep -qF -- "$2" "$3"; then echo "FAIL $1 (found: $2)"; fail=1; else echo "ok   $1"; fi
}

read_yaml() {
  python3 - "$@" <<'PY'
import sys, yaml
wf = yaml.safe_load(open(sys.argv[1]))
if sys.argv[2] == "step":
    print(next(s["run"] for s in wf["jobs"]["scrub"]["steps"] if s.get("name") == sys.argv[3]), end="")
else:
    print(wf["env"][sys.argv[2]])
PY
}

read_yaml "$workflows/scrub.yml" step "Resolve the scan range" >"$work/range.sh"
read_yaml "$workflows/scrub.yml" step "gitleaks" >"$work/gitleaks.sh"
read_yaml "$workflows/scrub.yml" step "Generic identifiers" >"$work/identifiers.sh"
read_yaml "$workflows/scrub.yml" step "DCO sign-off" >"$work/dco.sh"

want_version="$(read_yaml "$workflows/scrub.yml" GITLEAKS_VERSION)"
got_version="$(gitleaks version)"
expect_exit "gitleaks on PATH is the pinned $want_version" "$want_version" "$got_version"
for k in GITLEAKS_VERSION GITLEAKS_SHA256; do
  expect_exit "checks.yml pins the same $k" "$(read_yaml "$workflows/scrub.yml" "$k")" "$(read_yaml "$workflows/checks.yml" "$k")"
done

# range <log> VAR=value...: runs the range step with the event variables
# given (the rest empty) and prints its exit code. The resolved range is left
# in $work/out.
range() {
  local log="$1" rc=0
  shift
  : >"$work/out"
  (cd "$work/repo" && env EVENT= FULL=false REF= DEFAULT_BRANCH=main EVENT_SHA= PR_BASE= PR_HEAD= \
    PUSH_BEFORE= PUSH_AFTER= MG_BASE= MG_HEAD= "$@" GITHUB_OUTPUT="$work/out" \
    bash -eo pipefail "$work/range.sh") >"$log" 2>&1 || rc=$?
  echo "$rc"
}
resolved() { sed -n "s/^$1=//p" "$work/out"; }

# step <script> <log>: runs a scan step over the range left by the last
# range call and prints its exit code.
step() {
  local rc=0
  (cd "$work/repo" && env BASE="$(resolved base)" HEAD_SHA="$(resolved head)" TOOLS="$tools" \
    ALLOWED_DOMAINS= PR_TITLE= PR_BODY= bash -eo pipefail "$work/$1.sh") >"$2" 2>&1 || rc=$?
  echo "$rc"
}

commit() {
  git -C "$work/repo" add -A
  git -C "$work/repo" commit -q -s -m "$1"
  git -C "$work/repo" rev-parse HEAD
}

# A fake AWS-style access key and a private address, for this test only.
fake_key="AKIA$(python3 -c 'import secrets; print("".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(16)))')"
private_ip="$(printf '%s.%s.%s.%s' 10 20 30 40)"

# Commits use the ambient git identity: the repo is local-only scratch,
# deleted on exit and never pushed. The identifier step also reads authors,
# so its checks below look for the fixture's files in its report rather than
# at its exit code.
git init -q -b main "$work/repo"
echo "# fixture" >"$work/repo/README.md"
root="$(commit "chore: root")"
printf 'aws_access_key_id = %s\n' "$fake_key" >"$work/repo/settings.ini"
commit "feat: add settings" >/dev/null
git -C "$work/repo" rm -q settings.ini
main_tip="$(commit "fix: drop settings")"

# A clean PR branch, and the test merge GitHub checks out for it
# (refs/pull/<n>/merge): first parent the base, second parent the PR head.
git -C "$work/repo" switch -q -c feature "$main_tip"
echo "clean" >"$work/repo/feature.txt"
pr_head="$(commit "docs: clean change")"
git -C "$work/repo" switch -q main
echo "main moved" >"$work/repo/main.txt"
base_tip="$(commit "docs: main moves on")"
git -C "$work/repo" merge -q --no-ff --no-edit feature
merge="$(git -C "$work/repo" rev-parse HEAD)"
git -C "$work/repo" reset -q --hard "$base_tip"

# Branches the PR doesn't contain: one with a key, one with an address, one
# with an unsigned commit.
git -C "$work/repo" switch -q -c bad-key "$root"
printf 'aws_access_key_id = %s\n' "$fake_key" >"$work/repo/other.ini"
commit "feat: a key on another branch" >/dev/null
git -C "$work/repo" switch -q -c bad-ip "$root"
printf 'host = %s\n' "$private_ip" >"$work/repo/hosts.txt"
commit "feat: an address on another branch" >/dev/null
git -C "$work/repo" switch -q -c unsigned "$root"
echo "x" >"$work/repo/x.txt"
git -C "$work/repo" add -A
git -C "$work/repo" commit -q -m "chore: no sign-off"
git -C "$work/repo" switch -q main

# --- pull_request ---------------------------------------------------------
rc="$(range "$work/pr.log" EVENT=pull_request PR_BASE="$base_tip" PR_HEAD="$pr_head" EVENT_SHA="$merge")"
expect_exit "a PR resolves" 0 "$rc"
expect_exit "a PR scans from the test merge's first parent" "$base_tip" "$(resolved base)"
expect_exit "a PR scans up to the test merge, so the merge result is read" "$merge" "$(resolved head)"
expect_exit "gitleaks: a key on another branch doesn't fail a clean PR" 0 "$(step gitleaks "$work/pr-gl.log")"
step identifiers "$work/pr-id.log" >/dev/null
expect_contains "identifiers: a clean PR is read" "scrub identifiers:" "$work/pr-id.log"
expect_lacks "identifiers: an address on another branch isn't read" "hosts.txt" "$work/pr-id.log"
expect_exit "dco: an unsigned commit on another branch doesn't fail a clean PR" 0 "$(step dco "$work/pr-dco.log")"

# A test merge whose result adds a key and an address the PR's own commits
# don't have (as a conflict resolution can).
git -C "$work/repo" switch -q --detach "$base_tip"
git -C "$work/repo" merge -q --no-ff --no-commit feature >/dev/null 2>&1
printf 'aws_access_key_id = %s\n' "$fake_key" >"$work/repo/merged.ini"
printf 'host = %s\n' "$private_ip" >"$work/repo/merged.txt"
git -C "$work/repo" add -A
git -C "$work/repo" commit -q --no-edit
evil_merge="$(git -C "$work/repo" rev-parse HEAD)"
git -C "$work/repo" switch -q main
range "$work/evil.log" EVENT=pull_request PR_BASE="$base_tip" PR_HEAD="$pr_head" EVENT_SHA="$evil_merge" >/dev/null
expect_exit "gitleaks: a key added in the merge result fails" 1 "$(step gitleaks "$work/evil-gl.log")"
if grep -qF -- "$fake_key" "$work/evil-gl.log"; then
  echo "FAIL the finding is redacted"; fail=1
else
  echo "ok   the finding is redacted"
fi
expect_exit "identifiers: an address added in the merge result fails" 1 "$(step identifiers "$work/evil-id.log")"
expect_contains "it names the merged file" "merged.txt:1 (net diff): private-ip" "$work/evil-id.log"

# pull_request_target checks out the base, not a merge: fall back to the PR range.
rc="$(range "$work/prt.log" EVENT=pull_request_target PR_BASE="$base_tip" PR_HEAD="$pr_head" EVENT_SHA="$base_tip")"
expect_exit "with no test merge, a PR resolves" 0 "$rc"
expect_exit "with no test merge, a PR scans from its base" "$base_tip" "$(resolved base)"
expect_exit "with no test merge, a PR scans up to its head" "$pr_head" "$(resolved head)"

rc="$(range "$work/norange.log" EVENT=pull_request EVENT_SHA="$merge")"
expect_exit "a PR with no range is an error, not a full-history scan" 2 "$rc"
expect_contains "it says why" "No commit range" "$work/norange.log"

rc="$(range "$work/full.log" EVENT=pull_request FULL=true PR_BASE="$base_tip" PR_HEAD="$pr_head" EVENT_SHA="$merge")"
expect_exit "full-history resolves" 0 "$rc"
expect_exit "full-history drops the base" "" "$(resolved base)"
expect_exit "full-history still reads only the head's own history" "$merge" "$(resolved head)"
expect_exit "gitleaks: full-history finds the removed key" 1 "$(step gitleaks "$work/full-gl.log")"

# --- merge_group ----------------------------------------------------------
rc="$(range "$work/mg.log" EVENT=merge_group MG_BASE="$base_tip" MG_HEAD="$merge" EVENT_SHA="$merge")"
expect_exit "a merge group resolves" 0 "$rc"
expect_exit "a merge group scans from its base" "$base_tip" "$(resolved base)"
expect_exit "a merge group scans up to its head" "$merge" "$(resolved head)"
rc="$(range "$work/mg-none.log" EVENT=merge_group EVENT_SHA="$merge")"
expect_exit "a merge group with no range is an error" 2 "$rc"

# --- push -----------------------------------------------------------------
rc="$(range "$work/main.log" EVENT=push REF=refs/heads/main PUSH_BEFORE="$main_tip" PUSH_AFTER="$base_tip" EVENT_SHA="$base_tip")"
expect_exit "a push to main resolves" 0 "$rc"
expect_exit "a push to main reads the full history" "" "$(resolved base)"
expect_exit "a push to main reads the pushed head" "$base_tip" "$(resolved head)"
expect_contains "it says so" "Scanning the full history of $base_tip" "$work/main.log"
expect_exit "gitleaks: a push to main finds a key removed long ago" 1 "$(step gitleaks "$work/main-gl.log")"

rc="$(range "$work/branch.log" EVENT=push REF=refs/heads/feature PUSH_BEFORE="$main_tip" PUSH_AFTER="$pr_head" EVENT_SHA="$pr_head")"
expect_exit "a push to another branch resolves" 0 "$rc"
expect_exit "a push to another branch scans from before" "$main_tip" "$(resolved base)"
expect_exit "a push to another branch scans up to after" "$pr_head" "$(resolved head)"

rc="$(range "$work/new.log" EVENT=push REF=refs/heads/feature PUSH_BEFORE=0000000000000000000000000000000000000000 PUSH_AFTER="$pr_head" EVENT_SHA="$pr_head")"
expect_exit "a new branch's first push reads its full history" "" "$(resolved base)"

# --- anything else ----------------------------------------------------------
rc="$(range "$work/schedule.log" EVENT=schedule EVENT_SHA="$base_tip")"
expect_exit "a scheduled run resolves" 0 "$rc"
expect_exit "a scheduled run reads the full history" "" "$(resolved base)"
expect_exit "a scheduled run reads the checked-out commit" "$base_tip" "$(resolved head)"

echo
if [[ "$fail" == 0 ]]; then
  echo "scrub_scope_test.sh: all checks passed"
else
  echo "scrub_scope_test.sh: FAILURES ABOVE"
fi
exit "$fail"
