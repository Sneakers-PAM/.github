#!/usr/bin/env bash
# Self-test for gomod-guard.sh against go.mod fixtures. Touches no network.
#
# Run from anywhere:
#   bash .github/scripts/gomod-guard_test.sh
set -euo pipefail

scripts_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
guard="$scripts_dir/gomod-guard.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail=0
ok() { echo "ok: $1"; }
bad() {
  echo "FAIL: $1"
  fail=1
}
expect_exit() { # expect_exit <desc> <want> <got>
  if [[ "$2" == "$3" ]]; then ok "$1 (exit $3)"; else bad "$1 (want exit $2, got $3)"; fi
}
expect_contains() { # expect_contains <desc> <needle> <file>
  if grep -qF -- "$2" "$3"; then
    ok "$1"
  else
    bad "$1 (missing: $2)"
    sed 's/^/    /' "$3" >&2
  fi
}
expect_not_contains() { # expect_not_contains <desc> <needle> <file>
  if grep -qF -- "$2" "$3"; then
    bad "$1 (should not contain: $2)"
    sed 's/^/    /' "$3" >&2
  else
    ok "$1"
  fi
}

# run <dir> <log>: runs gomod-guard.sh in <dir> and echoes its exit code.
run() {
  local rc=0
  (cd "$1" && bash "$guard") >"$2" 2>&1 || rc=$?
  sed 's/^/    | /' "$2" >&2
  echo "$rc"
}

# A clean go.mod: tagged owner packages, and third-party pseudo-versions,
# which the guard leaves alone.
mkdir -p "$work/clean"
cat >"$work/clean/go.mod" <<'GOMOD'
module github.com/Sneakers-PAM/sneakers-fixture

go 1.26.6

require github.com/Bugs5382/go-apperr v1.1.0

require (
	github.com/Bugs5382/go-log v1.3.0
	github.com/Bugs5382/go-otel/v2 v2.0.0-rc.1
	github.com/Sneakers-PAM/sneakers-release v0.1.0 // indirect
	golang.org/x/exp v0.0.0-20260101000000-0123456789ab // indirect
)
GOMOD
rc="$(run "$work/clean" "$work/clean.log")"
expect_exit "tagged owner packages pass" 0 "$rc"
expect_contains "a clean go.mod says so" "go.mod: no replace directives, owner packages at tagged releases" "$work/clean.log"

# Every way an untagged owner package or a replace gets in.
mkdir -p "$work/dirty"
cat >"$work/dirty/go.mod" <<'GOMOD'
module github.com/Sneakers-PAM/sneakers-fixture

go 1.26.6

require github.com/Bugs5382/go-apperr v0.0.0-20260930120000-0123456789ab

require (
	github.com/Bugs5382/go-log v1.3.1-0.20260930120000-abcdefabcdef
	github.com/Bugs5382/go-otel v1.4.0-rc.1.0.20260930120000-abcdefabcdef // indirect
	github.com/Sneakers-PAM/sneakers-release v0.0.0-20261001000000-fedcbafedcba
	github.com/Bugs5382/go-redis v1.2.0
	golang.org/x/exp v0.0.0-20260101000000-0123456789ab
)

replace github.com/Bugs5382/go-redis => ../go-redis

replace (
	github.com/Bugs5382/go-postgres v1.2.2 => github.com/someone/go-postgres v1.2.3
)
GOMOD
rc="$(run "$work/dirty" "$work/dirty.log")"
expect_exit "an untagged go.mod fails" 1 "$rc"
expect_contains "a v0.0.0 pseudo-version fails" \
  "::error file=go.mod,line=5::github.com/Bugs5382/go-apperr is at a pseudo-version (v0.0.0-20260930120000-0123456789ab)" "$work/dirty.log"
expect_contains "a -0.<timestamp> pseudo-version fails" \
  "::error file=go.mod,line=8::github.com/Bugs5382/go-log is at a pseudo-version (v1.3.1-0.20260930120000-abcdefabcdef)" "$work/dirty.log"
expect_contains "a pre-release pseudo-version fails, indirect too" \
  "::error file=go.mod,line=9::github.com/Bugs5382/go-otel is at a pseudo-version (v1.4.0-rc.1.0.20260930120000-abcdefabcdef)" "$work/dirty.log"
expect_contains "a Sneakers-PAM pseudo-version fails" \
  "::error file=go.mod,line=10::github.com/Sneakers-PAM/sneakers-release is at a pseudo-version" "$work/dirty.log"
expect_not_contains "a tagged owner package isn't flagged" "github.com/Bugs5382/go-redis is at" "$work/dirty.log"
expect_not_contains "a third-party pseudo-version isn't flagged" "golang.org/x/exp" "$work/dirty.log"
expect_contains "a one-line replace fails" \
  "::error file=go.mod,line=15::replace directive: github.com/Bugs5382/go-redis => ../go-redis" "$work/dirty.log"
expect_contains "a replace in a block fails" \
  "::error file=go.mod,line=18::replace directive: github.com/Bugs5382/go-postgres v1.2.2 => github.com/someone/go-postgres v1.2.3" "$work/dirty.log"

# A nested module is checked too; hidden directories (fetched protos, the
# workflow's tools checkout) are not.
mkdir -p "$work/nested/tools" "$work/nested/.proto-sync-tools"
printf 'module github.com/Sneakers-PAM/sneakers-fixture\n\ngo 1.26.6\n' >"$work/nested/go.mod"
printf 'module github.com/Sneakers-PAM/sneakers-fixture/tools\n\ngo 1.26.6\n\nreplace example.com/a => ../a\n' >"$work/nested/tools/go.mod"
printf 'module example.com/hidden\n\ngo 1.26.6\n\nreplace example.com/b => ../b\n' >"$work/nested/.proto-sync-tools/go.mod"
rc="$(run "$work/nested" "$work/nested.log")"
expect_exit "a nested module with a replace fails" 1 "$rc"
expect_contains "the nested go.mod is named" "::error file=tools/go.mod,line=5::replace directive: example.com/a => ../a" "$work/nested.log"
expect_not_contains "hidden directories are skipped" "example.com/b" "$work/nested.log"

mkdir -p "$work/none"
rc="$(run "$work/none" "$work/none.log")"
expect_exit "no go.mod passes" 0 "$rc"

echo
if [[ "$fail" == 0 ]]; then
  echo "gomod-guard_test.sh: all checks passed"
else
  echo "gomod-guard_test.sh: FAILURES ABOVE"
fi
exit "$fail"
