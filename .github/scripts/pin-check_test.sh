#!/usr/bin/env bash
# Self-test for pin-check.sh. By default it touches no network: a fake gh on
# PATH answers the compare calls the way the GitHub API does. With
# PIN_CHECK_LIVE=1 it also runs against real Sneakers-PAM/sneakers-audit
# commits, through the real gh (signed in, or GH_TOKEN set).
#
# Cases:
#   - good:     a commit on main (compare status "ahead" or "identical")
#   - pr-head:  a squash-merged PR head, never on main ("diverged")
#   - missing:  a SHA the repo doesn't have (HTTP 404)
#   - a pin ahead of main, an unknown repo and malformed lines fail too
#
# Run from anywhere:
#   bash .github/scripts/pin-check_test.sh
#   PIN_CHECK_LIVE=1 bash .github/scripts/pin-check_test.sh
set -euo pipefail

scripts_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
pin_check="$scripts_dir/pin-check.sh"

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

# run <dir> <log>: runs pin-check.sh in <dir> and echoes its exit code.
run() {
  local rc=0
  (cd "$1" && bash "$pin_check") >"$2" 2>&1 || rc=$?
  sed 's/^/    | /' "$2" >&2
  echo "$rc"
}

good=1111111111111111111111111111111111111111
same=2222222222222222222222222222222222222222
head=3333333333333333333333333333333333333333
gone=4444444444444444444444444444444444444444
behind=5555555555555555555555555555555555555555

# The fake gh answers `gh api repos/<org>/<repo>/compare/<sha>...main?per_page=1 --jq .status`
# and 404s on anything else, as the API does for an unknown repo or commit.
fake="$work/bin"
mkdir -p "$fake"
{
  echo '#!/usr/bin/env bash'
  echo '[[ "$1" == api ]] || exit 9'
  echo 'case "$2" in'
  echo "  repos/fixture-org/sneakers-audit/compare/$good...main?per_page=1) echo ahead ;;"
  echo "  repos/fixture-org/sneakers-vault/compare/$same...main?per_page=1) echo identical ;;"
  echo "  repos/fixture-org/sneakers-notify/compare/$head...main?per_page=1) echo diverged ;;"
  echo "  repos/fixture-org/sneakers-identity/compare/$behind...main?per_page=1) echo behind ;;"
  echo '  *)'
  echo "    echo '{\"message\":\"Not Found\",\"status\":\"404\"}'"
  echo '    echo "gh: Not Found (HTTP 404)" >&2'
  echo '    exit 1'
  echo '    ;;'
  echo 'esac'
} >"$fake/gh"
chmod +x "$fake/gh"

echo "=== offline: fake compare API ==="
export PROTO_SYNC_ORG=fixture-org

mkdir -p "$work/good"
printf '%s\n' "# a comment, then a blank line" "" \
  "SNEAKERS_AUDIT_REF=$good" "SNEAKERS_VAULT_REF=$same" >"$work/good/proto-refs.env"
rc="$(PATH="$fake:$PATH" run "$work/good" "$work/good.log")"
expect_exit "good pins pass" 0 "$rc"
expect_contains "ahead is on main" "SNEAKERS_AUDIT_REF: fixture-org/sneakers-audit $good is on main (ahead)" "$work/good.log"
expect_contains "identical is on main" "SNEAKERS_VAULT_REF: fixture-org/sneakers-vault $same is on main (identical)" "$work/good.log"

mkdir -p "$work/bad"
printf '%s\n' \
  "SNEAKERS_AUDIT_REF=$good" \
  "SNEAKERS_NOTIFY_REF=$head" \
  "SNEAKERS_VAULT_REF=$gone" \
  "SNEAKERS_IDENTITY_REF=$behind" \
  "SNEAKERS_NOSUCH_REF=$good" \
  "SNEAKERS_SHORT_REF=abc123" \
  "OTHER_REF=$good" >"$work/bad/proto-refs.env"
rc="$(PATH="$fake:$PATH" run "$work/bad" "$work/bad.log")"
expect_exit "bad pins fail" 1 "$rc"
expect_not_contains "the good pin isn't flagged" "::error file=proto-refs.env::SNEAKERS_AUDIT_REF" "$work/bad.log"
expect_contains "a PR head off main fails" \
  "::error file=proto-refs.env::SNEAKERS_NOTIFY_REF: $head isn't reachable from fixture-org/sneakers-notify main (compare status: diverged)." "$work/bad.log"
expect_contains "a missing SHA fails" \
  "::error file=proto-refs.env::SNEAKERS_VAULT_REF: fixture-org/sneakers-vault has no commit $gone (compare returned 404)." "$work/bad.log"
expect_contains "a pin ahead of main fails" \
  "::error file=proto-refs.env::SNEAKERS_IDENTITY_REF: $behind isn't reachable from fixture-org/sneakers-identity main (compare status: behind)." "$work/bad.log"
expect_contains "an unknown repo fails" \
  "::error file=proto-refs.env::SNEAKERS_NOSUCH_REF: fixture-org/sneakers-nosuch has no commit $good (compare returned 404)." "$work/bad.log"
expect_contains "a short SHA fails" \
  "::error file=proto-refs.env::Not a SNEAKERS_<NAME>_REF=<40-hex commit> line: SNEAKERS_SHORT_REF=abc123" "$work/bad.log"
expect_contains "a ref outside SNEAKERS_ fails" \
  "::error file=proto-refs.env::Not a SNEAKERS_<NAME>_REF=<40-hex commit> line: OTHER_REF=$good" "$work/bad.log"

mkdir -p "$work/none"
rc="$(PATH="$fake:$PATH" run "$work/none" "$work/none.log")"
expect_exit "no proto-refs.env passes" 0 "$rc"

if [[ "${PIN_CHECK_LIVE:-}" == 1 ]]; then
  echo "=== live: Sneakers-PAM/sneakers-audit through the real compare API ==="
  unset PROTO_SYNC_ORG
  live_main="$(gh api repos/Sneakers-PAM/sneakers-audit/commits/main --jq .sha)"
  # The squash-merge commit of sneakers-audit PR 24 (on main), and the head of
  # the squash-merged sneakers-audit PR 26, which never reached main.
  live_old=c79a2a3110011fa8293e5cb1e0ebaf9a41ad336b
  live_head=b3128a1bde76ae2c4cf55e26625951d737eb73aa
  live_gone=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef

  for c in main:"$live_main" old:"$live_old" head:"$live_head" gone:"$live_gone"; do
    name="${c%%:*}" sha="${c#*:}"
    mkdir -p "$work/live-$name"
    echo "SNEAKERS_AUDIT_REF=$sha" >"$work/live-$name/proto-refs.env"
  done
  rc="$(run "$work/live-main" "$work/live-main.log")"
  expect_exit "live: main's head passes" 0 "$rc"
  expect_contains "live: main's head is identical" "is on main (identical)" "$work/live-main.log"
  rc="$(run "$work/live-old" "$work/live-old.log")"
  expect_exit "live: an older merge commit passes" 0 "$rc"
  expect_contains "live: an older merge commit is behind main" "is on main (ahead)" "$work/live-old.log"
  rc="$(run "$work/live-head" "$work/live-head.log")"
  expect_exit "live: a squash-merged PR head fails" 1 "$rc"
  expect_contains "live: a squash-merged PR head has diverged" \
    "isn't reachable from Sneakers-PAM/sneakers-audit main (compare status: diverged)." "$work/live-head.log"
  rc="$(run "$work/live-gone" "$work/live-gone.log")"
  expect_exit "live: a nonexistent SHA fails" 1 "$rc"
  expect_contains "live: a nonexistent SHA is a 404" "has no commit $live_gone (compare returned 404)." "$work/live-gone.log"
fi

echo
if [[ "$fail" == 0 ]]; then
  echo "pin-check_test.sh: all checks passed"
else
  echo "pin-check_test.sh: FAILURES ABOVE"
fi
exit "$fail"
