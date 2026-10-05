#!/usr/bin/env bash
# Self-test for dco-check.sh, against throwaway local repositories.
#
# Run from anywhere:
#   bash .github/scripts/dco-check_test.sh
set -euo pipefail

scripts_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dco_check="$scripts_dir/dco-check.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail=0
expect_exit() {
  if [[ "$2" == "$3" ]]; then echo "ok   $1"; else echo "FAIL $1 (want exit $2, got $3)"; fail=1; fi
}
expect_contains() {
  if grep -qF -- "$2" "$3"; then echo "ok   $1"; else echo "FAIL $1 (missing: $2)"; fail=1; fi
}
run() {
  local rc=0
  (cd "$work/repo" && bash "$dco_check" "$1" "$2") >"$3" 2>&1 || rc=$?
  echo "$rc"
}
commit() {
  echo "$1" >>"$work/repo/file"
  git -C "$work/repo" add file
  git -C "$work/repo" commit -q -m "$1" "${@:2}"
  git -C "$work/repo" rev-parse HEAD
}

# Commits use the ambient git identity: the repo is local-only scratch,
# deleted on exit and never pushed.
git init -q -b main "$work/repo"

root="$(commit "chore: root" -s)"
signed="$(commit "feat: signed" -s)"
rc="$(run "$root" "$signed" "$work/signed.log")"
expect_exit "a signed-off commit passes" 0 "$rc"
expect_contains "it reports the count" "All 1 commits are signed off." "$work/signed.log"

rc="$(run "$signed" "$signed" "$work/empty.log")"
expect_exit "an empty range passes" 0 "$rc"

unsigned="$(commit "fix: unsigned")"
rc="$(run "$root" "$unsigned" "$work/unsigned.log")"
expect_exit "an unsigned commit fails" 1 "$rc"
expect_contains "it names the commit" "fix: unsigned: no Signed-off-by" "$work/unsigned.log"
expect_contains "it counts the misses" "1 of 2 commits are not signed off." "$work/unsigned.log"

bare="$(commit "fix: bare trailer" -m "Signed-off-by: Alice Example")"
rc="$(run "$unsigned" "$bare" "$work/bare.log")"
expect_exit "a trailer with no email fails" 1 "$rc"

inbody="$(commit "fix: not a trailer" -m "Signed-off-by: Alice Example <alice@example.org> was here" -m "More text.")"
rc="$(run "$bare" "$inbody" "$work/inbody.log")"
expect_exit "a sign-off outside the trailers fails" 1 "$rc"

git -C "$work/repo" switch -q -c side "$root"
echo side >"$work/repo/side"
git -C "$work/repo" add side
git -C "$work/repo" commit -q -s -m "feat: side"
git -C "$work/repo" switch -q main
git -C "$work/repo" reset -q --hard "$signed"
git -C "$work/repo" merge -q --no-ff --no-edit side
merge="$(git -C "$work/repo" rev-parse HEAD)"
rc="$(run "$root" "$merge" "$work/merge.log")"
expect_exit "an unsigned merge commit is skipped" 0 "$rc"
expect_contains "only the non-merge commits count" "All 2 commits are signed off." "$work/merge.log"

rc="$(cd "$work/repo" && bash "$dco_check" "$root" >/dev/null 2>&1; echo $?)" || true
expect_exit "a missing argument is a usage error" 2 "$rc"

echo
if [[ "$fail" == 0 ]]; then
  echo "dco-check_test.sh: all checks passed"
else
  echo "dco-check_test.sh: FAILURES ABOVE"
fi
exit "$fail"
