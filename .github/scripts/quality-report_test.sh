#!/usr/bin/env bash
# Self-test for quality-report.sh, against canned tool output. Touches no
# network and needs none of the tools.
#
# Run from anywhere:
#   bash .github/scripts/quality-report_test.sh
set -euo pipefail

scripts_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
report="$scripts_dir/quality-report.sh"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail=0
expect_exit() {
  if [[ "$2" == "$3" ]]; then echo "ok   $1"; else echo "FAIL $1 (want exit $2, got $3)"; fail=1; fi
}
expect_contains() {
  if grep -qF -- "$2" "$3"; then echo "ok   $1"; else echo "FAIL $1 (missing: $2)"; fail=1; fi
}
expect_absent() {
  if grep -qF -- "$2" "$3"; then echo "FAIL $1 (unexpected: $2)"; fail=1; else echo "ok   $1"; fi
}
expect_count() {
  local got
  got="$(grep -c -- "$2" "$3" || true)"
  if [[ "$got" == "$4" ]]; then echo "ok   $1"; else echo "FAIL $1 (want $4 of $2, got $got)"; fail=1; fi
}

ws="$work/ws"
mkdir -p "$ws"
run() {
  local tool="$1" input="$2" outcome="$3" name="$4"
  : >"$work/$name.summary"
  set +e
  GITHUB_WORKSPACE="$ws" GITHUB_STEP_SUMMARY="$work/$name.summary" \
    bash "$report" "$tool" "$input" "$outcome" >"$work/$name.out" 2>&1
  echo $? >"$work/$name.rc"
  set -e
}

printf '' >"$work/clean.txt"
run golangci-lint "$work/clean.txt" success clean
expect_exit "a clean run exits 0" 0 "$(cat "$work/clean.rc")"
expect_count "a clean run emits no annotation" '^::' "$work/clean.out" 0
expect_contains "a clean run says so in the summary" "No findings." "$work/clean.summary"
expect_contains "the summary names the tool as advisory" "golangci-lint (advisory)" "$work/clean.summary"

cat >"$work/lint.txt" <<EOF
internal/store/db.go:12:5: Error return value of \`rows.Close\` is not checked (errcheck)
$ws/cmd/app/main.go:3:1: 100% wrong, a,b: c (unused)
2 issues:
* errcheck: 1
* unused: 1
EOF
run golangci-lint "$work/lint.txt" failure lint
expect_exit "findings still exit 0" 0 "$(cat "$work/lint.rc")"
expect_contains "a finding becomes a warning on its line" \
  '::warning file=internal/store/db.go,line=12,col=5,title=golangci-lint::Error return value of `rows.Close` is not checked (errcheck)' "$work/lint.out"
expect_contains "a workspace path is made relative and the message escaped" \
  '::warning file=cmd/app/main.go,line=3,col=1,title=golangci-lint::100%25 wrong, a,b: c (unused)' "$work/lint.out"
expect_count "lines without a position emit nothing" '^::' "$work/lint.out" 2
expect_contains "the summary counts the findings" "2 findings" "$work/lint.summary"
expect_contains "the summary keeps the full output" '* errcheck: 1' "$work/lint.summary"

cat >"$work/vuln.txt" <<'EOF'
=== Symbol Results ===

Vulnerability #1: GO-2000-0001
    A made-up flaw in an example module
  More info: https://pkg.go.dev/vuln/GO-2000-0001
  Module: example.com/mod
    Found in: example.com/mod@v1.0.0
    Fixed in: example.com/mod@v1.0.1
    Example traces found:
      #1: internal/fetch.go:10:2: fetch.Get calls mod.Parse

Your code is affected by 1 vulnerability from 1 module.
EOF
run govulncheck "$work/vuln.txt" failure vuln
expect_contains "a vulnerability becomes a warning" \
  '::warning title=govulncheck::Vulnerability #1: GO-2000-0001' "$work/vuln.out"
expect_contains "a trace becomes a warning on its line" \
  '::warning file=internal/fetch.go,line=10,col=2,title=govulncheck::fetch.Get calls mod.Parse' "$work/vuln.out"

echo "a.go:1:1: one" >"$work/one.txt"
run modernize "$work/one.txt" failure one
expect_contains "one finding is counted in the singular" "1 finding." "$work/one.summary"

printf 'level=error msg="can not load config"\n' >"$work/broken.txt"
run golangci-lint "$work/broken.txt" failure broken
expect_exit "a tool error exits 0" 0 "$(cat "$work/broken.rc")"
expect_contains "a tool error with no findings is still a warning" \
  '::warning title=golangci-lint::golangci-lint failed without a finding; see the job log.' "$work/broken.out"
expect_contains "a tool error is in the summary" "failed without a finding" "$work/broken.summary"

run gosec "$work/missing.txt" skipped skipped
expect_exit "a tool that never ran exits 0" 0 "$(cat "$work/skipped.rc")"
expect_contains "a tool that never ran is reported" "gosec did not run" "$work/skipped.summary"

for i in $(seq 1 60); do echo "a.go:$i:1: finding $i"; done >"$work/many.txt"
run modernize "$work/many.txt" failure many
expect_count "annotations stop at 50" '^::warning file=' "$work/many.out" 50
expect_contains "the summary still counts every finding" "60 findings" "$work/many.summary"
expect_contains "the summary says annotations were capped" "first 50" "$work/many.summary"

exit "$fail"
