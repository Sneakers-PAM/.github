#!/usr/bin/env bash
# quality-report.sh <tool> <output-file> <outcome>
#
# Turns one advisory tool's captured output into warning annotations and a
# job summary section. <outcome> is the tool step's outcome: success, failure
# or skipped. It always exits 0: quality.yml's checks report, they never gate.
#
# A line `path.go:line:col: message`, optionally led by a govulncheck trace
# marker (`#1: `), becomes a warning on that line; a govulncheck
# `Vulnerability #N: ID` line becomes a warning with no position. GitHub
# shows few annotations per step, so only the first 50 are emitted; the
# summary always has the full output.
set -uo pipefail

tool="$1"
output="$2"
outcome="$3"
workspace="${GITHUB_WORKSPACE:-$PWD}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"
max=50

escape_data() {
  local s="$1"
  s="${s//%/%25}"
  s="${s//$'\r'/%0D}"
  s="${s//$'\n'/%0A}"
  printf '%s' "$s"
}

escape_property() {
  local s
  s="$(escape_data "$1")"
  s="${s//:/%3A}"
  s="${s//,/%2C}"
  printf '%s' "$s"
}

position_re='^[[:space:]]*(#[0-9]+: )?([^[:space:]:]+\.go):([0-9]+):([0-9]+): (.*)$'
vuln_re='^Vulnerability #[0-9]+: [^[:space:]]+'

count=0
annotate() {
  count=$((count + 1))
  if [ "$count" -le "$max" ]; then
    echo "$1"
  fi
}

if [ "$outcome" != "skipped" ] && [ -f "$output" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ "$line" =~ $position_re ]]; then
      file="${BASH_REMATCH[2]#"$workspace"/}"
      annotate "::warning file=$(escape_property "$file"),line=${BASH_REMATCH[3]},col=${BASH_REMATCH[4]},title=$(escape_property "$tool")::$(escape_data "${BASH_REMATCH[5]}")"
    elif [[ "$line" =~ $vuln_re ]]; then
      annotate "::warning title=$(escape_property "$tool")::$(escape_data "${BASH_REMATCH[0]}")"
    fi
  done <"$output"
fi

{
  echo "### $tool (advisory)"
  echo
  if [ "$outcome" = "skipped" ] || [ ! -f "$output" ]; then
    echo "$tool did not run; see the job log."
  elif [ "$count" -gt 0 ]; then
    if [ "$count" -eq 1 ]; then noun=finding; else noun=findings; fi
    echo "$count $noun. They don't block the PR."
    if [ "$count" -gt "$max" ]; then
      echo "Only the first $max are annotated on the diff."
    fi
  elif [ "$outcome" = "success" ]; then
    echo "No findings."
  else
    echo "$tool failed without a finding; see the job log."
  fi
  if [ -s "$output" ]; then
    echo
    echo "<details><summary>Output</summary>"
    echo
    echo '```text'
    cat "$output"
    echo '```'
    echo
    echo "</details>"
  fi
  echo
} >>"$summary"

if [ "$count" -eq 0 ] && [ "$outcome" = "failure" ]; then
  echo "::warning title=$(escape_property "$tool")::$tool failed without a finding; see the job log."
fi
if [ "$outcome" = "skipped" ]; then
  echo "::warning title=$(escape_property "$tool")::$tool did not run; see the job log."
fi
exit 0
