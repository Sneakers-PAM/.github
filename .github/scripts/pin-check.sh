#!/usr/bin/env bash
# Fails when a callee proto pin in proto-refs.env isn't reachable from its
# owner's main, asking GitHub's compare API rather than a local clone. A pin
# off main (a squash-merged PR head, say) still resolves on codeload until
# GitHub drops the commit, so scripts/proto-generate.sh keeps working until it
# suddenly doesn't. The proto-sync workflow runs it from the root of the
# calling repo, before proto-sync.sh check.
#
# For each SNEAKERS_<NAME>_REF=<commit> line it calls
#   repos/<org>/sneakers-<name>/compare/<commit>...main
# and passes only when the status is "ahead" (main has moved on from the pin)
# or "identical". "behind" or "diverged" fails, and so does a 404 (no such
# repo, or no such commit in it).
#
# Needs gh on PATH, signed in or with GH_TOKEN set.
#
# Environment:
#   PROTO_SYNC_ORG  owner of the callee repos (default Sneakers-PAM)
set -euo pipefail

org="${PROTO_SYNC_ORG:-Sneakers-PAM}"
refs="proto-refs.env"

if [[ ! -f "$refs" ]]; then
  echo "No $refs: this repo pins no callee protos."
  exit 0
fi

annotate() { echo "::$1 file=$refs::$2"; }

status=0
while IFS= read -r line || [[ -n "$line" ]]; do
  line="${line%$'\r'}"
  [[ -z "$line" || "$line" == \#* ]] && continue
  if ! [[ "$line" =~ ^SNEAKERS_([A-Z0-9_]+)_REF=([0-9a-f]{40})$ ]]; then
    annotate error "Not a SNEAKERS_<NAME>_REF=<40-hex commit> line: $line"
    status=1
    continue
  fi
  var="SNEAKERS_${BASH_REMATCH[1]}_REF"
  pin="${BASH_REMATCH[2]}"
  name="${BASH_REMATCH[1],,}"
  repo="sneakers-${name//_/-}"

  rc=0
  out="$(gh api "repos/$org/$repo/compare/$pin...main?per_page=1" --jq .status 2>&1)" || rc=$?
  if ((rc != 0)); then
    if [[ "$out" == *"HTTP 404"* ]]; then
      annotate error "$var: $org/$repo has no commit $pin (compare returned 404)."
    else
      annotate error "$var: comparing $pin with $org/$repo main failed: ${out//$'\n'/ }"
    fi
    status=1
    continue
  fi
  case "$out" in
    ahead | identical)
      echo "$var: $org/$repo $pin is on main ($out)"
      ;;
    *)
      annotate error "$var: $pin isn't reachable from $org/$repo main (compare status: $out). Pin a commit on main, such as the owner's merge commit."
      status=1
      ;;
  esac
done <"$refs"

exit "$status"
