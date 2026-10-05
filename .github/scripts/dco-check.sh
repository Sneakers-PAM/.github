#!/usr/bin/env bash
# Fails when any non-merge commit in <base>..<head> has no
# "Signed-off-by: Name <email>" trailer (the Developer Certificate of Origin).
#
# Usage: dco-check.sh <base> <head>, from inside the repository.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: dco-check.sh <base> <head>" >&2
  exit 2
fi
base="$1" head="$2"

commits="$(git rev-list --no-merges "${base}..${head}")"
if [[ -z "$commits" ]]; then
  echo "No commits to check in ${base}..${head}."
  exit 0
fi

missing=0 checked=0
while read -r sha; do
  checked=$((checked + 1))
  trailers="$(git log -1 --format='%(trailers:key=Signed-off-by,valueonly)' "$sha")"
  if ! grep -Eq '^[^<>]*[^<> ][^<>]* <[^<>@ ]+@[^<> ]+>$' <<<"$trailers"; then
    echo "::error::$(git log -1 --format='%h %s' "$sha"): no Signed-off-by: Name <email> trailer. Sign off with git commit -s."
    missing=$((missing + 1))
  fi
done <<<"$commits"

if [[ "$missing" -gt 0 ]]; then
  echo "$missing of $checked commits are not signed off."
  exit 1
fi
echo "All $checked commits are signed off."
