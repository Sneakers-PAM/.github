#!/usr/bin/env bash
# Checks or bumps the callee proto pins of a Sneakers-PAM service. The proto-sync
# workflow runs it from the root of the calling repo:
#
#   proto-sync.sh check     fail if a pin isn't on its owner's main, or if the
#                           owner's main breaks against the pin; warn if main's
#                           protos have moved past the pin without a break
#   proto-sync.sh refresh   point every stale pin at its owner's main
#
# Each pin is a SNEAKERS_<NAME>_REF=<commit> line in proto-refs.env, for the
# repo <org>/sneakers-<name> (underscores become hyphens). A pin is stale when
# it isn't on main (a squash merge leaves a PR head off main) or when proto/
# differs between it and main.
#
# Environment:
#   PROTO_SYNC_ORG      owner of the callee repos (default Sneakers-PAM)
#   PROTO_SYNC_URL      git host the repos are fetched from (default https://github.com)
#   PROTO_SYNC_CHANGES  refresh only: a file to append one line per bumped pin to
set -euo pipefail

mode="${1:-}"
case "$mode" in
  check | refresh) ;;
  *)
    echo "usage: proto-sync.sh check|refresh" >&2
    exit 2
    ;;
esac

org="${PROTO_SYNC_ORG:-Sneakers-PAM}"
host="${PROTO_SYNC_URL:-https://github.com}"
refs="proto-refs.env"

if [[ ! -f "$refs" ]]; then
  echo "No $refs: this repo pins no callee protos."
  exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

annotate() { echo "::$1 file=$refs::$2"; }

# breaks <repo dir> <pin> <main>: buf breaking of main's protos against the pin's.
breaks() {
  local dir="$1" pin="$2" main="$3"
  git -C "$dir" worktree add -q --detach "$dir.pin" "$pin"
  git -C "$dir" worktree add -q --detach "$dir.main" "$main"
  ! buf breaking "$dir.main" --against "$dir.pin"
}

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
  dir="$work/$repo"

  git init -q "$dir"
  git -C "$dir" remote add origin "$host/$org/$repo.git"
  git -C "$dir" fetch -q --filter=blob:none origin main
  main="$(git -C "$dir" rev-parse FETCH_HEAD)"

  on_main=false
  if git -C "$dir" merge-base --is-ancestor "$pin" "$main" 2>/dev/null; then
    on_main=true
  else
    git -C "$dir" fetch -q --filter=blob:none origin "$pin" 2>/dev/null || true
  fi
  known=false
  git -C "$dir" cat-file -e "$pin^{commit}" 2>/dev/null && known=true

  moved=true
  if $known && git -C "$dir" diff --quiet "$pin" "$main" -- proto; then
    moved=false
  fi

  has_proto=false
  git -C "$dir" cat-file -e "$main:proto" 2>/dev/null && has_proto=true

  echo "$var: $org/$repo pin $pin, main $main (on main: $on_main, protos moved: $moved)"

  if [[ "$mode" == refresh ]]; then
    if $on_main && ! $moved; then
      echo "  current"
    elif ! $has_proto; then
      echo "  main has no proto/ yet; left as it is"
    else
      sed -i "s/^$var=.*/$var=$main/" "$refs"
      echo "  bumped to $main"
      if [[ -n "${PROTO_SYNC_CHANGES:-}" ]]; then
        echo "- \`$var\` ($org/$repo): \`$pin\` to \`$main\`" >>"$PROTO_SYNC_CHANGES"
      fi
    fi
    continue
  fi

  if ! $known; then
    annotate error "$var: $pin isn't a commit in $org/$repo."
    status=1
    continue
  fi
  if ! $has_proto; then
    annotate error "$var: $org/$repo main has no proto/ yet. Pin a commit on main once the owner's protos merge."
    status=1
    continue
  fi
  broke=false
  if $moved && breaks "$dir" "$pin" "$main"; then
    annotate error "$var: $org/$repo main ($main) breaks the protos at the pin ($pin); this repo's stubs no longer match what the owner serves."
    status=1
    broke=true
  fi
  if ! $on_main; then
    annotate error "$var: $pin isn't on $org/$repo main. Pin a commit on main once the owner's change merges."
    status=1
  elif $broke; then
    :
  elif $moved; then
    annotate warning "$var: $org/$repo main ($main) has proto changes past the pin ($pin), none breaking. The scheduled proto-sync run opens a PR to bump it."
  else
    echo "  in sync"
  fi
done <"$refs"

exit "$status"
