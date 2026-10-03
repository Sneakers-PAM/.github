#!/usr/bin/env bash
# Fails when a go.mod in the repo builds against something CI can't
# reproduce: any replace directive, or an owner package (github.com/Bugs5382/*
# or github.com/Sneakers-PAM/*) required at a pseudo-version
# (v0.0.0-<timestamp>-<commit>, vX.Y.Z-0.<timestamp>-<commit> or
# vX.Y.Z-<pre>.0.<timestamp>-<commit>) rather than a tagged release. Work
# against a local package checkout goes in a git-ignored go.work instead.
#
# The proto-sync workflow runs it from the root of the calling repo. It checks
# every go.mod below the root, skipping hidden directories (fetched protos,
# tool checkouts) and vendor/. It needs no Go toolchain and no network.
set -euo pipefail

owners='^github\.com/(Bugs5382|Sneakers-PAM)/'
pseudo='[0-9]{14}-[0-9a-f]{12}(\+incompatible)?$'

mapfile -t mods < <(find . \( -name '.?*' -o -name vendor \) -prune -o -name go.mod -type f -print | sed 's|^\./||' | sort)
if ((${#mods[@]} == 0)); then
  echo "No go.mod: nothing to check."
  exit 0
fi

status=0
for mod in "${mods[@]}"; do
  bad=0
  block=""
  n=0
  while IFS= read -r raw || [[ -n "$raw" ]]; do
    n=$((n + 1))
    line="${raw%%//*}"
    line="${line%$'\r'}"
    read -r -a f <<<"$line" || true
    ((${#f[@]} == 0)) && continue

    if [[ -n "$block" ]]; then
      if [[ "${f[0]}" == ")" ]]; then
        block=""
        continue
      fi
      words=("${f[@]}")
    else
      case "${f[0]}" in
        require | replace)
          if [[ "${f[1]:-}" == "(" ]]; then
            block="${f[0]}"
            continue
          fi
          block_once="${f[0]}"
          words=("${f[@]:1}")
          ;;
        *) continue ;;
      esac
    fi
    kind="${block:-$block_once}"

    if [[ "$kind" == replace ]]; then
      echo "::error file=$mod,line=$n::replace directive: ${words[*]}. Commit tagged versions only; link a local checkout with a git-ignored go.work."
      bad=1
    else
      path="${words[0]//\"/}"
      ver="${words[1]:-}"
      if [[ "$path" =~ $owners && "$ver" =~ $pseudo ]]; then
        echo "::error file=$mod,line=$n::$path is at a pseudo-version ($ver). Require a tagged release; link a local checkout with a git-ignored go.work."
        bad=1
      fi
    fi
  done <"$mod"

  if ((bad == 0)); then
    echo "$mod: no replace directives, owner packages at tagged releases"
  else
    status=1
  fi
done

exit "$status"
