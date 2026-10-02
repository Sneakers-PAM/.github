#!/usr/bin/env bash
# Self-test for proto-sync.sh against local git fixtures, standing in for
# Sneakers-PAM. Touches no network: PROTO_SYNC_URL points at a local bare-repo
# tree instead of https://github.com.
#
# Builds a multi-owner caller like sneakers-gateway, pinning five callees
# (identity, vault, audit, notify, sshbroker), covering:
#   - identity: main moved past the pin, additively (expect a warning)
#   - vault:    same, but vault's own buf.yaml also names a nested callee
#               module (.protos/sneakers-notify) that's never fetched here —
#               the shape that broke buf breaking's module resolution before
#               scope_to_proto existed (expect a warning, no resolution error)
#   - audit:    pin equals main (expect "in sync")
#   - notify:   pin is on a branch that never merged to main, with proto/
#               otherwise identical to main (expect an "isn't on main"
#               failure, isolated from the breaking check)
#   - sshbroker: main drops an rpc the pin has, and also carries a nested
#               callee module like vault's (expect a "breaks the protos"
#               failure, proving scope_to_proto doesn't mask a real break)
#
# Run from anywhere, with buf and git on PATH:
#   bash .github/scripts/proto-sync_test.sh
set -euo pipefail

scripts_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
proto_sync="$scripts_dir/proto-sync.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

export PROTO_SYNC_ORG="fixture-org"
export PROTO_SYNC_URL="$work/remotes"
remotes="$PROTO_SYNC_URL/$PROTO_SYNC_ORG"
mkdir -p "$remotes"

fail=0

ok() { echo "ok: $1"; }
bad() {
  echo "FAIL: $1"
  fail=1
}

expect_exit() { # expect_exit <desc> <want> <got>
  if [[ "$2" == "$3" ]]; then
    ok "$1 (exit $3)"
  else
    bad "$1 (want exit $2, got $3)"
  fi
}

expect_contains() { # expect_contains <desc> <needle> <file>
  if grep -qF "$2" "$3"; then
    ok "$1"
  else
    bad "$1 (missing: $2)"
    sed 's/^/    /' "$3" >&2
  fi
}

expect_not_contains() { # expect_not_contains <desc> <needle> <file>
  if grep -qF "$2" "$3"; then
    bad "$1 (should not contain: $2)"
    sed 's/^/    /' "$3" >&2
  else
    ok "$1"
  fi
}

# make_repo <name>: a bare remote at $remotes/sneakers-<name>.git, and a
# scratch checkout at $work/src/<name> on main to build commits in. Commits
# inherit the ambient git identity (global user.name/user.email); these repos
# are local-only scratch, deleted with $work on exit, and never pushed to a
# real host.
make_repo() {
  local name="$1"
  local bare="$remotes/sneakers-$name.git" src="$work/src/$name"
  git init -q --bare "$bare"
  git init -q -b main "$src"
  git -C "$src" remote add origin "$bare"
}

# commit_and_push <name> <message>: commit the scratch checkout's current
# state on main and push it; echoes the new commit.
commit_and_push() {
  local src="$work/src/$1"
  git -C "$src" add -A
  git -C "$src" commit -q -m "$2"
  git -C "$src" push -q origin main
  git -C "$src" rev-parse HEAD
}

# push_unmerged <name> <message>: commit the scratch checkout's current state
# on a branch that's never merged to main, and push only that branch.
push_unmerged() {
  local src="$work/src/$1"
  git -C "$src" switch -q -c unmerged
  git -C "$src" add -A
  git -C "$src" commit -q -m "$2"
  git -C "$src" push -q origin unmerged
  local sha
  sha="$(git -C "$src" rev-parse HEAD)"
  git -C "$src" switch -q main
  echo "$sha"
}

# A service proto with the given rpc names, one per line.
write_service() {
  local src="$1" pkg="$2" go_pkg="$3"
  shift 3
  mkdir -p "$src/proto/sneakers/$pkg/v1"
  {
    echo 'syntax = "proto3";'
    echo
    echo "package sneakers.$pkg.v1;"
    echo
    echo "option go_package = \"github.com/fixture-org/sneakers-$pkg/gen/go/sneakers/$pkg/v1;${go_pkg}v1\";"
    echo
    echo "message Empty {}"
    echo
    echo "service ${go_pkg^}Service {"
    for rpc in "$@"; do
      echo "  rpc $rpc(Empty) returns (Empty);"
    done
    echo "}"
  } >"$src/proto/sneakers/$pkg/v1/$pkg.proto"
}

write_buf_yaml() { # write_buf_yaml <src> <extra module path>...
  local src="$1"
  shift
  {
    echo "version: v2"
    echo "modules:"
    echo "  - path: proto"
    for m in "$@"; do
      echo "  - path: $m"
    done
    echo "breaking:"
    echo "  use: [FILE]"
  } >"$src/buf.yaml"
}

echo "=== building fixtures ==="

# identity: additive-only move past the pin.
make_repo identity
write_buf_yaml "$work/src/identity"
write_service "$work/src/identity" identity identity Get List
identity_pin="$(commit_and_push identity "feat: identity v1")"
write_service "$work/src/identity" identity identity Get List Ping
identity_main="$(commit_and_push identity "feat: add Ping")"

# vault: additive-only move past the pin, but vault's own buf.yaml also
# names a callee module nothing here ever fetches (reproduces the bug).
make_repo vault
write_buf_yaml "$work/src/vault" .protos/sneakers-notify
write_service "$work/src/vault" vault vault Get List
vault_pin="$(commit_and_push vault "feat: vault v1")"
write_service "$work/src/vault" vault vault Get List Rotate
vault_main="$(commit_and_push vault "feat: add Rotate")"

# audit: pin equals main.
make_repo audit
write_buf_yaml "$work/src/audit"
write_service "$work/src/audit" audit audit Record
audit_pin="$(commit_and_push audit "feat: audit v1")"
audit_main="$audit_pin"

# notify: the pin is only on a branch that never merged to main; proto/ is
# identical on both sides, so this isolates the "isn't on main" failure from
# the breaking check.
make_repo notify
write_buf_yaml "$work/src/notify"
write_service "$work/src/notify" notify notify Send
notify_main="$(commit_and_push notify "feat: notify v1")"
echo "unmerged" >"$work/src/notify/UNRELEASED.md"
notify_pin="$(push_unmerged notify "chore: unmerged, unrelated to proto")"

# sshbroker: main drops an rpc the pin has (a real break), and also carries a
# nested callee module like vault's.
make_repo sshbroker
write_buf_yaml "$work/src/sshbroker" .protos/sneakers-audit .protos/sneakers-vault
write_service "$work/src/sshbroker" sshbroker sshbroker Connect Heartbeat
sshbroker_pin="$(commit_and_push sshbroker "feat: sshbroker v1")"
write_service "$work/src/sshbroker" sshbroker sshbroker Connect
sshbroker_main="$(commit_and_push sshbroker "feat!: drop Heartbeat")"

echo "=== running proto-sync.sh check against the fixture caller ==="
caller="$work/caller"
mkdir -p "$caller"
cat >"$caller/proto-refs.env" <<EOF
SNEAKERS_IDENTITY_REF=$identity_pin
SNEAKERS_VAULT_REF=$vault_pin
SNEAKERS_AUDIT_REF=$audit_pin
SNEAKERS_NOTIFY_REF=$notify_pin
SNEAKERS_SSHBROKER_REF=$sshbroker_pin
EOF

out="$work/check.log"
check_exit=0
(cd "$caller" && bash "$proto_sync" check) >"$out" 2>&1 || check_exit=$?
cat "$out"

expect_exit "check fails overall (a real break and an off-main pin are in the fixture)" 1 "$check_exit"

expect_contains "identity: additive move warns, doesn't fail" \
  "SNEAKERS_IDENTITY_REF: fixture-org/sneakers-identity main ($identity_main) has proto changes past the pin ($identity_pin), none breaking." "$out"

expect_contains "vault: additive move warns even with an unfetched nested module" \
  "SNEAKERS_VAULT_REF: fixture-org/sneakers-vault main ($vault_main) has proto changes past the pin ($vault_pin), none breaking." "$out"
expect_not_contains "vault: no buf module-resolution error leaks through" \
  "had no .proto files" "$out"

expect_contains "audit: pin equals main, reported in sync" "in sync" "$out"

expect_contains "notify: pin isn't on main, fails" \
  "SNEAKERS_NOTIFY_REF: $notify_pin isn't on fixture-org/sneakers-notify main." "$out"

expect_contains "sshbroker: a real rpc removal still fails, nested module included" \
  "SNEAKERS_SSHBROKER_REF: fixture-org/sneakers-sshbroker main ($sshbroker_main) breaks the protos at the pin ($sshbroker_pin)" "$out"

echo "=== proto-sync.sh refresh bumps every stale pin ==="
refresh_out="$work/refresh.log"
refresh_exit=0
(cd "$caller" && bash "$proto_sync" refresh) >"$refresh_out" 2>&1 || refresh_exit=$?
cat "$refresh_out"
expect_exit "refresh itself always succeeds" 0 "$refresh_exit"

refreshed="$(cat "$caller/proto-refs.env")"
expect_contains "refresh bumps identity to main" "SNEAKERS_IDENTITY_REF=$identity_main" <(echo "$refreshed")
expect_contains "refresh bumps vault to main" "SNEAKERS_VAULT_REF=$vault_main" <(echo "$refreshed")
expect_contains "refresh leaves audit alone (already current)" "SNEAKERS_AUDIT_REF=$audit_pin" <(echo "$refreshed")
expect_contains "refresh bumps notify onto main" "SNEAKERS_NOTIFY_REF=$notify_main" <(echo "$refreshed")
expect_contains "refresh bumps sshbroker to main" "SNEAKERS_SSHBROKER_REF=$sshbroker_main" <(echo "$refreshed")

echo
if [[ "$fail" == 0 ]]; then
  echo "proto-sync_test.sh: all checks passed"
else
  echo "proto-sync_test.sh: FAILURES ABOVE"
fi
exit "$fail"
