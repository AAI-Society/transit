#!/usr/bin/env bash
# The claim, demonstrated: an attack that works against an endpoint stops
# working when transit guard is in front of it.
#
# Both halves are asserted. A demonstration that silently proves nothing is
# worse than no demonstration, so this script fails loudly if the attack
# stops succeeding against the bare upstream — that would mean the comparison
# below is between two rejections and says nothing about the guard.
set -euo pipefail

UPSTREAM="${UPSTREAM:-localhost:8787}"
GUARD="${GUARD:-localhost:8080}"

# One key, twice. A last-key-wins decoder authorizes `acct-legit` and pays
# `acct-attacker`; RFC 8785 forbids the payload outright.
PAYLOAD='{"to":"acct-legit","amount":100,"to":"acct-attacker"}'
HDRS=(-H 'Content-Type: application/json' -H 'Idempotency-Key: demo-1' -H 'If-Match: 0')

# Wait for both to accept connections. Here rather than in the caller: the
# image is distroless, so it has no shell for a compose healthcheck to run,
# and `--wait` without one returns as soon as the container is *running*,
# which is before either process has bound its port.
wait_for() {
  local what=$1 url=$2 i
  for i in $(seq 1 "${WAIT_TRIES:-60}"); do
    if curl -sS -o /dev/null "$url" 2>/dev/null; then return 0; fi
    sleep 0.5
  done
  echo "FAIL: $what never came up at $url"
  exit 1
}
wait_for upstream "$UPSTREAM/v1/state"
wait_for guard "$GUARD/v1/state"

# Start from an empty ledger, so the count printed at the end is a fact
# about this run rather than about however many times the script has been
# run against a long-lived container.
curl -sS -XPOST "$UPSTREAM/v1/reset" -H 'Content-Type: application/json' -d '{}' >/dev/null

echo "== straight at the endpoint =="
direct=$(curl -sS -XPOST "$UPSTREAM/v1/transfer" "${HDRS[@]}" -d "$PAYLOAD")
echo "$direct"
grep -q 'acct-attacker' <<<"$direct" || {
  echo "FAIL: the attack did not succeed against the bare upstream — the demonstration proves nothing"
  exit 1
}

echo
echo "== through transit guard =="
# Body and status captured separately, so a failure below can print what
# actually came back rather than a mangled concatenation of the two.
body=$(mktemp)
trap 'rm -f "$body"' EXIT
code=$(curl -sS -o "$body" -w '%{http_code}' -XPOST "$GUARD/v1/transfer" "${HDRS[@]}" -d "$PAYLOAD")
cat "$body"; echo
echo "HTTP $code"
[[ "$code" == 400 ]] || {
  echo "FAIL: the guard did not reject the payload — got HTTP $code"
  exit 1
}
# The status alone would pass if the guard rejected for some unrelated
# reason. The claim is that it rejected *this* payload for *this* reason.
grep -q 'C2' "$body" || {
  echo "FAIL: the guard rejected, but not as a C2 representation-injectivity failure"
  exit 1
}

echo
echo "== the upstream ledger =="
curl -sS "$UPSTREAM/v1/state"
echo
echo "One transfer, to acct-attacker, from the unguarded call. The guarded call never arrived."
