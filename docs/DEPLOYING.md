# Deploying `transit guard`

`transit guard` is an enforcing reverse proxy. It strict-ingests every request
before the upstream sees it and forwards the **canonical** form rather than the
wire form, so the upstream and whatever signed the request cannot be reading
two spellings of one document.

This document is what an operator needs to put it in front of a real API. Read
the next section first.

---

## What this does not do

Placed before the instructions on purpose. Everything below is what you get
*after* configuring it correctly; this is what you do not get at all.

* **C2 is closed at the boundary, unconditionally.** Duplicate keys, lone
  surrogates, noncharacters and unbounded numerics cannot reach the upstream,
  and what does reach it is the canonical form — so the upstream and the signer
  cannot be reading two spellings of one document.

* **C1 is closed only where you configure it.** A proxy cannot know what an
  endpoint defaults. Name those parameters per route in `require_parameters`,
  using `transit classify` on the OpenAPI document to find them. **Without that
  list the parameter-defaulting bypass still works.** This is pinned by a test
  rather than a promise: see
  `the_defaulting_bypass_is_not_stopped_without_that_list` in
  `tests/guard_blocks_the_attacks.rs`.

* **C3 and C4 are demanded, not verified.** The guard requires an
  `Idempotency-Key` and an `If-Match` to be present. Whether the upstream
  honours them is not something a proxy can check.

* **Alias collapse is not addressed at all.** `/v1/users/me` and
  `/v1/users/usr_99812` are one resource under two names; the guard sees two
  paths, no body, and forwards both.

* **It binds what reaches the upstream, not what the upstream does with it.**
  That is the honest ceiling on any enforcement point outside the process
  performing the effect.

---

## The one-command demonstration

```bash
docker compose up -d
./scripts/demo.sh
docker compose down
```

The compose file stands up two containers: the deliberately hostile endpoint on
`:8787`, and the guard in front of it on `:8080`. `demo.sh` sends one payload —
`{"to":"acct-legit","amount":100,"to":"acct-attacker"}` — to each.

Straight at the endpoint, a last-key-wins decoder authorizes `acct-legit` and
pays `acct-attacker`. Through the guard, the same bytes are refused with 400
and a `C2 representation injectivity` reason, and the upstream ledger records
exactly one transfer: the unguarded one.

The script asserts **both** halves and exits 1 if either fails, including the
case where the attack stops working against the bare upstream. A demonstration
that silently proves nothing is worse than no demonstration.

The upstream's port is published in `docker-compose.yml` because the argument
*is* the comparison and cannot be made without reaching the endpoint directly.
That is not a deployment topology. A real one publishes the guard and leaves
the upstream reachable only from it.

---

## Putting it in front of a real API

Copy `examples/guard.toml`, edit it, and mount it at
`/etc/transit/guard.toml`:

```bash
docker run --rm -p 8080:8080 \
  -e TRANSIT_LISTEN=0.0.0.0:8080 \
  -e TRANSIT_UPSTREAM=http://api.internal:8080 \
  -v "$PWD/guard.toml:/etc/transit/guard.toml:ro" \
  transit:latest
```

`listen` and `upstream` are the two settings a container cannot edit in its own
config file, so both are overridable from the environment — `TRANSIT_LISTEN`
and `TRANSIT_UPSTREAM`. **These two and nothing else.** No enforcement rule is
reachable from the environment: a rule an environment variable can switch off
is a rule anything that can set one can switch off.

Note that the shipped config binds `127.0.0.1:8080`, which is right on a
workstation and unreachable inside a container behind a published port. Set
`TRANSIT_LISTEN=0.0.0.0:8080` there.

**It speaks HTTP only, by design.** It is meant to run as a sidecar inside a
trust boundary — same pod, same host, loopback or a private network — with TLS
terminated in front of it. It is not an edge proxy and has no certificate
handling. If it is reachable from an untrusted network, something in front of
it should be terminating TLS and authenticating callers.

The image is distroless and runs as UID 65532. There is no shell in it: an
enforcement point with a shell is a worse hole than the one it closes.

### Read the banner, not the config comments

On startup the guard prints what it is actually enforcing:

```
transit guard on http://0.0.0.0:8080 → http://api.internal:8080
fail-closed: strict I-JSON ingestion; idempotency key required; state precondition required; at most 256 requests in flight
```

That line is generated from the loaded configuration. A comment in a config
file is a claim about what someone intended; this is a report of what the
running process will do.

---

## Finding out what will break, before it does

Every rule below refuses traffic that works today against most APIs. Point
`transit classify` at the upstream's OpenAPI document first:

```bash
transit classify --spec ./their-openapi.json
```

It reports each operation as Qualified, Conditional, or Non-qualifying against
C1–C4 and names the specific condition that failed. Two readings matter here:

* A **C1 `ClientDependent`** verdict lists the optional parameters by name.
  That list is your `require_parameters` for the route — those are exactly the
  fields the endpoint may fill from its own state.
* A **C3 or C4 `Failed`/`Unknown`** verdict means clients are not sending an
  idempotency key or a precondition today. Turning
  `require_idempotency_key` or `require_state_precondition` on will refuse
  their traffic with 428 until they do.

Every verdict `classify` produces is derived from a document, and the output
says so. It cannot see server-side defaulting that the document does not
mention.

### Per-route relaxation

Global settings live under `[enforce]`; a `[[route]]` block overrides them for
one method and path prefix:

```toml
[[route]]
method = "POST"
path_prefix = "/v1/search"
require_idempotency_key = false
require_state_precondition = false
```

A read-only POST — a search body rather than a form of state change —
legitimately needs neither.

**`strict_ingestion` is not among the relaxable rules.** It is not a route key
at all, and a config file that sets it `false` globally is *refused at load*
rather than ignored. It is the one rule the whole deployment claim rests on: a
config that could switch it off is a config that can reintroduce the bug the
proxy exists to prevent.

`require_parameters` entries are either a bare name (checked for presence as a
JSON string) or a table naming the type — `{ name = "amount", type = "number" }`
— for a parameter the endpoint reads some other way. Get the type wrong and a
wrong-shaped value passes as though it were absent, which is the bypass the
list exists to close. A name matches a literal top-level key only; it cannot
reach into a nested object.

---

## What the responses mean

| Status | Condition | What happened |
| :-- | :-- | :-- |
| **400** | C2 | The body is not strict I-JSON — a duplicate key, a lone surrogate, a noncharacter, an unrepresentable number. Or the request line itself was malformed. |
| **405** | — | The method is not one this guard forwards. |
| **413** | — | The body is over `max_body_bytes`. A body the guard cannot hold is one it cannot canonicalize. |
| **415** | — | The body is not `application/json`. The guard forwards only what it can canonicalize. |
| **422** | C1 | A parameter named in the route's `require_parameters` is absent, or present with the wrong JSON type. |
| **428** | C3 | A non-idempotent method arrived with no `Idempotency-Key`. |
| **428** | C4 | A state-changing method arrived with no `If-Match` precondition. |
| **503** | — | More than `max_concurrent_requests` are already in flight. Shed without spawning a thread or reading a byte. |

400 and 428 both carry a `condition` field in the response body naming which of
C1–C4 was involved, so a caller can tell a malformed body from a missing
precondition without parsing prose.

---

## Where this sits in the standard

This is **option (c) of C7.1.4** — complete mediation at an enforcement point
outside the agent, with the canonical form and its digest attached to what the
upstream receives.

The standard presents its three options as alternatives. They are not equally
strong: option (b), un-attested local normalization, cannot guarantee effect
binding, because nothing downstream can tell a normalized request from one that
merely claims to be. What this proxy does is (c), and the ceiling stated at the
top of this document — that it binds what reaches the upstream, not what the
upstream does with it — is the honest limit of (c) as against (a).
