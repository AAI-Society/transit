# Using transit

`DEPLOYING.md` is for whoever runs the proxy. This is for a developer with a
codebase, and it is organised by what you are trying to do.

Everything here runs offline against an endpoint that ships in this
repository. Nothing needs credentials, and nothing touches a third party.

```bash
git clone https://github.com/Task-force-for-AI-agents-in-Healthcare/transit
cd transit && cargo build --release
```

Three situations. Find yours.

---

## 1. I own an API, and something signs requests to it

This is the main case. You have an OpenAPI document, and you want to know
whether a signature over a request to your API actually pins down what your
API will do.

### Step 1 — ask

```bash
transit classify --spec ./your-openapi.json
```

You get a verdict per operation and, crucially, the *reason*:

```
POST /v1/charges — Conditional
    C1 parameter completeness      ClientDependent { how: "send every optional
                                   parameter explicitly: capture, currency,
                                   description, idempotency-key (header)" }
    C2 representation injectivity  Satisfied
    C3 strict idempotency          ClientDependent { how: "send the optional
                                   `idempotency-key` on every request" }
    C4 contextual state pinning    Unknown { why: "no precondition mechanism
                                   is described..." }
```

Read that as three different kinds of statement:

| Verdict | What it means for you |
| :-- | :-- |
| `Satisfied` | Nothing to do. |
| `ClientDependent` | Your API is fine **if** every client volunteers something it is not obliged to. One client that forgets reopens the hole. |
| `Failed` | No well-behaved client can work around this. Change the interface. |
| `Unknown` | The document cannot answer. Usually C1 or C4. Not a pass — go look at the code. |

`Unknown` is the one people misread. It does not mean "probably fine." C1 and
C4 are properties of your implementation, and no document reveals them. If
`classify` says `Unknown` for C4, the question "does this effect depend on
state that could move between signing and execution?" is one only you can
answer, by reading your handler.

Exit code is 1 if any operation is `NonQualifying`, so this drops into CI.

### Step 2 — fix what you can in the endpoint

In rough order of value for effort:

**Decode strictly, then canonicalize, then verify the signature.** Not after.
This is the cheapest change in the whole project and it closes C2 outright.
If your authorization service and your endpoint both parse JSON, they must
parse it the same way, and "the same way" has to mean RFC 8785 rather than
"both use the default library." Use `transit::json::parse_strict` and
`transit::canonicalize` as a reference for exactly which inputs to reject.

**Stop defaulting from server-side state.** Every `ClientDependent` on C1 is a
field your server fills in when the client omits it. Make it required, or make
the omission mean one fixed value that never depends on the account. If you
cannot do either, you cannot close C1 at the endpoint, and step 3 is your
fallback.

**Require an idempotency key, and keep it separate from your auth nonce.**
This is the single most common real failure. If you already have replay
protection, you are probably reusing that nonce to deduplicate business
operations, and those are different jobs — see §1 of the paper for why the
composition breaks. Two identifiers: one that changes on every retry, one that
names the operation and does not.

**Accept `If-Match`.** Wherever the effect depends on current state, let the
client say which state it assumed, and refuse with 412 when it has moved.

### Step 3 — enforce what you cannot fix, at the boundary

If you cannot change the endpoint quickly — someone else owns it, or it is
third-party, or the change is a six-month migration — put the proxy in front
of it. Generate its configuration from the same specification:

```bash
transit classify --spec ./your-openapi.json --emit-guard-config > guard.toml
```

That writes a real config, with the C1 parameters named and typed, plus
comments marking what it cannot cover. **Read it before you run it** — it will
refuse traffic that works today. Then:

```bash
$EDITOR guard.toml          # set `upstream`, and review every route
transit guard --config guard.toml
```

The proxy prints what it is actually enforcing on startup. Believe that line,
not the comments in the config file.

Know what you are getting, because it is not everything:

- **C2 is closed unconditionally.** Duplicate keys, lone surrogates,
  noncharacters and unbounded numbers cannot reach your upstream, and what
  does reach it is the canonical form.
- **C1 is closed only for the parameters named in `require_parameters`.** That
  is why generating the config from the spec matters; hand-written lists are
  where this gets forgotten.
- **C3 and C4 are demanded, not verified.** The proxy insists the headers are
  present. Whether your upstream honours them is not something a proxy can
  check.
- **Alias collapse is not closed at all.** `/v1/users/me` and
  `/v1/users/usr_99812` are one resource under two names, and a proxy cannot
  know that. Fix it in the endpoint or accept it.

`docs/DEPLOYING.md` covers the operational side: containers, TLS expectations,
what each status code means, per-route relaxation.

---

## 2. I write the client, or the agent

You do not control the endpoint. You want your requests to mean one thing.

**Send every optional parameter, explicitly, every time.** Whatever
`classify` lists under a `ClientDependent` C1 is your checklist. The whole
point of that verdict is that the endpoint is safe only if you do this, and
defaults you did not send are values you did not authorize.

**Send a business idempotency key on every non-idempotent call, and keep it
constant across retries.** Your HTTP library's retry logic will not do this
for you. If your framework rotates an auth nonce per attempt — most do — then
the key must be a separate value that does not rotate.

**Send `If-Match` when the endpoint supports it.**

**Canonicalize before you sign.** If you sign the bytes you happened to
serialize, and the endpoint reads them with a different decoder, you have
signed something other than what will happen.

```rust
use transit::{parse_strict, canonicalize, digest};

let doc = parse_strict(&body)?;        // refuses what RFC 7493 refuses
let bytes = canonicalize(&doc)?;       // RFC 8785
let d = digest(&doc)?;                 // sign this
```

And one thing to accept rather than solve: if a call fails with no response,
you do not know whether it happened. An idempotency key makes it safe to ask
again. It does not make the ambiguity go away. Design for a state where you
must reconcile.

---

## 3. I want to see the failure before I believe in it

Reasonable.

```bash
docker compose up -d
./scripts/demo.sh
```

Sends one payload — `{"to":"acct-legit","amount":100,"to":"acct-attacker"}` —
at the raw endpoint and then at the same endpoint behind the proxy. Direct, it
pays the attacker. Through the proxy, 400. The script asserts both halves and
fails loudly if the attack ever stops working against the bare endpoint,
because a demo that silently proves nothing is worse than none.

Without Docker:

```bash
transit fuzz --scenario all-hostile      # the attacks, against a bad endpoint
transit fuzz --scenario boundable        # the same attacks, against a good one
transit differential                      # where the JSON decoders on your machine disagree
```

Run those two `fuzz` commands together. The first finds things; the second
finds nothing but still prints the retry residual, which is the part no
endpoint fix removes.

---

## What this tool will not do for you

- **It will not tell you your API is safe.** `classify` reads documents. C1
  and C4 live in your code.
- **`probe` does not yet work against arbitrary APIs.** Its checks address
  this repository's own routes. Against a real API it reports that the checks
  did not apply rather than that you are clean — that distinction is
  deliberate, but the feature is unfinished.
- **It does not handle multi-step workflows.** One message, one effect. If
  your agent chains five calls and each depends on the last, that is an open
  research question, not a gap in the CLI.

## Command reference

| Command | Network | Use it for |
| :-- | :-- | :-- |
| `classify --spec` | none | Is this API effect-bindable? Which condition fails? |
| `classify --emit-guard-config` | none | Turn that answer into proxy configuration |
| `differential` | none | Do the JSON decoders on this host disagree? |
| `fuzz` | none | Reproduce the attacks against the bundled endpoint |
| `guard --config` | proxies | Enforce the conditions in front of an upstream |
| `serve-hostile` | local | The deliberately broken endpoint, for demos and tests |
| `survey` | none | The 24-endpoint desk study, with its caveat attached |
| `probe` | **yes, gated** | Live probing. Requires written authorization |
