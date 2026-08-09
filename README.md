<p align="center">
  <img src="assets/banner.svg" alt="transit — signing the bytes is not signing the deed" width="100%">
</p>

<p align="center">
  <img alt="Rust 2021" src="https://img.shields.io/badge/rust-2021%20%C2%B7%201.90%2B-CFFF04?style=flat-square&labelColor=0A0A0A">
  <img alt="tests passing" src="https://img.shields.io/badge/tests-passing-CFFF04?style=flat-square&labelColor=0A0A0A">
  <img alt="Apache 2.0" src="https://img.shields.io/badge/licence-Apache--2.0-CFFF04?style=flat-square&labelColor=0A0A0A">
  <img alt="3 of 13 tasks" src="https://img.shields.io/badge/build-3%20of%2013%20tasks-8F8A82?style=flat-square&labelColor=0A0A0A">
</p>

---

## "The signature covers the request"

It does. That is the problem.

A signed capability binds a byte sequence. The security proofs for capability
systems — macaroons, Biscuit, OAuth Rich Authorization Requests, token binding,
every "signed intent" scheme in agent tooling — establish exactly that, and no
more. The marketing says the endpoint performs the action that was approved.
Those are different claims, and you can watch them come apart in about four
seconds.

RFC 8785 prohibits duplicate JSON object keys. Real decoders disagree about
what to do anyway. Go and Node keep the **last**. Elixir keeps the **first**.
None of them refuses.

```console
$ cargo run --example duplicate_key

wire payload (one byte sequence, signed once):
  {"to":"acct-legit","amount":100,"to":"acct-attacker"}

policy engine  (first-key-wins) authorizes a transfer to: acct-legit
backend        (last-key-wins)  executes  a transfer to: acct-attacker

canonical form each side believes it signed:
  policy   {"amount":100,"to":"acct-legit"}
  backend  {"amount":100,"to":"acct-attacker"}

...and therefore two different digests over the same wire bytes:
  policy   54c323d30a388a17cd45ccb995606888bb7e5f3999fd4c422dfd9ad654f3f080
  backend  a7713be516575c5d5156c126fd6cb060b9aa1fe0dbcabb2553f8fd37cec6ffc8

strict I-JSON ingestion refuses the payload outright:
  duplicate object key `to` at byte 32; RFC 8785 forbids duplicate keys
```

The signature verifies. The nonce is fresh. Nobody replayed anything. **Every
step is individually correct and the composition is exploitable**, which is
exactly why message-level proofs miss it: there is no step to blame.

That last line is also the fix, and it is the cheapest one in the field —
reject non-canonical input *before* verifying the signature, not after.

---

## What transit does

You give it an endpoint — an OpenAPI document, or a live target you are
authorized to probe. It reports whether binding a message to that endpoint
binds an *effect*, against four separately checkable conditions:

| | Condition | Fails when |
| :-- | :-- | :-- |
| **C1** | Parameter completeness | the endpoint fills an omitted field from state the signature never covered |
| **C2** | Representation injectivity | two wire forms with one digest induce different effects — parser differentials, URI aliases |
| **C3** | Strict idempotency | the authorization nonce is conflated with the business idempotency key |
| **C4** | Contextual state pinning | a concurrent mutation between check and use changes the effect instead of aborting |

The conditions are **sufficient**. This project is careful not to claim they
are necessary — an endpoint could achieve effect binding by other means, and
that direction has not been proved. Getting this right is a small point of
rigour a reviewer will absolutely test.

---

## Two results we did not expect

### The canonicalizer cannot be written the obvious way

RFC 8785 says numbers serialize per ECMA-262 `Number::toString`. It also says
*including the "Note 2" enhancement* — round half to even. Rust's own float
formatting rounds half away from zero. Nobody notices, because the two agree
almost always.

```console
$ cargo run --example tie_break

one IEEE-754 double, bit pattern 43143ff3c1cb0959

Rust's own float formatting   1424953923781206.3
RFC 8785 Appendix B requires  1424953923781206.2
                              ^ they disagree in the last digit

digest over the canonical form   e1547479d27f057e3197d49417a1dcbe19dd8781b34fa9f83b789925943d00cb
digest had we written it naively 38d2e996c847955502d2489bc8274bc3b07abf3fdb508bf169b098e4332b6f02
```

**10,762 disagreements in 4,979,995 doubles — 0.216%.** Each one is a
capability that verifies on one implementation and fails on another, over a
value both sides parsed identically. The whole of RFC 8785 Appendix B is in the
test suite; its last row exists for no other reason than this.

### The survey we were handed does not add up

The desk study behind this work classified 24 production endpoints against
C1–C4 and reported the split as 4 qualified / 6 conditional / 14 non-qualifying.
Transcribing its own table to assert those counts in code gives **4 / 7 / 13**.

Square `POST /v2/payments` is classified conditional in the table, is missing
from the 25% count, and is absorbed into the 58% one. The table's own example
lists show it — six conditional examples against a claimed six, thirteen
non-qualifying against a claimed fourteen. The rows were right; the arithmetic
over them was not, and the corrected figure is now in the research note.

Nothing was found by being clever. It was found because the survey loader
asserts its counts against the transcribed rows, so a figure *cannot* drift
from the data behind it.

---

## Try it

```bash
git clone https://github.com/Task-force-for-AI-agents-in-Healthcare/transit
cd transit
cargo run --example duplicate_key
cargo run --example tie_break
```

Or the whole argument in one command — the vulnerable endpoint, the guard in
front of it, and the same payload sent at each:

```bash
docker compose up -d
./scripts/demo.sh
```

Straight at the endpoint, the payload pays `acct-attacker`. Through the guard,
it is refused with 400 and the upstream ledger shows one transfer: the
unguarded one. The script asserts both halves and exits 1 if either fails —
including if the attack stops working against the bare endpoint, since a
demonstration that silently proves nothing is worse than none.
[`docs/DEPLOYING.md`](docs/DEPLOYING.md) is the operator's guide, and it starts
with what the guard does *not* do.

Rust 2021, toolchain floor 1.90. No panics on malformed input — this crate eats
hostile input by design, so that is a tested guarantee rather than an
aspiration, asserted directly against deeply nested documents, truncated
escapes, lone surrogates and `i128::MIN`.

## The six commands

**All fifteen tasks are merged.** Every command below runs today. This table
is the design, and the ticks are the authority.

| | | |
| :-- | :-- | :-- |
| ✅ | *library* | strict I-JSON parser, RFC 8785 canonicalizer, five decoder models, the observation format |
| ✅ | `differential` | one payload, every decoder on the host, **zero network at all** |
| ✅ | `serve-hostile` | a server built to fail — five failure modes, each toggleable alone |
| ✅ | `fuzz` | reproduce the defaulting bypass and both horns of the retry ambiguity |
| ✅ | `classify` | OpenAPI → C1–C4 → Qualified / Conditional / Non-qualifying, naming what failed |
| ✅ | `guard` | an enforcing reverse proxy that refuses what the conditions forbid |
| ✅ | `probe` | live probing, gated — see below |

`probe`'s gate and its transport are built and tested; the checks it runs are
still the ones written for this repository's own routes, so against a real API
it reports that the checks did not apply rather than that the endpoint is
clean. Per-target route configuration is not built.

Everything except `probe` runs offline with no credentials, against a hostile
endpoint that ships in the repository. The reproductions the paper rests on
never touch a third party.

## Live probing is gated

`probe` is the only command that can reach a third-party network, and it
refuses unless **all** of the following hold: `--live` and `--i-am-authorized`
are both given and each is checked separately; every target declares
`authorization = "own-account"` or `"written-permission"`, with no default and
no third value; every target declares a `contact` the probed party could use to
tell you to stop; and the config parses with unknown fields rejected, so a
misspelled key is a loud error rather than a setting that quietly is not there.
Otherwise it exits **3** with an explanation. Rate-limited to 10 requests a
minute by default.

`fuzz --target` is *not* gated, so it refuses any URL that is not loopback — it
sends the same adversarial traffic, including a deliberate double execution,
and labels its findings as coming from this repository's own hostile endpoint.
That label would be a lie about a stranger's server.

Defence in depth, not a guarantee. **The operator is responsible for what this
sends.**

---

## What is real, and what is not

This project is about not overclaiming, so:

**Real.** The strict I-JSON parser and the RFC 8785 canonicalizer, tested
against the specifications — including all 24 serializable vectors of Appendix
B. Divergences reported between language runtimes are *measured*, by executing
those runtimes on the host that ran them.

**Modelled.** Five configurations model production decoders. Four (Go, Node,
Python, Ruby) report `RuntimeInstalled` in their provenance whenever the real
runtime is found on this host — and that label means exactly what it says and
no more: the runtime is *present*, not that it *agrees*. Agreement is a
separate, falsifiable claim that only `tests/model_fidelity.rs` makes, by
actually running the shared corpus against the runtime and failing if a model
and its runtime disagree; the label itself is derived purely from discovery
(`present.iter().any(...)`) and cannot see that test's result. (An earlier
name for this label, `CrossChecked`, claimed agreement it had no way to know
at the point it was produced — renamed after a fix round measured two of the
four models disagreeing with their runtime while both still carried it.)
**The Elixir model carries no such label at all** — no Elixir runtime is
installed on this host, so `Config::elixir_otp_json()` is labelled
`Unverified` everywhere it appears in this crate, even though it has in fact
been measured out-of-band, once, on GCP (`results/elixir-measurement.txt`);
that measurement is not wired into the crate's automatic provenance, so the
in-crate label stays conservative regardless. Every label here is *derived*
from what discovery actually found, never hard-coded: on a machine with none
of the four installed, every model reports itself unverified. A tool claiming
measurements it never made would be committing the exact error it exists to
expose.

**Hypothesis, not data.** The 24-endpoint survey is a documentation review.
Every row is tagged `DeskStudy`, no code path can promote a row to `LiveProbed`
without an actual probe run, and the tool refuses to print the table without
saying so.

**Stricter than the RFCs, deliberately.** The strict configuration rejects
integers outside ±(2⁵³−1) even when exactly representable, so it refuses `1e20`
— which RFC 7493 and RFC 8785 both permit. §2.2's `SHOULD NOT` covers magnitude
or precision *beyond* a double, and `1e20` is not that. Fail-closed is a
defensible policy for an authorization pipeline; pretending the RFCs require it
would not be.

**The limit that matters.** Classifying an endpoint from its OpenAPI document
is a claim about the *document*. C1 and C4 are properties of an implementation,
and no specification reveals server-side defaulting. That is why `Unknown` is a
first-class verdict, why every verdict carries an evidence tag, and why live
probing — not classification — is what would turn this survey into evidence.
**That probing has not been done.** If you take one thing from this repository,
take that rather than the duplicate-key demo.

---

## How this maps to the standard

transit is a research tool for the
[**Proof-of-Control Standard**](https://github.com/AAI-Society/ov-poc-standard).
It contradicts three of its claims and supplies two things it is missing:

| | Standard | |
| :-- | :-- | :-- |
| ⚠️ | **Theorem 1** — *execution fidelity*: an adversary cannot make a relying party perform an action other than the one evaluated | the proof binds the *message*. No snapshot-to-effect relation is ever defined. Holds only given C1–C4 |
| ⚠️ | **C7.1.4** — three complete-mediation options presented as alternatives | they are not equally strong. Option (b), un-attested local normalization, cannot guarantee effect binding and should be demoted below (c) and (a) |
| ⚠️ | **C7.1.5** — Tier 1–2 only, as the exception | it is the majority. 13 of 24 surveyed endpoints fail both idempotency and parameter completeness |
| ◻︎ | **A parser mandate** — currently absent | authorization pipelines MUST use strict RFC 8785 ingestion, rejecting duplicate keys, lone surrogates and unbounded numerics *before* signature verification |
| ◻︎ | **A named condition per claim** — conformance claims do not say what they rest on | every verdict names the specific condition that failed, so a verifier can tell which of C1–C4 is load-bearing |

⚠️ is a contradiction; ◻︎ is a gap this tool is being built to fill and has not
filled yet. The duplicate-key contradiction is demonstrated above and runs. The
retry ambiguity and the survey split are argued from the research note, not yet
reproduced by this tool — the hostile endpoint that would reproduce them is
task seven of thirteen.

## The paper

**Not written yet.** *From Message Authorization to Effect Binding: Conditions,
Counterexamples, and a Conformance Harness* is the last task in the plan, and
the results sections will read generated LaTeX from `results/` rather than
hand-typed numbers — CI regenerates them and fails on drift, so a figure in the
paper cannot disagree with the code that produced it.

Its sibling, [**A Trust Calculus for Attestation
Tiers**](https://github.com/Task-force-for-AI-agents-in-Healthcare/parallax/blob/main/paper/main.pdf),
is finished and shows the shape this one will take.

## Related

Three tools, named for the observational-astronomy method each one uses:

- **[parallax](https://github.com/Task-force-for-AI-agents-in-Healthcare/parallax)** — depth from two viewpoints. Computes the residual trust set of an attestation deployment.
- **transit** — infer a hidden body from what it does to passing light. This one.
- **occultation** — one body deliberately hiding another. Measures what unlinkability costs at agent action rates.

## Licence

Apache-2.0 throughout, code and paper alike. Built for the
[Advanced AI Society](https://advancedaisociety.org) Proof-of-Control initiative —
see [**AAI-Society/ov-poc-standard**](https://github.com/AAI-Society/ov-poc-standard).

<p align="center"><img src="assets/logo.svg" width="52" alt=""></p>
