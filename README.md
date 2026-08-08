# transit

Determines whether an endpoint satisfies the four conditions under which
binding a message binds an effect — and demonstrates, offline and with no
credentials, what goes wrong when it does not.

Supporting tool for **P02 — From Message Authorization to Effect Binding**.

## What is real and what is modelled

**Real.** The strict I-JSON parser and the RFC 8785 canonicalizer are
implemented here and tested against the specifications. The divergences
`transit differential` reports between language runtimes are *measured* on
the host that ran it, by executing those runtimes. The hostile server's
behaviour is real behaviour of a real server — it is simply a server that
was built to fail.

**Modelled.** Five decoder configurations model production decoders. Four of
them (Go, Node, Python, Ruby) are cross-checked against the real runtime
whenever it is installed, and `tests/model_fidelity.rs` fails if the model
and the runtime disagree. **The Elixir model is not cross-checked**: no
Elixir runtime is installed, so its behaviour here is a claim taken from
documentation, and the tool labels it `Unverified` everywhere it appears.

That label is *derived*, not written down. `CrossChecked` appears only when
discovery actually found the runtime, so on a machine with none of them
installed every model reports itself unverified. A hard-coded label would
have this tool claim a measurement it never made, which is the exact failure
it exists to expose.

**Hypothesis, not data.** The 24-endpoint survey in `survey/desk-study.toml`
is a *documentation-derived classification*, not a measurement. Every row is
tagged `DeskStudy`. No code path can promote a row to `LiveProbed` without a
live probe, and the tool refuses to print it without saying so.

**A limit worth stating plainly.** `transit classify` reads an OpenAPI
document. C1 and C4 are properties of an endpoint's *implementation*, and no
document reveals server-side defaulting. A `Qualified` verdict from a spec is
a claim about the spec, which is why the classifier has `Unknown` as a
first-class verdict and why every verdict carries its evidence tag.

## Licence

Apache-2.0 throughout, code and paper alike. See `LICENSE` and `NOTICE`.
