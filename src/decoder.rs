use crate::json::{parse, Config, Json, Num, Utf16};
use serde::Serialize;

/// What a decoder did with a payload.
///
/// `Rejected` carries no detail on purpose: two decoders that both refuse a
/// payload agree, and their error wording must not manufacture a divergence.
/// The human-readable reason travels beside it in `DecoderReport::detail`.
/// A struct variant, not `Value(String)`. Serde's internally-tagged
/// representation cannot serialize a newtype variant wrapping a string: it
/// compiles and then fails at runtime with "cannot serialize tagged newtype
/// variant". That would have killed every `--format json` path, and with it
/// `results/` and the CI diff gate, at the first run.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Observation {
    Value {
        rendered: String,
    },
    Rejected,
    /// The decoder never got a chance to accept or refuse the payload: the
    /// runtime itself failed to run (a bad spawn, output `differential`
    /// could not parse, ...). Distinct from `Rejected` on purpose — fix
    /// round 1, C1: a version of this crate once folded that case into
    /// `Rejected`, so a runtime that merely crashed was reported as having
    /// agreed with every other decoder that genuinely refused the payload,
    /// silently inflating the tool's own agreement count.
    /// `differential::classify` excludes `Unavailable` from every
    /// comparison — it is an absence, not a data point about the payload —
    /// so it can neither create nor hide a divergence on its own. See
    /// `differential::observe_all`.
    Unavailable,
}

/// Where a decoder's behaviour comes from, and therefore how much a reader
/// should believe it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Provenance {
    /// Implemented in this crate and exercised directly.
    InCrate,
    /// A language runtime installed on this host, executed as a subprocess.
    External { runtime: String, version: String },
    /// A configuration that models a decoder written elsewhere.
    Modelled {
        models: String,
        verification: ModelVerification,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ModelVerification {
    /// The modelled runtime is installed on this host — nothing more. This
    /// is presence, not agreement: `modelled()` awards it purely from
    /// `present.iter().any(...)`, so a model can carry `RuntimeInstalled`
    /// while still disagreeing with the runtime it claims to model.
    /// Agreement is a separate, falsifiable claim made only by
    /// `tests/model_fidelity.rs` actually running the corpus against the
    /// runtime — this label must never be read as asserting it.
    ///
    /// Fix round 1, C5: this variant was previously named `CrossChecked`
    /// and documented as "installed here and agreed with the model on the
    /// whole corpus," a claim this crate had no way to back up at the point
    /// the label is produced. Measured directly on this host: all four
    /// runtimes reported that stronger label while two of the four models
    /// (Python, Ruby) demonstrably disagreed with their runtimes — a false
    /// provenance claim from the one tool whose entire purpose is not to
    /// make those. Renamed rather than patched, so the label can no longer
    /// be misread as a correctness guarantee.
    RuntimeInstalled,
    /// The runtime is not installed here, so this behaviour is a claim taken
    /// from documentation — the kind of claim this tool exists to distrust.
    Unverified { why: String },
}

#[derive(Clone, Debug, Serialize)]
pub struct DecoderReport {
    pub id: String,
    pub provenance: Provenance,
    /// Keyed by meaning. This is what `differential` groups on.
    pub observation: Observation,
    /// Keyed by representation. Reported alongside, never grouped on: two
    /// decoders storing one value differently have not disagreed.
    pub representation: Option<String>,
    /// Diagnostics only. Excluded from every comparison.
    pub detail: Option<String>,
}

/// Which identity a rendering is keyed by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    /// What the document *means*. Numbers are keyed by their canonical
    /// serialization, so `100` and `100.0` are one value.
    Material,
    /// How the decoder *represented* it. Numbers keep their type and bit
    /// pattern, so an exact integer and a rounded double are distinguishable.
    Exact,
}

/// The comparison key: identical when two decoders agree about what a payload
/// means, different when they do not, and never different for reasons of
/// spelling or of the host language's type model.
///
/// * a number is `N:<its RFC 8785 canonical form>`. Keying by value rather
///   than by representation is the whole point: Python parses `100` to an
///   exact integer and Node to a double, and those decoders have **not**
///   disagreed about anything. Keying by type would have made every payload
///   containing any integer a Python-versus-Node divergence, drowning the
///   real finding — that `9007199254740993` rounds to `...992` — in noise,
///   and inflating every divergence count the paper quotes.
/// * a string is `S:<UTF-16 code units>`, which represents a lone surrogate
///   rather than hiding it
/// * object members are sorted, because member order is not a decoder
///   difference; array order is preserved, because it is
///
/// `render_exact` keeps the representation, and `differential` reports the
/// two separately: a material divergence is a disagreement about meaning, a
/// representation divergence is a disagreement about storage.
pub fn render(v: &Json) -> String {
    render_with(v, Key::Material)
}

pub fn render_exact(v: &Json) -> String {
    render_with(v, Key::Exact)
}

pub fn render_with(v: &Json, key: Key) -> String {
    match v {
        Json::Null => "null".to_string(),
        Json::Bool(b) => b.to_string(),
        // `es_number`, never the canonicalizer's `canonical_number`. The
        // canonical form coerces an integer to a double for RFC 8785
        // conformance, which is right for what a capability signs and wrong
        // here: it would make Python's exact `9007199254740993` and Node's
        // rounded `…992` compare equal and delete the corpus's central
        // numeric finding.
        Json::Number(n) => match key {
            Key::Material => {
                // `es_number` renders `Int` as exact decimal and `Float` via
                // ECMAScript `Number::toString`, which switches to exponent
                // notation at |x| >= 1e21. Below that cutoff the two forms
                // already agree; at and above it, an `Int` that is bit-
                // identical to some `Float` (e.g. 10^21 = 2^21*5^21, and
                // 5^21 < 2^53) would otherwise render as exact decimal
                // while the equal-valued double renders in exponent form —
                // a pure formatting-convention split, indistinguishable in
                // the output from a genuine precision-loss finding like
                // `9007199254740993`, and one that would even split a
                // single decoder against itself. So an `Int` that
                // round-trips exactly through `f64` is rendered the way
                // that same-valued double would be; an `Int` that does
                // *not* round-trip (the actual 2^53 finding) keeps the
                // exact-decimal path, so it still differs from the rounded
                // double it was not equal to.
                let as_float = match n {
                    Num::Int(i) if (*i as f64) as i128 == *i => Some(Num::Float(*i as f64)),
                    _ => None,
                };
                let target = as_float.as_ref().unwrap_or(n);
                match crate::jcs::es_number(target) {
                    Ok(s) => format!("N:{s}"),
                    // Reachable: no `Config` in this crate rejects an
                    // out-of-range exponent, so `parse("1e400", ..)` yields
                    // `Float(INFINITY)`. Signed and kinded rather than one
                    // shared sentinel, so `1e400` and `-1e400` — which
                    // `render_exact` already tells apart — do not collapse
                    // into one material key.
                    Err(_) => match target {
                        Num::Float(f) if f.is_nan() => "N:!nan".to_string(),
                        Num::Float(f) if f.is_sign_negative() => "N:!-inf".to_string(),
                        Num::Float(_) => "N:!inf".to_string(),
                        // Unreachable — `es_number` never errors on `Int` —
                        // but recorded rather than panicked.
                        Num::Int(_) => "N:!non-finite".to_string(),
                    },
                }
            }
            Key::Exact => match n {
                Num::Int(i) => format!("I:{i}"),
                Num::Float(f) => format!("F:{:016x}", f.to_bits()),
            },
        },
        Json::String(u) => render_string(u),
        Json::Array(a) => {
            let parts: Vec<String> = a.iter().map(|x| render_with(x, key)).collect();
            format!("[{}]", parts.join(","))
        }
        Json::Object(m) => {
            let mut parts: Vec<(String, String)> = m
                .iter()
                .map(|(k, val)| (render_string(k), render_with(val, key)))
                .collect();
            // Sorted by key, not by the whole `key=value` string. The
            // external helpers emit the representation form and Rust
            // materializes it afterwards, so a sort that depended on the
            // value would put members in a different order on the two paths
            // and manufacture a divergence out of nothing. Keys are unique
            // here — the parser has already resolved duplicates — so the key
            // order is total.
            parts.sort_by(|a, b| a.0.cmp(&b.0));
            let joined: Vec<String> = parts.into_iter().map(|(k, v)| format!("{k}={v}")).collect();
            format!("{{{}}}", joined.join(","))
        }
    }
}

/// Rewrite an exact observation into the material key.
///
/// The external helpers emit only the representation form: `String(v)` is
/// already ECMAScript `Number::toString` in JavaScript, but computing an
/// RFC 8785 number in Go, Python and Ruby would mean reimplementing Ryū three
/// more times, in languages where a mistake would be invisible. The exact
/// form carries the full IEEE-754 bit pattern, so the material key is
/// recoverable in Rust — where it is computed once, by the same function the
/// canonicalizer uses.
pub fn materialize(exact: &str) -> String {
    fn flush(token: &mut String, out: &mut String) {
        if let Some(d) = token.strip_prefix("I:") {
            match d.parse::<i128>() {
                Ok(v) => out.push_str(&render(&Json::Number(Num::Int(v)))),
                Err(_) => out.push_str(token),
            }
        } else if let Some(h) = token.strip_prefix("F:") {
            match u64::from_str_radix(h, 16) {
                Ok(bits) => out.push_str(&render(&Json::Number(Num::Float(f64::from_bits(bits))))),
                Err(_) => out.push_str(token),
            }
        } else {
            out.push_str(token);
        }
        token.clear();
    }

    let mut out = String::with_capacity(exact.len());
    let mut token = String::new();
    for c in exact.chars() {
        if matches!(c, ',' | '=' | '[' | ']' | '{' | '}') {
            flush(&mut token, &mut out);
            out.push(c);
        } else {
            token.push(c);
        }
    }
    flush(&mut token, &mut out);
    out
}

fn render_string(u: &Utf16) -> String {
    let units: Vec<String> = u.iter().map(|c| format!("{c:04x}")).collect();
    format!("S:{}", units.join(","))
}

/// Named because `clippy::type_complexity` is denied by `-D warnings` and
/// fires on the inline form, which fails the build.
type DecodeFn = Box<dyn Fn(&str) -> Result<Json, String> + Send + Sync>;

pub struct InCrateDecoder {
    pub id: String,
    pub provenance: Provenance,
    decode: DecodeFn,
}

impl InCrateDecoder {
    pub fn observe(&self, payload: &str) -> DecoderReport {
        match (self.decode)(payload) {
            Ok(v) => DecoderReport {
                id: self.id.clone(),
                provenance: self.provenance.clone(),
                observation: Observation::Value {
                    rendered: render(&v),
                },
                representation: Some(render_exact(&v)),
                detail: None,
            },
            Err(why) => DecoderReport {
                id: self.id.clone(),
                provenance: self.provenance.clone(),
                observation: Observation::Rejected,
                representation: None,
                detail: Some(why),
            },
        }
    }
}

fn cfg_decoder(id: &str, provenance: Provenance, cfg: Config) -> InCrateDecoder {
    InCrateDecoder {
        id: id.to_string(),
        provenance,
        decode: Box::new(move |s: &str| parse(s, cfg).map_err(|e| e.to_string())),
    }
}

/// `RuntimeInstalled` is **derived**, never asserted.
///
/// A hard-coded `RuntimeInstalled` would have this crate report all four
/// models as installed on a host with no Go, Node, Python or Ruby installed —
/// an unverified claim presented as a measurement, which is precisely the
/// failure this tool exists to expose. `runtime` names the discovery id that
/// has to be present for the label to hold. Note what this label does *not*
/// claim: agreement with the runtime. That is `tests/model_fidelity.rs`'s
/// job, not this function's — see `ModelVerification::RuntimeInstalled`'s
/// doc comment.
fn modelled(
    id: &str,
    models: &str,
    runtime: &str,
    present: &[String],
    cfg: Config,
) -> InCrateDecoder {
    let verification = if present.iter().any(|p| p == runtime) {
        ModelVerification::RuntimeInstalled
    } else {
        ModelVerification::Unverified {
            why: format!(
                "no {runtime} runtime was found on this host, so this model has not been measured"
            ),
        }
    };
    cfg_decoder(
        id,
        Provenance::Modelled {
            models: models.to_string(),
            verification,
        },
        cfg,
    )
}

/// Every decoder that needs no subprocess.
///
/// Reports every model as `Unverified`, which is the conservative default: a
/// caller that has not looked for the runtimes cannot claim they agreed.
/// `differential` calls `in_crate_verified_against` with what discovery
/// actually found.
pub fn in_crate() -> Vec<InCrateDecoder> {
    in_crate_verified_against(&[])
}

pub fn in_crate_verified_against(present: &[String]) -> Vec<InCrateDecoder> {
    vec![
        cfg_decoder("strict-ijson", Provenance::InCrate, Config::strict()),
        InCrateDecoder {
            id: "serde_json".to_string(),
            // Not a model: an independently written implementation that
            // happens to live in this process.
            provenance: Provenance::InCrate,
            decode: Box::new(|s: &str| {
                serde_json::from_str::<serde_json::Value>(s)
                    .map_err(|e| e.to_string())
                    .map(|v| from_serde(&v))
            }),
        },
        modelled(
            "model:go-encoding-json",
            "Go encoding/json",
            "go",
            present,
            Config::go_encoding_json(),
        ),
        modelled(
            "model:node-json-parse",
            "Node JSON.parse",
            "node",
            present,
            Config::node_json_parse(),
        ),
        modelled(
            "model:python-json",
            "CPython json",
            "python",
            present,
            Config::python_json(),
        ),
        modelled(
            "model:ruby-json",
            "Ruby JSON",
            "ruby",
            present,
            Config::ruby_json(),
        ),
        cfg_decoder(
            "model:elixir-otp-json",
            Provenance::Modelled {
                models: "Elixir OTP :json".to_string(),
                verification: ModelVerification::Unverified {
                    // Fix round 1 (M11): this used to say the behaviour "has
                    // not been measured," full stop — false as of
                    // `results/elixir-measurement.txt`, which measured
                    // first-key-wins directly on elixir 1.17.3 / OTP 27 on
                    // GCP. What is true, and the only thing this label may
                    // claim, is that it was not measured *on this host* —
                    // no Elixir runtime is installed here, so this crate has
                    // no way to check the model against reality locally,
                    // regardless of what was confirmed elsewhere.
                    why: "no Elixir runtime is installed on this host, so this behaviour \
                          has not been measured on this host; see \
                          `results/elixir-measurement.txt` for the GCP measurement \
                          this model is otherwise based on"
                        .to_string(),
                },
            },
            Config::elixir_otp_json(),
        ),
    ]
}

fn from_serde(v: &serde_json::Value) -> Json {
    use serde_json::Value as V;
    match v {
        V::Null => Json::Null,
        V::Bool(b) => Json::Bool(*b),
        V::Number(n) => {
            if let Some(i) = n.as_i64() {
                Json::Number(Num::Int(i as i128))
            } else if let Some(u) = n.as_u64() {
                Json::Number(Num::Int(u as i128))
            } else {
                // serde_json only reaches here for a float, so `as_f64`
                // cannot fail; NaN is nonetheless a value, not a panic.
                Json::Number(Num::Float(n.as_f64().unwrap_or(f64::NAN)))
            }
        }
        V::String(s) => Json::String(s.encode_utf16().collect()),
        V::Array(a) => Json::Array(a.iter().map(from_serde).collect()),
        V::Object(m) => Json::Object(
            m.iter()
                .map(|(k, val)| (k.encode_utf16().collect(), from_serde(val)))
                .collect(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::{parse, parse_strict, Config};

    fn obs(src: &str, cfg: Config) -> Observation {
        match parse(src, cfg) {
            Ok(v) => Observation::Value {
                rendered: render(&v),
            },
            Err(_) => Observation::Rejected,
        }
    }

    #[test]
    fn semantically_identical_inputs_compare_equal() {
        // The load-bearing direction of the identity rule, and the one a
        // wrong implementation passes by accident far less often. Python
        // parses `100` to an exact integer and Node to a double; they have
        // not disagreed about anything, and the key must say so.
        assert_eq!(
            render(&parse("100", Config::python_json()).unwrap()),
            render(&parse("100", Config::node_json_parse()).unwrap()),
            "an exact integer and a double of the same value are one meaning"
        );
        assert_eq!(
            render(&parse(r#"{"a":1,"b":2}"#, Config::python_json()).unwrap()),
            render(&parse(r#"{"b":2,"a":1}"#, Config::node_json_parse()).unwrap()),
            "member order is not a decoder difference"
        );
        // And a payload of nothing but integers must produce *no* divergence
        // across the whole in-crate set, which is the property that keeps the
        // corpus's real findings from drowning in type-model noise.
        let keys: std::collections::BTreeSet<String> = in_crate()
            .iter()
            .filter_map(
                |d| match d.observe(r#"{"amount":100,"id":7}"#).observation {
                    Observation::Value { rendered } => Some(rendered),
                    Observation::Rejected | Observation::Unavailable => None,
                },
            )
            .collect();
        assert_eq!(
            keys.len(),
            1,
            "every decoder agrees about a benign object: {keys:?}"
        );
    }

    #[test]
    fn a_rounded_integer_is_not_the_same_value_as_an_exact_one() {
        // The other direction: this is the divergence the corpus is built to
        // find, and it must survive keying by value.
        assert_ne!(
            render(&parse("9007199254740993", Config::python_json()).unwrap()),
            render(&parse("9007199254740993", Config::node_json_parse()).unwrap()),
            "Python keeps it, Node rounds it to ...992"
        );
    }

    #[test]
    fn an_exact_integer_past_the_exponent_cutoff_is_not_a_manufactured_divergence() {
        // 10^21 = 2^21 * 5^21 and 5^21 < 2^53, so it is exactly
        // representable as both an arbitrary-precision integer and an
        // IEEE-754 double — no decoder has rounded anything. But
        // `es_number` switches a `Float` to ECMAScript exponent notation at
        // |x| >= 1e21 while an `Int` still renders as exact decimal, so
        // naively keying an `Int` by its own decimal form would split this
        // bit-identical value into two material keys — a pure
        // formatting-convention divergence, indistinguishable in the output
        // from the genuine 9007199254740993 finding this test's neighbour
        // pins. It must not happen, in either direction: across decoders,
        // and within one arbitrary-precision decoder comparing the integer
        // and exponent spellings of the same value.
        let payload = "1000000000000000000000";
        assert_eq!(
            render(&parse(payload, Config::python_json()).unwrap()),
            render(&parse(payload, Config::node_json_parse()).unwrap()),
            "python's exact 10^21 and node's double 10^21 are one value"
        );
        assert_eq!(
            render(&parse(payload, Config::python_json()).unwrap()),
            render(&parse("1e21", Config::python_json()).unwrap()),
            "one arbitrary-precision decoder must not disagree with itself \
             over the spelling of one value"
        );
        // And the whole in-crate set must agree, the same property
        // `semantically_identical_inputs_compare_equal` checks for a benign
        // small integer.
        let body = format!(r#"{{"amount":{payload}}}"#);
        let keys: std::collections::BTreeSet<String> = in_crate()
            .iter()
            .filter_map(|d| match d.observe(&body).observation {
                Observation::Value { rendered } => Some(rendered),
                Observation::Rejected | Observation::Unavailable => None,
            })
            .collect();
        assert_eq!(keys.len(), 1, "every decoder agrees about 10^21: {keys:?}");
    }

    #[test]
    fn signed_infinity_and_nan_are_distinct_material_keys() {
        // No `Config` in this crate rejects an out-of-range exponent, so
        // `1e400` parses to `Float(INFINITY)` under any of the lenient
        // configs — this is reachable, not a theoretical case. `+Infinity`
        // and `-Infinity` are different values (and `render_exact` already
        // tells them apart via their bit patterns), so a single shared
        // non-finite sentinel would wrongly make them compare equal
        // materially.
        let pos = render(&parse("1e400", Config::node_json_parse()).unwrap());
        let neg = render(&parse("-1e400", Config::node_json_parse()).unwrap());
        assert_ne!(
            pos, neg,
            "+Infinity and -Infinity must not collapse to one key"
        );
        assert!(pos.contains("inf") && !pos.contains('-'), "{pos}");
        assert!(neg.contains("-inf"), "{neg}");
    }

    #[test]
    fn representation_is_recorded_even_where_meaning_agrees() {
        // Keyed by meaning they are equal; keyed exactly they are not, and
        // `differential` reports that as a representation difference rather
        // than as a disagreement.
        let py = parse("100", Config::python_json()).unwrap();
        let node = parse("100", Config::node_json_parse()).unwrap();
        assert_eq!(render(&py), render(&node));
        assert_ne!(render_exact(&py), render_exact(&node));
    }

    #[test]
    fn negative_zero_means_zero_and_is_recorded_as_distinct() {
        // RFC 8785 serializes -0 as 0, so they *mean* the same thing — which
        // is exactly why strict mode refuses the literal rather than letting
        // canonicalization quietly erase the sign.
        assert_eq!(
            render(&parse("-0.0", Config::node_json_parse()).unwrap()),
            render(&parse("0.0", Config::node_json_parse()).unwrap())
        );
        assert_ne!(
            render_exact(&parse("-0.0", Config::node_json_parse()).unwrap()),
            render_exact(&parse("0.0", Config::node_json_parse()).unwrap())
        );
        assert!(parse_strict("-0.0").is_err(), "and strict mode refuses it");
    }

    #[test]
    fn a_lone_surrogate_is_visible_in_the_observation() {
        let node = obs(r#"{"a":"\ud800"}"#, Config::node_json_parse());
        let go = obs(r#"{"a":"\ud800"}"#, Config::go_encoding_json());
        assert_ne!(node, go, "Node retains U+D800, Go substitutes U+FFFD");
        let Observation::Value { rendered } = &node else {
            panic!("Node parses it")
        };
        assert!(
            rendered.contains("d800"),
            "the surrogate survives: {rendered}"
        );
    }

    #[test]
    fn object_member_order_does_not_affect_the_observation() {
        assert_eq!(
            render(&parse_strict(r#"{"a":1,"b":2}"#).unwrap()),
            render(&parse_strict(r#"{"b":2,"a":1}"#).unwrap())
        );
    }

    #[test]
    fn array_order_does_affect_the_observation() {
        assert_ne!(
            render(&parse_strict("[1,2]").unwrap()),
            render(&parse_strict("[2,1]").unwrap())
        );
    }

    #[test]
    fn rejection_compares_equal_regardless_of_message() {
        // Two decoders that both refuse a payload agree, even though their
        // error text differs. Otherwise every strict decoder would appear to
        // diverge from every other strict decoder.
        assert_eq!(
            obs(r#"{"a":"\ud800"}"#, Config::strict()),
            obs(r#"{"a":"\ud800"}"#, Config::ruby_json())
        );
    }

    #[test]
    fn the_in_crate_set_covers_strict_serde_and_the_five_models() {
        let ds = in_crate();
        // Assert the size too. `contains` alone would pass with a stray
        // eighth decoder silently joining every differential.
        assert_eq!(ds.len(), 7, "strict, serde_json, and five models");
        let ids: Vec<&str> = ds.iter().map(|d| d.id.as_str()).collect();
        for want in [
            "strict-ijson",
            "serde_json",
            "model:go-encoding-json",
            "model:node-json-parse",
            "model:python-json",
            "model:ruby-json",
            "model:elixir-otp-json",
        ] {
            assert!(ids.contains(&want), "missing {want} in {ids:?}");
        }
    }

    fn verification_of(ds: &[InCrateDecoder], id: &str) -> ModelVerification {
        match &ds.iter().find(|d| d.id == id).expect("declared").provenance {
            Provenance::Modelled { verification, .. } => verification.clone(),
            other => panic!("{id} should be a model, got {other:?}"),
        }
    }

    #[test]
    fn runtime_installed_is_derived_from_discovery_not_asserted() {
        // The mutation that matters: with no runtimes found, *every* model
        // must report itself unverified. A hard-coded `RuntimeInstalled`
        // passes any test that only reads the shipped labels, and would
        // have this crate claim measurements it never made.
        for d in in_crate_verified_against(&[]) {
            if let Provenance::Modelled { verification, .. } = &d.provenance {
                assert!(
                    matches!(verification, ModelVerification::Unverified { .. }),
                    "{} claims verification with nothing installed",
                    d.id
                );
            }
        }
        // The zero-arg entry point every other caller uses must be the same
        // conservative default, not merely `in_crate_verified_against(&[])`
        // under another name: nothing above pins `in_crate()` itself, so a
        // mutation of its body (e.g. to hard-code some runtimes as present)
        // would pass every other assertion in this file.
        for d in in_crate() {
            if let Provenance::Modelled { verification, .. } = &d.provenance {
                assert!(
                    matches!(verification, ModelVerification::Unverified { .. }),
                    "{} claims verification via in_crate() with nothing installed",
                    d.id
                );
            }
        }
        // And with a runtime present, the model that names it flips — while
        // its neighbours do not.
        let ds = in_crate_verified_against(&["go".to_string()]);
        assert_eq!(
            verification_of(&ds, "model:go-encoding-json"),
            ModelVerification::RuntimeInstalled
        );
        assert!(matches!(
            verification_of(&ds, "model:node-json-parse"),
            ModelVerification::Unverified { .. }
        ));
    }

    #[test]
    fn the_elixir_model_can_never_report_runtime_installed_here() {
        // There is no Elixir candidate in `external::EXPECTED`, so no local
        // discovery result can promote it -- the out-of-band GCP
        // measurement in `results/elixir-measurement.txt` is not wired
        // into this crate's automatic provenance and does not change that.
        // Its label is a claim from documentation and must stay one.
        for present in [vec![], vec!["go".to_string(), "node".to_string()]] {
            let ds = in_crate_verified_against(&present);
            assert!(matches!(
                verification_of(&ds, "model:elixir-otp-json"),
                ModelVerification::Unverified { .. }
            ));
        }
    }

    #[test]
    fn serde_json_is_an_independent_implementation_not_a_model() {
        // Its agreement with a model is evidence; a model agreeing with
        // itself is not.
        let d = in_crate()
            .into_iter()
            .find(|d| d.id == "serde_json")
            .unwrap();
        assert!(matches!(d.provenance, Provenance::InCrate));
    }

    #[test]
    fn a_decoder_that_rejects_reports_why_without_it_affecting_equality() {
        let d = in_crate()
            .into_iter()
            .find(|d| d.id == "strict-ijson")
            .unwrap();
        let r = d.observe(r#"{"a":1,"a":2}"#);
        assert_eq!(r.observation, Observation::Rejected);
        assert!(r.detail.unwrap().contains("duplicate"));
    }

    #[test]
    fn materialize_recovers_the_material_key_from_the_exact_one() {
        // `materialize` has no test of its own in the brief because it is
        // Task 4's input path: the external helpers emit only
        // `render_exact`'s representation form, and Rust rewrites it back
        // into the material key that `differential` groups on. Pin the
        // round trip cheaply here rather than leave it unverified until
        // Task 4 exercises it through a subprocess.
        let docs = [
            r#"{"amount":100,"id":7}"#,
            "9007199254740993",
            "-0.0",
            "[1,2,3.5,-0.0]",
            r#"{"b":2,"a":1,"nested":{"x":true,"y":null}}"#,
            // An exact `Int` beside an equal-valued `Float` under different
            // keys: `S:0061` ("a") sorts before `S:0062` ("b") by key, but
            // their *values* (`N:100` for both) are equal, so a sort that
            // depended on the value would put "b" first here without
            // failing on any of the documents above. This is the sole
            // killer of that mutation.
            r#"{"a":100,"b":100.0}"#,
        ];
        for src in docs {
            let v = parse(src, Config::python_json()).unwrap();
            assert_eq!(
                materialize(&render_exact(&v)),
                render(&v),
                "materialize(render_exact(v)) must reproduce render(v) for {src}"
            );
        }
        // And with a lone surrogate, which is retained as a string token
        // that `materialize` must pass through untouched.
        let v = parse(r#"{"a":"\ud800"}"#, Config::node_json_parse()).unwrap();
        assert_eq!(materialize(&render_exact(&v)), render(&v));
    }
}
