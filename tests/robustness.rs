//! This tool eats hostile input by design, so "no panics on malformed input"
//! has to be a tested guarantee rather than an aspiration. Every entry point
//! that a hostile party can reach is fed malformed input here.

use transit::classify::classify_spec;
use transit::corpus;
use transit::hostile::{handle, FailureModes, Ledger, Request};
use transit::jcs::canonicalize;
use transit::json::{parse, parse_strict, Config};

/// Inputs that are malformed in structurally different ways. Anything that
/// crashes on one of these crashes on a request some stranger can send.
fn hostile_inputs() -> Vec<String> {
    let mut v: Vec<String> = vec![
        String::new(),
        "{".into(),
        "}".into(),
        "[".into(),
        "null".into(),
        "\"unterminated".into(),
        r#"{"a":}"#.into(),
        r#"{"a":1,}"#.into(),
        r#"{,}"#.into(),
        r#"{"a":01}"#.into(),
        r#"{"a":1e}"#.into(),
        r#"{"a":-}"#.into(),
        r#"{"a":"\u"}"#.into(),
        r#"{"a":"\ud800"}"#.into(),
        r#"{"a":"\udfff\udfff"}"#.into(),
        r#"{"a":"\q"}"#.into(),
        "{\"a\":\"\u{1}\"}".into(),
        r#"{"a":1e999999999}"#.into(),
        r#"{"a":-1e-999999999}"#.into(),
        r#"{"a":99999999999999999999999999999999999999999}"#.into(),
        // i128::MIN. `v.abs()` on this panics in debug and wraps in release,
        // and a wrapped comparison silently accepts it.
        r#"{"n":-170141183460469231731687303715884105728}"#.into(),
        // RFC 7493 noncharacters, escaped and raw, BMP and via a pair.
        r#"{"a":"￾"}"#.into(),
        r#"{"a":"﷐"}"#.into(),
        r#"{"a":"􏿿"}"#.into(),
        "{\"a\":\"\u{fffe}\"}".into(),
        "\u{feff}{}".into(),
        // Deep nesting, both shapes: the recursion cap has to hold for
        // objects as well as arrays.
        format!("{}{}", "[".repeat(200_000), "]".repeat(200_000)),
        "[".repeat(200_000),
        format!("{}1{}", r#"{"a":"#.repeat(50_000), "}".repeat(50_000)),
    ];
    v.extend(corpus::cases().into_iter().map(|c| c.payload));
    v
}

#[test]
fn every_parser_configuration_survives_every_hostile_input() {
    let configs = [
        Config::strict(),
        Config::go_encoding_json(),
        Config::node_json_parse(),
        Config::python_json(),
        Config::ruby_json(),
        Config::elixir_otp_json(),
    ];
    for src in hostile_inputs() {
        for cfg in configs {
            // The assertion is that this returns at all. A panic fails the
            // test; an `Err` is a correct answer.
            let _ = parse(&src, cfg);
        }
    }
}

#[test]
fn canonicalization_survives_anything_a_lenient_decoder_produces() {
    for src in hostile_inputs() {
        for cfg in [
            Config::node_json_parse(),
            Config::go_encoding_json(),
            Config::python_json(),
        ] {
            if let Ok(v) = parse(&src, cfg) {
                let _ = canonicalize(&v);
            }
        }
    }
}

#[test]
fn the_endpoint_answers_every_hostile_body_in_both_configurations() {
    for modes in [FailureModes::all_hostile(), FailureModes::boundable()] {
        let mut state = Ledger::default();
        for src in hostile_inputs() {
            for path in [
                "/v1/transfer",
                "/v1/orders",
                "/v1/state",
                "/../../etc/passwd",
                "",
            ] {
                let res = handle(
                    &modes,
                    &mut state,
                    &Request {
                        method: "POST".into(),
                        path: path.into(),
                        headers: vec![("Idempotency-Key".into(), src.chars().take(64).collect())],
                        body: src.clone(),
                    },
                );
                // `>= 200` would be vacuous: every return path already sits in
                // 200..=428, so the assertion would hold against any code the
                // endpoint could emit. Bound it on both sides.
                assert!(
                    (200..500).contains(&res.status),
                    "an answer in range is required, got {}",
                    res.status
                );
            }
        }
    }
}

#[test]
fn the_classifier_survives_documents_that_are_not_specifications() {
    for src in hostile_inputs() {
        let _ = classify_spec(&src);
    }
    // And documents that are JSON but nonsense in OpenAPI's shape.
    for src in [
        r#"{"paths":{"/x":{"post":{"parameters":"not an array"}}}}"#,
        r#"{"paths":{"/x":{"post":{"requestBody":{"content":{"application/json":{"schema":5}}}}}}}"#,
        r#"{"paths":{"/x":5}}"#,
        r#"{"paths":{}}"#,
    ] {
        let _ = classify_spec(src);
    }
}

#[test]
fn strict_parsing_refuses_every_corpus_case_without_crashing() {
    for c in corpus::cases() {
        assert!(parse_strict(&c.payload).is_err(), "case `{}`", c.name);
    }
}
