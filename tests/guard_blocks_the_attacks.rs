//! The pairing the whole deployment argument rests on: an attack that
//! succeeds against the endpoint directly, run past the guard instead.
//!
//! Alias collapse is asserted to PASS. That is not a bug being tolerated —
//! it is the boundary of what a proxy can do, and pinning it stops the
//! README quietly growing a claim the code does not support.

use transit::corpus;
use transit::guard::{decide, Decision, Enforcement, GuardConfig, RouteRule};
use transit::hostile::Request;

fn cfg_with_required_params() -> GuardConfig {
    GuardConfig {
        listen: "127.0.0.1:0".into(),
        upstream: "http://127.0.0.1:8787".into(),
        enforce: Enforcement::default(),
        route: vec![RouteRule {
            method: "POST".into(),
            path_prefix: "/v1/transfer".into(),
            require_idempotency_key: None,
            require_state_precondition: None,
            require_parameters: vec!["to".into(), "amount".into(), "fee_tier".into()],
        }],
    }
}

fn post(path: &str, body: &str) -> Request {
    Request {
        method: "POST".into(),
        path: path.into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Idempotency-Key".into(), "k1".into()),
            ("If-Match".into(), "0".into()),
        ],
        body: body.into(),
    }
}

#[test]
fn the_duplicate_key_split_never_reaches_the_upstream() {
    let d = decide(
        &cfg_with_required_params(),
        &post(
            "/v1/transfer",
            r#"{"to":"acct-1","amount":100,"fee_tier":"standard","to":"acct-9"}"#,
        ),
    );
    assert!(
        matches!(
            d,
            Decision::Reject {
                condition: Some(corpus::Condition::C2),
                ..
            }
        ),
        "{d:?}"
    );
}

#[test]
fn the_defaulting_bypass_is_stopped_when_the_route_names_the_parameters() {
    let d = decide(
        &cfg_with_required_params(),
        &post("/v1/transfer", r#"{"to":"acct-9","amount":100}"#),
    );
    assert!(
        matches!(
            d,
            Decision::Reject {
                condition: Some(corpus::Condition::C1),
                ..
            }
        ),
        "{d:?}"
    );
}

#[test]
fn the_defaulting_bypass_is_not_stopped_without_that_list() {
    // The honest half. An operator who does not configure require_parameters
    // gets no C1 enforcement, and the docs say so.
    let mut c = cfg_with_required_params();
    c.route.clear();
    let d = decide(&c, &post("/v1/transfer", r#"{"to":"acct-9","amount":100}"#));
    assert!(matches!(d, Decision::Forward(_)), "{d:?}");
}

#[test]
fn alias_collapse_passes_through_and_that_is_the_boundary() {
    let mut r = post("/v1/users/me", "");
    r.method = "GET".into();
    r.headers.clear();
    let d = decide(&cfg_with_required_params(), &r);
    assert!(
        matches!(d, Decision::Forward(_)),
        "a proxy cannot know that /v1/users/me and /v1/users/usr_99812 are one resource"
    );
}

/// The whole developer workflow, in one test: point the classifier at a
/// specification, feed what it emits straight into the guard, and check that
/// the attack the classifier warned about is now refused.
///
/// This is the claim `--emit-guard-config` makes, and it is the one worth
/// pinning. The two halves are written by different modules that share no
/// types -- `classify` emits text, `guard` parses it -- so a change to either
/// side's vocabulary breaks this and nothing else.
#[test]
fn a_config_generated_from_a_specification_stops_the_bypass_it_warned_about() {
    let spec = std::fs::read_to_string("examples/stripe-charges.openapi.json").unwrap();
    let cs = transit::classify::classify_spec(&spec).unwrap();

    // The classifier says a client may omit `currency`, and that the endpoint
    // will then fill it in -- the C1 exposure.
    assert!(cs[0].unbound_body.iter().any(|p| p.name == "currency"));

    let generated = transit::classify::emit_guard_config(&cs);
    let mut cfg = transit::guard::parse_config(&generated)
        .expect("what classify emits must be what guard accepts");
    cfg.upstream = "http://127.0.0.1:8787".into();

    // Before: this request omits `currency`, and a bare proxy forwards it.
    let omits_currency = Request {
        method: "POST".into(),
        path: "/v1/charges".into(),
        headers: vec![
            ("Content-Type".into(), "application/json".into()),
            ("Idempotency-Key".into(), "k1".into()),
            ("If-Match".into(), "0".into()),
        ],
        body: r#"{"amount":100,"source":"tok_1","capture":true,"description":"x"}"#.into(),
    };
    let mut bare = cfg.clone();
    bare.route.clear();
    assert!(
        matches!(decide(&bare, &omits_currency), Decision::Forward(_)),
        "without the generated rule the bypass goes through"
    );

    // After: the generated rule refuses it, and names C1 as the reason.
    let d = decide(&cfg, &omits_currency);
    assert!(
        matches!(
            d,
            Decision::Reject {
                status: 422,
                condition: Some(corpus::Condition::C1),
                ..
            }
        ),
        "{d:?}"
    );

    // And the generated types are load-bearing, not decoration. `capture` is
    // declared `bool`; sending it as the string "true" satisfies a presence
    // check and is still read as absent by an upstream expecting a boolean.
    let wrong_type = Request {
        body:
            r#"{"amount":100,"source":"tok_1","capture":"true","description":"x","currency":"usd"}"#
                .into(),
        ..omits_currency.clone()
    };
    let d = decide(&cfg, &wrong_type);
    assert!(
        matches!(
            d,
            Decision::Reject {
                condition: Some(corpus::Condition::C1),
                ..
            }
        ),
        "a wrong-typed parameter must not pass as present: {d:?}"
    );

    // A fully explicit request is forwarded. Without this the test would pass
    // against a guard that refused everything.
    let complete = Request {
        body:
            r#"{"amount":100,"source":"tok_1","capture":true,"description":"x","currency":"usd"}"#
                .into(),
        ..omits_currency
    };
    assert!(
        matches!(decide(&cfg, &complete), Decision::Forward(_)),
        "a request that names every parameter must still get through"
    );
}

#[test]
fn every_corpus_payload_is_stopped() {
    for case in corpus::cases() {
        let d = decide(&cfg_with_required_params(), &post("/v1/t", &case.payload));
        assert!(
            matches!(d, Decision::Reject { .. }),
            "case `{}` got through: {d:?}",
            case.name
        );
    }
}
