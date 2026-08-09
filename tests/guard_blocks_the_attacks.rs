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
