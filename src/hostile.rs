use crate::json::{parse, Config, Json};
use serde::Serialize;
use std::collections::BTreeMap;

/// The failure modes, each switchable on its own so a finding can be
/// attributed to exactly one of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FailureModes {
    /// Ingest with a real language decoder's leniency rather than refusing.
    ///
    /// Named for what it *controls*, not for one of its effects: it switches
    /// the whole ingestion configuration to `Config::go_encoding_json()`, so
    /// it governs duplicate keys, lone surrogates, noncharacters and numeric
    /// handling together. Calling it `last_key_wins` invited a surrogate or a
    /// 2^53 finding under the `duplicate-keys` scenario to be attributed to
    /// duplicate keys.
    pub lenient_decoder: bool,
    /// Fill an omitted parameter from server-side profile state.
    pub profile_defaults: bool,
    /// Resolve `/v1/users/me` to a concrete identifier.
    pub uri_aliasing: bool,
    /// Execute on every call, ignoring any idempotency key.
    pub non_idempotent: bool,
    /// Execute without requiring the client to pin the state it depends on.
    pub no_state_pinning: bool,
}

pub const SCENARIOS: &[&str] = &[
    "all-hostile",
    "boundable",
    "default-injection",
    "duplicate-keys",
    "retry-ambiguity",
    "alias",
    "state-drift",
];

#[derive(Debug, thiserror::Error)]
#[error("unknown scenario `{name}`; try one of: {}", SCENARIOS.join(", "))]
pub struct ScenarioError {
    pub name: String,
}

impl FailureModes {
    pub fn all_hostile() -> Self {
        FailureModes {
            lenient_decoder: true,
            profile_defaults: true,
            uri_aliasing: true,
            non_idempotent: true,
            no_state_pinning: true,
        }
    }

    /// Every mode off: an endpoint conforming to the Boundable API Profile.
    /// The same code path, so a finding that disappears here disappeared
    /// because the endpoint changed, not because the test did.
    pub fn boundable() -> Self {
        FailureModes {
            lenient_decoder: false,
            profile_defaults: false,
            uri_aliasing: false,
            non_idempotent: false,
            no_state_pinning: false,
        }
    }

    pub fn named(name: &str) -> Result<Self, ScenarioError> {
        let b = Self::boundable();
        Ok(match name {
            "all-hostile" => Self::all_hostile(),
            "boundable" => b,
            // One mode at a time, so a reproduction names one cause.
            "default-injection" => FailureModes {
                profile_defaults: true,
                ..b
            },
            "duplicate-keys" => FailureModes {
                lenient_decoder: true,
                ..b
            },
            "retry-ambiguity" => FailureModes {
                non_idempotent: true,
                ..b
            },
            "alias" => FailureModes {
                uri_aliasing: true,
                ..b
            },
            // Five failure modes need five single-mode scenarios. Without
            // this one a C4 finding could never be attributed to a single
            // cause, which is the entire premise of the toggles.
            "state-drift" => FailureModes {
                no_state_pinning: true,
                ..b
            },
            _ => {
                return Err(ScenarioError {
                    name: name.to_string(),
                })
            }
        })
    }

    /// The decoder this endpoint ingests with. A hostile endpoint uses its
    /// language's default; a boundable one uses a strict RFC 8785 decoder,
    /// which is the cheapest fix in the whole paper.
    fn decoder(&self) -> Config {
        if self.lenient_decoder {
            // `Config::go_encoding_json()`, not a hand-written literal.
            // `Config` gained `overflow`, `non_finite` and `noncharacters`
            // during Task 4's measurement round, so a three-field literal no
            // longer compiles — and reusing the measured Go configuration
            // means the hostile endpoint ingests exactly as a real Go service
            // does, including its overflow rejection.
            Config::go_encoding_json()
        } else {
            Config::strict()
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Transfer {
    pub to: String,
    pub amount: f64,
    pub fee_tier: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Ledger {
    pub version: u64,
    pub transfers: Vec<Transfer>,
    pub orders: Vec<String>,
    used_nonces: Vec<String>,
    /// `Idempotency-Key` → `(canonical request digest, cached response)`.
    ///
    /// The digest is stored because a cache keyed on the header alone lets one
    /// key return another request's success: same key, different body, and the
    /// endpoint replays the first transfer while the client is told the second
    /// one happened. That is a lost write inside the configuration this crate
    /// calls conforming.
    idempotency: BTreeMap<String, (String, String)>,
    /// The business idempotency key for `/v1/orders`, deliberately separate
    /// from `used_nonces`. Keeping them apart is the whole of C3.
    orders_idempotency: BTreeMap<String, String>,
}

impl Ledger {
    pub fn etag(&self) -> String {
        self.version.to_string()
    }
}

#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Clone, Debug)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

fn json_err(status: u16, message: &str) -> Response {
    Response {
        status,
        body: format!(r#"{{"error":{}}}"#, quote(message)),
    }
}

/// JSON-escape a string for interpolation into a response body.
///
/// **Not** "small and local: the endpoint only ever quotes its own messages" —
/// that was wrong, and it produced invalid JSON on attacker-reachable paths.
/// The success body interpolates `to` and `fee_tier` straight from the
/// payload, and `json_err(400, &e.to_string())` interpolates a duplicate key
/// name the client chose. A raw `U+0001` in either emits a response no JSON
/// parser accepts, which Task 8's transport then reports as a transport
/// failure masquerading as a finding.
fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if c.is_control() => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// The endpoint. A pure function of its failure modes, its state and the
/// request, which is what lets every reproduction in Tasks 8 and 9 run with
/// no socket.
pub fn handle(modes: &FailureModes, state: &mut Ledger, req: &Request) -> Response {
    // `raw.url()` carries the query string, so routing on it directly makes
    // `POST /v1/transfer?x=1` fall through to the 404 arm.
    let path = req.path.split('?').next().unwrap_or("");
    match (req.method.as_str(), path) {
        ("POST", "/v1/transfer") => transfer(modes, state, req),
        ("POST", "/v1/orders") => order(modes, state, req),
        ("GET", "/v1/state") => Response {
            status: 200,
            body: serde_json::to_string(state).unwrap_or_else(|_| "{}".into()),
        },
        ("POST", "/v1/reset") => {
            *state = Ledger::default();
            Response {
                status: 200,
                body: r#"{"reset":true}"#.into(),
            }
        }
        ("GET", "/v1/users/me") => {
            if modes.uri_aliasing {
                Response {
                    status: 200,
                    body: r#"{"id":"usr_99812","via":"alias"}"#.into(),
                }
            } else {
                json_err(
                    404,
                    "alias resolution is disabled; name the resource directly",
                )
            }
        }
        ("GET", "/v1/users/usr_99812") => Response {
            status: 200,
            body: r#"{"id":"usr_99812","via":"identifier"}"#.into(),
        },
        _ => json_err(404, "no such resource"),
    }
}

fn transfer(modes: &FailureModes, state: &mut Ledger, req: &Request) -> Response {
    let body = match parse(&req.body, modes.decoder()) {
        Ok(v) => v,
        Err(e) => return json_err(400, &e.to_string()),
    };

    let Some(to) = body.get("to").and_then(Json::as_string) else {
        return json_err(400, "missing or non-string parameter `to`");
    };
    let Some(amount) = body.get("amount").and_then(Json::as_f64) else {
        return json_err(400, "missing or non-numeric parameter `amount`");
    };

    let to = if modes.uri_aliasing && to == "me" {
        "acct-owner".to_string()
    } else {
        to
    };

    // C1. The hostile branch reaches past the request into profile state the
    // signature never covered; the boundable branch refuses to guess.
    let fee_tier = match body.get("fee_tier").and_then(Json::as_string) {
        Some(f) => f,
        None if modes.profile_defaults => "priority".to_string(),
        None => return json_err(400, "missing required parameter `fee_tier`"),
    };

    // C3 is evaluated *before* C4, and the order is load-bearing. A retry of
    // a request that already executed must replay the cached answer, not be
    // refused for state drift that its own first execution caused. Checking
    // the precondition first would make the boundable endpoint fail the very
    // retry scenario C3 exists to fix, which is the opposite of the claim.
    // The digest binds the cache entry to *this* request. Without it, a client
    // reusing a key with a different body is handed the earlier request's
    // success and told an action happened that never did.
    // Falls back to the wire bytes rather than to an empty string: a lenient
    // decoder can produce a value the canonicalizer refuses (a lone surrogate
    // has no UTF-8 form), and `unwrap_or_default()` would make every such
    // request share one cache key.
    let req_digest = crate::jcs::digest(&body).unwrap_or_else(|_| format!("raw:{}", req.body));
    let key = req.header("Idempotency-Key").map(str::to_string);
    if !modes.non_idempotent {
        let Some(k) = key.clone() else {
            return json_err(400, "this endpoint requires an Idempotency-Key");
        };
        if let Some((seen_digest, cached)) = state.idempotency.get(&k) {
            if seen_digest != &req_digest {
                return json_err(422, "this Idempotency-Key was used for a different request");
            }
            return Response {
                status: 200,
                body: cached.clone(),
            };
        }
    }

    // C4, for a cache miss — a request that has not executed before.
    if !modes.no_state_pinning {
        match req.header("If-Match") {
            None => return json_err(428, "this endpoint requires an If-Match precondition"),
            Some(tag) if tag != state.etag() => {
                return json_err(412, "state has moved since the request was signed")
            }
            Some(_) => {}
        }
    }

    state.transfers.push(Transfer {
        to: to.clone(),
        amount,
        fee_tier: fee_tier.clone(),
    });
    state.version += 1;
    let body = format!(
        r#"{{"executed":{{"to":{},"amount":{},"fee_tier":{}}},"state_version":{},"transfer_count":{}}}"#,
        quote(&to),
        amount,
        quote(&fee_tier),
        state.version,
        state.transfers.len()
    );
    if !modes.non_idempotent {
        if let Some(k) = key {
            state.idempotency.insert(k, (req_digest, body.clone()));
        }
    }
    Response { status: 200, body }
}

fn order(modes: &FailureModes, state: &mut Ledger, req: &Request) -> Response {
    let nonce = req
        .header("Authorization")
        .and_then(|a| a.split("nonce=").nth(1))
        .unwrap_or("")
        .to_string();
    if nonce.is_empty() {
        return json_err(401, "no capability nonce");
    }

    // The nonce is checked first and the commit follows, which is the real
    // ordering. The ambiguity does not come from checking late: it comes from
    // the *first* call having already committed by the time the retry arrives,
    // so the monitor correctly identifies a replay and the client correctly
    // records a failure, over a state change that stands.
    if state.used_nonces.iter().any(|n| n == &nonce) {
        return json_err(409, "nonce already used; this looks like a replay");
    }
    state.used_nonces.push(nonce);

    // A boundable endpoint has a business idempotency key **distinct from the
    // authorization nonce**, so a retry with a fresh nonce resolves to the
    // order the key already created.
    //
    // This must read the key. An earlier draft wrote
    // `if !modes.non_idempotent && state.orders.len() == 1`, which hard-codes
    // "the second order is always a replay of the first" — so the boundable
    // endpoint silently dropped every genuine order after the first, and
    // Task 9's proof that decoupling the key from the nonce removes the retry
    // ambiguity was satisfied by a constant rather than by a mechanism.
    // Deleting that branch left all eleven tests green.
    let key = req.header("Idempotency-Key").map(str::to_string);
    if !modes.non_idempotent {
        let Some(k) = key.clone() else {
            return json_err(400, "this endpoint requires an Idempotency-Key");
        };
        if let Some(existing) = state.orders_idempotency.get(&k) {
            return Response {
                status: 200,
                body: format!(
                    r#"{{"order_id":{},"order_count":{},"replayed":true}}"#,
                    quote(existing),
                    state.orders.len()
                ),
            };
        }
    }

    let id = format!("ord-{}", state.orders.len() + 1);
    if !modes.non_idempotent {
        if let Some(k) = key {
            state.orders_idempotency.insert(k, id.clone());
        }
    }
    state.orders.push(id.clone());
    state.version += 1;
    Response {
        status: 200,
        body: format!(
            r#"{{"order_id":{},"state_version":{},"order_count":{}}}"#,
            quote(&id),
            state.version,
            state.orders.len()
        ),
    }
}

/// Serve `handle` over HTTP, **loopback only**.
///
/// The refusal below is not defensive tidiness. This endpoint moves money on
/// purpose, resolves duplicate keys to the attacker's value on purpose, and
/// executes non-idempotent writes on purpose. An earlier draft documented
/// "loopback by default" while `--addr` was a free-form string, so
/// `--addr 0.0.0.0:8791` bound every interface on the host and was measured
/// doing it. A deliberately vulnerable endpoint must not be one flag away
/// from the network.
pub fn serve(addr: &str, modes: FailureModes) -> anyhow::Result<()> {
    use std::net::ToSocketAddrs;
    let resolved: Vec<_> = addr
        .to_socket_addrs()
        .map_err(|e| anyhow::anyhow!("could not resolve {addr}: {e}"))?
        .collect();
    if resolved.is_empty() || !resolved.iter().all(|s| s.ip().is_loopback()) {
        anyhow::bail!(
            "refusing to bind {addr}: the hostile endpoint is deliberately vulnerable \
             and serves loopback only. Use 127.0.0.1 or ::1."
        );
    }
    let server =
        tiny_http::Server::http(addr).map_err(|e| anyhow::anyhow!("could not bind {addr}: {e}"))?;
    println!("hostile endpoint on http://{addr} with {modes:?}");
    let mut state = Ledger::default();
    for mut raw in server.incoming_requests() {
        let mut body = String::new();
        let _ = std::io::Read::read_to_string(raw.as_reader(), &mut body);
        let req = Request {
            method: raw.method().as_str().to_string(),
            path: raw.url().to_string(),
            headers: raw
                .headers()
                .iter()
                .map(|h| {
                    (
                        h.field.as_str().as_str().to_string(),
                        h.value.as_str().to_string(),
                    )
                })
                .collect(),
            body,
        };
        let res = handle(&modes, &mut state, &req);
        let response = tiny_http::Response::from_string(res.body).with_status_code(res.status);
        let _ = raw.respond(response);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn post(path: &str, body: &str, headers: &[(&str, &str)]) -> Request {
        Request {
            method: "POST".into(),
            path: path.into(),
            headers: headers
                .iter()
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .collect(),
            body: body.into(),
        }
    }

    fn transfer(modes: FailureModes, body: &str, headers: &[(&str, &str)]) -> (Response, Ledger) {
        let mut l = Ledger::default();
        let r = handle(&modes, &mut l, &post("/v1/transfer", body, headers));
        (r, l)
    }

    #[test]
    fn hostile_mode_fills_in_a_fee_tier_the_client_never_sent() {
        // The parameter-defaulting bypass, at its source.
        let (r, l) = transfer(
            FailureModes::all_hostile(),
            r#"{"to":"acct-9","amount":100}"#,
            &[],
        );
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(
            l.transfers[0].fee_tier, "priority",
            "loaded from the user profile"
        );
    }

    #[test]
    fn boundable_mode_refuses_the_same_request_instead_of_guessing() {
        let (r, l) = transfer(
            FailureModes::boundable(),
            r#"{"to":"acct-9","amount":100}"#,
            &[],
        );
        assert_eq!(r.status, 400, "{}", r.body);
        assert!(r.body.contains("fee_tier"));
        assert!(
            l.transfers.is_empty(),
            "nothing may execute on a rejected request"
        );
    }

    #[test]
    fn hostile_mode_resolves_duplicate_keys_to_the_last_one() {
        let (_, l) = transfer(
            FailureModes::all_hostile(),
            r#"{"to":"acct-1","amount":100,"to":"acct-9","fee_tier":"standard"}"#,
            &[],
        );
        assert_eq!(l.transfers[0].to, "acct-9");
    }

    #[test]
    fn boundable_mode_rejects_duplicate_keys_outright() {
        let (r, _) = transfer(
            FailureModes::boundable(),
            r#"{"to":"acct-1","amount":100,"to":"acct-9","fee_tier":"standard"}"#,
            &[("Idempotency-Key", "k1"), ("If-Match", "0")],
        );
        assert_eq!(r.status, 400);
        assert!(r.body.contains("duplicate"), "{}", r.body);
    }

    #[test]
    fn state_pinning_aborts_on_drift_and_proceeds_when_pinned() {
        let mut l = Ledger::default();
        let modes = FailureModes::boundable();
        let body = r#"{"to":"acct-9","amount":100,"fee_tier":"standard"}"#;
        let ok = handle(
            &modes,
            &mut l,
            &post(
                "/v1/transfer",
                body,
                &[("Idempotency-Key", "k1"), ("If-Match", "0")],
            ),
        );
        assert_eq!(ok.status, 200, "{}", ok.body);
        // State has moved on, so the same pin is now stale.
        let stale = handle(
            &modes,
            &mut l,
            &post(
                "/v1/transfer",
                body,
                &[("Idempotency-Key", "k2"), ("If-Match", "0")],
            ),
        );
        assert_eq!(
            stale.status, 412,
            "a stale pin must abort, not execute differently"
        );
        assert_eq!(l.transfers.len(), 1);
    }

    #[test]
    fn an_idempotency_key_replays_the_answer_without_re_executing() {
        let mut l = Ledger::default();
        let modes = FailureModes::boundable();
        let body = r#"{"to":"acct-9","amount":100,"fee_tier":"standard"}"#;
        let a = handle(
            &modes,
            &mut l,
            &post(
                "/v1/transfer",
                body,
                &[("Idempotency-Key", "k1"), ("If-Match", "0")],
            ),
        );
        let b = handle(
            &modes,
            &mut l,
            &post(
                "/v1/transfer",
                body,
                &[("Idempotency-Key", "k1"), ("If-Match", "0")],
            ),
        );
        assert_eq!(a.body, b.body, "the second call returns the first answer");
        assert_eq!(l.transfers.len(), 1, "and executes nothing");
    }

    #[test]
    fn the_non_idempotent_mode_executes_every_time() {
        let mut l = Ledger::default();
        let modes = FailureModes::all_hostile();
        for _ in 0..3 {
            handle(
                &modes,
                &mut l,
                &post(
                    "/v1/transfer",
                    r#"{"to":"a","amount":1}"#,
                    &[("Idempotency-Key", "same")],
                ),
            );
        }
        assert_eq!(l.transfers.len(), 3, "the key is accepted and ignored");
    }

    #[test]
    fn the_alias_resolves_only_when_aliasing_is_switched_on() {
        let mut l = Ledger::default();
        let get = Request {
            method: "GET".into(),
            path: "/v1/users/me".into(),
            headers: vec![],
            body: String::new(),
        };
        assert_eq!(
            handle(&FailureModes::all_hostile(), &mut l, &get).status,
            200
        );
        assert!(handle(&FailureModes::all_hostile(), &mut l, &get)
            .body
            .contains("usr_99812"));
        assert_eq!(handle(&FailureModes::boundable(), &mut l, &get).status, 404);
    }

    #[test]
    fn a_replayed_nonce_is_refused_over_a_state_change_that_stands() {
        // This *is* the retry ambiguity. The nonce check is correct, the
        // refusal is correct, and the order committed by the first call is
        // still there.
        let mut l = Ledger::default();
        let modes = FailureModes::all_hostile();
        let req = post(
            "/v1/orders",
            "{}",
            &[("Authorization", "Capability nonce=n1")],
        );
        assert_eq!(handle(&modes, &mut l, &req).status, 200);
        assert_eq!(
            handle(&modes, &mut l, &req).status,
            409,
            "a replayed nonce is refused"
        );
        assert_eq!(l.orders.len(), 1, "and the first order is still there");
    }

    #[test]
    fn malformed_and_unknown_requests_answer_rather_than_panic() {
        let mut l = Ledger::default();
        for modes in [FailureModes::all_hostile(), FailureModes::boundable()] {
            for (path, body) in [
                ("/v1/transfer", "{"),
                ("/v1/transfer", ""),
                ("/v1/transfer", r#"{"to":5,"amount":"x"}"#),
                ("/v1/transfer", r#"{"amount":1}"#),
                ("/nope", "{}"),
            ] {
                let r = handle(&modes, &mut l, &post(path, body, &[]));
                assert!(
                    (400..=499).contains(&r.status),
                    "{path} {body:?} gave {}",
                    r.status
                );
            }
        }
    }

    #[test]
    fn a_query_string_on_the_path_does_not_change_the_route() {
        // `raw.url()` carries the query string, so routing on `req.path`
        // directly made `POST /v1/transfer?x=1` fall through to the 404 arm.
        // Every other test in this module posts to a bare path, so this gap
        // survived until it was checked for directly: mutating routing back
        // to the raw path left all sixteen other tests green.
        let mut l = Ledger::default();
        let r = handle(
            &FailureModes::boundable(),
            &mut l,
            &post(
                "/v1/transfer?x=1",
                r#"{"to":"acct-9","amount":100,"fee_tier":"standard"}"#,
                &[("Idempotency-Key", "k1"), ("If-Match", "0")],
            ),
        );
        assert_eq!(r.status, 200, "{}", r.body);
        assert_eq!(l.transfers.len(), 1);
    }

    #[test]
    fn the_lenient_decoder_is_the_measured_go_configuration() {
        // `decoder()` must resolve to `Config::go_encoding_json()`
        // specifically, not merely some other config that also last-wins on
        // duplicate keys: Go rejects a literal that overflows a 64-bit float
        // where Node silently produces Infinity. Every other test in this
        // module stayed green when this decoder was swapped for Node's.
        let (r, _) = transfer(
            FailureModes::all_hostile(),
            r#"{"to":"acct-9","amount":1e400,"fee_tier":"standard"}"#,
            &[],
        );
        assert_eq!(r.status, 400, "{}", r.body);
        assert!(r.body.contains("overflow"), "{}", r.body);
    }

    #[test]
    fn every_named_scenario_resolves_to_exactly_the_modes_it_names() {
        // Asserting only `is_ok()` pins nothing: collapsing all four
        // single-mode arms to `boundable()` passed every test, and Tasks 8,
        // 9, 10 and 15 all drive the endpoint through these names — so the
        // whole fuzz suite would have silently tested a conforming endpoint.
        let b = FailureModes::boundable();
        assert_eq!(FailureModes::named("boundable").unwrap(), b);
        assert_eq!(
            FailureModes::named("all-hostile").unwrap(),
            FailureModes::all_hostile()
        );
        assert_eq!(
            FailureModes::named("duplicate-keys").unwrap(),
            FailureModes {
                lenient_decoder: true,
                ..b
            }
        );
        assert_eq!(
            FailureModes::named("default-injection").unwrap(),
            FailureModes {
                profile_defaults: true,
                ..b
            }
        );
        assert_eq!(
            FailureModes::named("retry-ambiguity").unwrap(),
            FailureModes {
                non_idempotent: true,
                ..b
            }
        );
        assert_eq!(
            FailureModes::named("alias").unwrap(),
            FailureModes {
                uri_aliasing: true,
                ..b
            }
        );
        assert_eq!(
            FailureModes::named("state-drift").unwrap(),
            FailureModes {
                no_state_pinning: true,
                ..b
            }
        );
        assert_eq!(
            SCENARIOS.len(),
            7,
            "every scenario above is listed for the CLI"
        );
        assert!(FailureModes::named("wishful").is_err());
    }

    #[test]
    fn a_boundable_endpoint_can_still_create_more_than_one_order() {
        // The mechanism, not a constant. Three distinct keys must produce
        // three orders; one key reused must produce one.
        let mut l = Ledger::default();
        let modes = FailureModes::boundable();
        for (i, k) in ["k1", "k2", "k3"].iter().enumerate() {
            let r = handle(
                &modes,
                &mut l,
                &post(
                    "/v1/orders",
                    "{}",
                    &[
                        ("Authorization", &format!("Capability nonce=n{i}")),
                        ("Idempotency-Key", k),
                    ],
                ),
            );
            assert_eq!(r.status, 200, "{}", r.body);
        }
        assert_eq!(l.orders.len(), 3, "distinct keys are distinct orders");

        handle(
            &modes,
            &mut l,
            &post(
                "/v1/orders",
                "{}",
                &[
                    ("Authorization", "Capability nonce=n9"),
                    ("Idempotency-Key", "k1"),
                ],
            ),
        );
        assert_eq!(
            l.orders.len(),
            3,
            "a reused key replays rather than creating"
        );
    }

    #[test]
    fn an_idempotency_key_is_bound_to_the_request_that_used_it() {
        // Same key, different body: the endpoint must refuse rather than
        // hand back the first request's success for the second request.
        let mut l = Ledger::default();
        let modes = FailureModes::boundable();
        let a = handle(
            &modes,
            &mut l,
            &post(
                "/v1/transfer",
                r#"{"to":"acct-9","amount":100,"fee_tier":"standard"}"#,
                &[("Idempotency-Key", "k1"), ("If-Match", "0")],
            ),
        );
        assert_eq!(a.status, 200);
        let b = handle(
            &modes,
            &mut l,
            &post(
                "/v1/transfer",
                r#"{"to":"acct-2","amount":5,"fee_tier":"standard"}"#,
                &[("Idempotency-Key", "k1"), ("If-Match", "1")],
            ),
        );
        assert_eq!(
            b.status, 422,
            "a key bound to another request must not replay it"
        );
        assert_eq!(l.transfers.len(), 1);
    }

    #[test]
    fn the_alias_also_resolves_inside_a_transfer() {
        // Deleting the aliasing branch in `transfer` left every test green;
        // the only alias coverage was the `GET /v1/users/me` route.
        let mut l = Ledger::default();
        handle(
            &FailureModes::all_hostile(),
            &mut l,
            &post("/v1/transfer", r#"{"to":"me","amount":1}"#, &[]),
        );
        assert_eq!(l.transfers[0].to, "acct-owner");

        let mut l2 = Ledger::default();
        handle(
            &FailureModes::named("duplicate-keys").unwrap(),
            &mut l2,
            &post(
                "/v1/transfer",
                r#"{"to":"me","amount":1,"fee_tier":"standard"}"#,
                &[("Idempotency-Key", "k"), ("If-Match", "0")],
            ),
        );
        assert_eq!(l2.transfers[0].to, "me", "aliasing is off in this scenario");
    }

    #[test]
    fn every_response_is_valid_json_even_for_hostile_input() {
        // `quote` escaped only `"`, `\` and newline, so a control character
        // in a payload-controlled string produced a response no JSON parser
        // accepts — on both the success and the error path.
        let mut l = Ledger::default();
        for (modes, body) in [
            (
                FailureModes::all_hostile(),
                "{\"to\":\"a\\u0001b\",\"amount\":1}",
            ),
            (
                FailureModes::boundable(),
                "{\"a\\u0001b\":1,\"a\\u0001b\":2}",
            ),
        ] {
            let r = handle(&modes, &mut l, &post("/v1/transfer", body, &[]));
            assert!(
                serde_json::from_str::<serde_json::Value>(&r.body).is_ok(),
                "not valid JSON: {}",
                r.body
            );
        }
    }

    #[test]
    fn the_endpoint_refuses_to_bind_anything_but_loopback() {
        assert!(serve("0.0.0.0:0", FailureModes::boundable()).is_err());
        assert!(serve("[::]:0", FailureModes::boundable()).is_err());
    }
}
