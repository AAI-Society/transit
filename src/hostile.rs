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

/// Fix round 1, C1: every field here is reachable from `GET /v1/state`
/// through `#[derive(Serialize)]`, `used_nonces` and `orders_idempotency`
/// included. That is deliberate harness observability — Tasks 8 and 9 need
/// to see the capability and idempotency state a fuzzed request produced,
/// not just the business ledger — and not an oversight to `#[serde(skip)]`.
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
    ///
    /// Fix round 1, C1: `(canonical request digest, order id)`, the same
    /// shape as `idempotency` above and for the same reason — a cache keyed
    /// on the header alone let one key return another request's order:
    /// `POST /v1/orders` with `{"sku":"A"}` under `Idempotency-Key: k1`,
    /// then a second, distinct order under the same key, replayed the
    /// first order's id while the client was told the second succeeded. Two
    /// orders were meant, one was created, and the ledger disagreed with
    /// the client about it — inside the configuration this crate calls
    /// conforming.
    orders_idempotency: BTreeMap<String, (String, String)>,
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

/// Resolve a header that the client may have sent more than once, under the
/// same duplicate policy `decoder()` applies to the body.
///
/// Fix round 1, I7: `Request::header` took the first match with no stated
/// policy at all — `Idempotency-Key: k1` followed by `Idempotency-Key: k2`
/// silently used `k1`, undefined behaviour on the exact header this
/// endpoint's write routes treat as the client's one word on identity. For
/// a fixture whose entire subject is which duplicate a decoder resolves to,
/// and which `transit guard` sits in front of and may resolve differently,
/// that is a guard/upstream desync waiting to happen. Only `Idempotency-Key`
/// and `If-Match` go through this; `Authorization` still uses the plain
/// first-match `header()` above.
fn resolved_header(
    req: &Request,
    name: &str,
    modes: &FailureModes,
) -> Result<Option<String>, Response> {
    let matches: Vec<&str> = req
        .headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect();
    if modes.lenient_decoder {
        // Matches the lenient body decoder's `DuplicatePolicy::LastWins`.
        Ok(matches.last().map(|s| s.to_string()))
    } else if matches.len() > 1 {
        // Matches the strict body decoder's `DuplicatePolicy::Reject`.
        Err(json_err(400, &format!("duplicate header `{name}`")))
    } else {
        Ok(matches.first().map(|s| s.to_string()))
    }
}

/// Format an `f64` for interpolation into a response body, never emitting
/// Rust's `inf`/`NaN`/`-inf` spellings, none of which are valid JSON.
///
/// Fix round 1, minor: unreachable today, because both configurations this
/// endpoint ever decodes with (`Config::go_encoding_json()` and
/// `Config::strict()`) reject a literal that overflows a 64-bit float at
/// parse time — see `OverflowPolicy`. Guarded anyway, on the same principle
/// as `quote`: a value this endpoint interpolates into its own response is
/// payload-controlled, and "unreachable under the two configs wired up
/// today" is not a proof for a function with no such qualifier in its
/// signature.
fn json_number(f: f64) -> String {
    if f.is_finite() {
        f.to_string()
    } else {
        "null".to_string()
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
    let key = match resolved_header(req, "Idempotency-Key", modes) {
        Ok(v) => v,
        Err(e) => return e,
    };
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
        let if_match = match resolved_header(req, "If-Match", modes) {
            Ok(v) => v,
            Err(e) => return e,
        };
        match if_match.as_deref() {
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
        json_number(amount),
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

    // Fix round 1, C1/finding 8: this route used to never read `req.body`
    // at all, so `boundable` ingested it with no strict decoder — a
    // duplicate-keyed or otherwise malformed body returned 200 under every
    // mode, and `lenient_decoder` had no observable effect on this route.
    // Parsed with the same decoder `transfer()` uses, for the same reason.
    let body = match parse(&req.body, modes.decoder()) {
        Ok(v) => v,
        Err(e) => return json_err(400, &e.to_string()),
    };
    let req_digest = crate::jcs::digest(&body).unwrap_or_else(|_| format!("raw:{}", req.body));

    // The nonce is checked first and the commit follows, which is the real
    // ordering. The ambiguity does not come from checking late: it comes from
    // the *first* call having already committed by the time the retry arrives,
    // so the monitor correctly identifies a replay and the client correctly
    // records a failure, over a state change that stands.
    if state.used_nonces.iter().any(|n| n == &nonce) {
        return json_err(409, "nonce already used; this looks like a replay");
    }

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
    let key = match resolved_header(req, "Idempotency-Key", modes) {
        Ok(v) => v,
        Err(e) => return e,
    };

    if !modes.non_idempotent {
        let Some(k) = key else {
            return json_err(400, "this endpoint requires an Idempotency-Key");
        };

        // Fix round 1, I2: committed here, not before the key check above.
        // The push used to happen unconditionally right after the replay
        // check, so a request rejected for a missing key still burned the
        // nonce — leaving a corrected retry on the same nonce refused as a
        // replay of a request that never executed. That is exactly the
        // "did it happen?" ambiguity C3 exists to eliminate, reintroduced
        // by the harness meant to demonstrate its absence.
        state.used_nonces.push(nonce);

        // Fix round 1, C1: the digest binds the cache entry to *this*
        // request, the same way `transfer`'s idempotency cache does. Keyed
        // on the header alone, a client reusing a key for a genuinely
        // different order was handed the first order's id while told the
        // second one — with different contents — had succeeded.
        if let Some((seen_digest, existing)) = state.orders_idempotency.get(&k) {
            if seen_digest != &req_digest {
                return json_err(422, "this Idempotency-Key was used for a different request");
            }
            return Response {
                status: 200,
                body: format!(
                    r#"{{"order_id":{},"order_count":{},"replayed":true}}"#,
                    quote(existing),
                    state.orders.len()
                ),
            };
        }

        let id = format!("ord-{}", state.orders.len() + 1);
        state.orders_idempotency.insert(k, (req_digest, id.clone()));
        state.orders.push(id.clone());
        state.version += 1;
        return Response {
            status: 200,
            body: format!(
                r#"{{"order_id":{},"state_version":{},"order_count":{}}}"#,
                quote(&id),
                state.version,
                state.orders.len()
            ),
        };
    }

    // `non_idempotent`: execute unconditionally, no key required.
    state.used_nonces.push(nonce);
    let id = format!("ord-{}", state.orders.len() + 1);
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

        // Fix round 1, I4: the assertions above call `named()` with seven
        // hardcoded literals, so a name misspelled in `SCENARIOS` itself —
        // the list `ScenarioError` prints and Tasks 10/15 iterate — was
        // never compared against them and passed every test. Iterate the
        // list directly, and require the seven to be pairwise distinct: a
        // scenario that silently resolved to another's modes would pass a
        // `len() == 7` check just as easily as a misspelling would.
        let resolved: Vec<FailureModes> = SCENARIOS
            .iter()
            .map(|name| {
                FailureModes::named(name)
                    .unwrap_or_else(|e| panic!("`{name}` is in SCENARIOS but doesn't resolve: {e}"))
            })
            .collect();
        for i in 0..resolved.len() {
            for j in (i + 1)..resolved.len() {
                assert_ne!(
                    resolved[i], resolved[j],
                    "`{}` and `{}` resolve to the same modes",
                    SCENARIOS[i], SCENARIOS[j]
                );
            }
        }
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
        // Fix round 1, minor: asserting only `is_err()` would still pass a
        // reordering that binds *then* refuses — the message is the only
        // thing that pins "refused before any socket was touched."
        let e1 = serve("0.0.0.0:0", FailureModes::boundable()).unwrap_err();
        assert!(e1.to_string().contains("refusing to bind"), "{e1}");
        let e2 = serve("[::]:0", FailureModes::boundable()).unwrap_err();
        assert!(e2.to_string().contains("refusing to bind"), "{e2}");
    }

    // ---- Fix round 1 ----

    #[test]
    fn an_order_idempotency_key_is_bound_to_the_request_that_used_it() {
        // C1. Same key, different body: the endpoint must refuse rather
        // than hand back the first order's id for a second, distinct
        // order. `orders_idempotency` used to be keyed on the header
        // alone, so this replayed `ord-1` and reported success for an
        // order that was never created.
        let mut l = Ledger::default();
        let modes = FailureModes::boundable();
        let a = handle(
            &modes,
            &mut l,
            &post(
                "/v1/orders",
                r#"{"sku":"A","qty":1}"#,
                &[
                    ("Authorization", "Capability nonce=n1"),
                    ("Idempotency-Key", "k1"),
                ],
            ),
        );
        assert_eq!(a.status, 200, "{}", a.body);
        let b = handle(
            &modes,
            &mut l,
            &post(
                "/v1/orders",
                r#"{"sku":"B","qty":9999}"#,
                &[
                    ("Authorization", "Capability nonce=n2"),
                    ("Idempotency-Key", "k1"),
                ],
            ),
        );
        assert_eq!(
            b.status, 422,
            "a key bound to another request must not replay it"
        );
        assert_eq!(l.orders.len(), 1, "only the first order was ever created");
    }

    #[test]
    fn orders_are_ingested_with_the_configured_decoder_too() {
        // Finding 8. `order()` used to never read `req.body`, so
        // `boundable` ingested this write route with no strict decoder at
        // all, and `lenient_decoder` had no observable effect on it:
        // `{"qty":1,"qty":2}` returned 200 under every mode.
        let mut l = Ledger::default();
        let r = handle(
            &FailureModes::boundable(),
            &mut l,
            &post(
                "/v1/orders",
                r#"{"qty":1,"qty":2}"#,
                &[
                    ("Authorization", "Capability nonce=n1"),
                    ("Idempotency-Key", "k1"),
                ],
            ),
        );
        assert_eq!(r.status, 400, "{}", r.body);
        assert!(r.body.contains("duplicate"), "{}", r.body);
        assert!(l.orders.is_empty());

        let mut l2 = Ledger::default();
        let r2 = handle(
            &FailureModes::all_hostile(),
            &mut l2,
            &post(
                "/v1/orders",
                r#"{"qty":1,"qty":2}"#,
                &[("Authorization", "Capability nonce=n1")],
            ),
        );
        assert_eq!(r2.status, 200, "{}", r2.body);
    }

    #[test]
    fn a_rejected_order_does_not_burn_the_capability_nonce() {
        // I2. The nonce used to be marked used before the missing-key
        // check, so a request that executed nothing still consumed it —
        // and the corrected retry, on the same nonce, was refused as a
        // replay of a request that never happened.
        let mut l = Ledger::default();
        let modes = FailureModes::boundable();
        let rejected = handle(
            &modes,
            &mut l,
            &post(
                "/v1/orders",
                "{}",
                &[("Authorization", "Capability nonce=n1")],
            ),
        );
        assert_eq!(rejected.status, 400, "{}", rejected.body);
        assert!(l.orders.is_empty());

        let retried = handle(
            &modes,
            &mut l,
            &post(
                "/v1/orders",
                "{}",
                &[
                    ("Authorization", "Capability nonce=n1"),
                    ("Idempotency-Key", "k1"),
                ],
            ),
        );
        assert_eq!(
            retried.status, 200,
            "the nonce must still be usable after a request that did nothing: {}",
            retried.body
        );
        assert_eq!(l.orders.len(), 1);
    }

    /// Exercises each of the five modes independently through `handle`, so
    /// a scenario is checked by what it *does*, not merely by the
    /// `FailureModes` value it resolves to. Returns, in field order,
    /// whether each mode's hostile behaviour was actually observed.
    ///
    /// I3. Two mutations passed all eighteen tests that existed before this
    /// one: swapping the `!modes.non_idempotent`/`!modes.no_state_pinning`
    /// guards (and the cache-insert alongside them), and substituting
    /// `modes.profile_defaults` for `modes.uri_aliasing` at the alias site
    /// inside `transfer`. Both compile, and both leave every previous
    /// assertion true, because only `all_hostile()` (every field `true`)
    /// and `boundable()` (every field `false`) were ever driven through
    /// `handle` — so swapping two `true`s or two `false`s changes nothing
    /// observable. The five single-mode scenarios were asserted only for
    /// field equality, never exercised.
    fn observed_hostile_behaviour(modes: FailureModes) -> [bool; 5] {
        // Duplicate keys: last-wins (the request succeeds) rather than a
        // rejected duplicate.
        let mut l = Ledger::default();
        let r = handle(
            &modes,
            &mut l,
            &post(
                "/v1/transfer",
                r#"{"to":"acct-1","amount":1,"to":"acct-9","fee_tier":"standard"}"#,
                &[("Idempotency-Key", "dup"), ("If-Match", "0")],
            ),
        );
        let lenient_decoder = r.status == 200;

        // Profile defaults: an omitted `fee_tier` is filled in rather than
        // refused.
        let mut l = Ledger::default();
        let r = handle(
            &modes,
            &mut l,
            &post(
                "/v1/transfer",
                r#"{"to":"acct-9","amount":1}"#,
                &[("Idempotency-Key", "def"), ("If-Match", "0")],
            ),
        );
        let profile_defaults = r.status == 200;

        // URI aliasing, checked at its actual site inside `transfer` (not
        // only the dedicated `GET /v1/users/me` route, which the
        // `profile_defaults`-for-`uri_aliasing` mutation above never
        // touches): `to: "me"` resolves to the owner account.
        let mut l = Ledger::default();
        handle(
            &modes,
            &mut l,
            &post(
                "/v1/transfer",
                r#"{"to":"me","amount":1,"fee_tier":"standard"}"#,
                &[("Idempotency-Key", "alias"), ("If-Match", "0")],
            ),
        );
        let uri_aliasing = l.transfers.first().map(|t| t.to.as_str()) == Some("acct-owner");

        // Non-idempotent: the same key executes twice, each call pinned to
        // the version it actually sees, so this isolates idempotency from
        // state pinning rather than needing it disabled too.
        let mut l = Ledger::default();
        let body = r#"{"to":"acct-9","amount":1,"fee_tier":"standard"}"#;
        handle(
            &modes,
            &mut l,
            &post(
                "/v1/transfer",
                body,
                &[("Idempotency-Key", "rep"), ("If-Match", "0")],
            ),
        );
        let etag = l.etag();
        handle(
            &modes,
            &mut l,
            &post(
                "/v1/transfer",
                body,
                &[("Idempotency-Key", "rep"), ("If-Match", &etag)],
            ),
        );
        let non_idempotent = l.transfers.len() == 2;

        // No state pinning: a request with no `If-Match` still executes.
        let mut l = Ledger::default();
        let r = handle(
            &modes,
            &mut l,
            &post(
                "/v1/transfer",
                r#"{"to":"acct-9","amount":1,"fee_tier":"standard"}"#,
                &[("Idempotency-Key", "pin")],
            ),
        );
        let no_state_pinning = r.status == 200;

        [
            lenient_decoder,
            profile_defaults,
            uri_aliasing,
            non_idempotent,
            no_state_pinning,
        ]
    }

    #[test]
    fn every_scenario_produces_exactly_the_behaviour_its_modes_name() {
        for name in SCENARIOS {
            let modes = FailureModes::named(name).unwrap();
            let observed = observed_hostile_behaviour(modes);
            let expected = [
                modes.lenient_decoder,
                modes.profile_defaults,
                modes.uri_aliasing,
                modes.non_idempotent,
                modes.no_state_pinning,
            ];
            assert_eq!(
                observed, expected,
                "scenario `{name}`: observed {observed:?}, modes name {expected:?}"
            );
        }
    }

    #[test]
    fn state_reports_the_ledger_as_json() {
        // I5. `GET /v1/state` had zero coverage; Tasks 8 and 9 depend on it
        // as the harness's only way to observe the ledger.
        let mut l = Ledger::default();
        handle(
            &FailureModes::all_hostile(),
            &mut l,
            &post("/v1/transfer", r#"{"to":"acct-9","amount":1}"#, &[]),
        );
        let get = Request {
            method: "GET".into(),
            path: "/v1/state".into(),
            headers: vec![],
            body: String::new(),
        };
        let r = handle(&FailureModes::boundable(), &mut l, &get);
        assert_eq!(r.status, 200, "{}", r.body);
        let v: serde_json::Value = serde_json::from_str(&r.body).expect("valid JSON");
        assert_eq!(v["transfers"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn reset_clears_the_ledger() {
        // I5. `POST /v1/reset` had zero coverage; it is the harness's only
        // way to start a scenario from a clean ledger.
        let mut l = Ledger::default();
        handle(
            &FailureModes::all_hostile(),
            &mut l,
            &post("/v1/transfer", r#"{"to":"acct-9","amount":1}"#, &[]),
        );
        assert_eq!(l.transfers.len(), 1);
        let reset = Request {
            method: "POST".into(),
            path: "/v1/reset".into(),
            headers: vec![],
            body: String::new(),
        };
        let r = handle(&FailureModes::boundable(), &mut l, &reset);
        assert_eq!(r.status, 200, "{}", r.body);
        assert!(l.transfers.is_empty());
        assert_eq!(l.version, 0);
    }

    #[test]
    fn the_canonical_identifier_resolves_regardless_of_aliasing() {
        // I5. `GET /v1/users/usr_99812` had zero coverage — it is the
        // identifier the alias resolves *to*, half of the aliasing
        // demonstration, and deleting the route entirely passed every
        // other test.
        let mut l = Ledger::default();
        let get = Request {
            method: "GET".into(),
            path: "/v1/users/usr_99812".into(),
            headers: vec![],
            body: String::new(),
        };
        for modes in [FailureModes::all_hostile(), FailureModes::boundable()] {
            let r = handle(&modes, &mut l, &get);
            assert_eq!(r.status, 200, "{}", r.body);
            assert!(r.body.contains("usr_99812"));
            assert!(r.body.contains("identifier"));
        }
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        // I6. `serve` forwards whatever casing the client sent; every test
        // above uses canonical casing, so a comparison that only matched
        // canonical casing would break the served endpoint while the whole
        // suite stayed green.
        let mut l = Ledger::default();
        let r = handle(
            &FailureModes::boundable(),
            &mut l,
            &post(
                "/v1/transfer",
                r#"{"to":"acct-9","amount":1,"fee_tier":"standard"}"#,
                &[("idempotency-key", "k1"), ("if-match", "0")],
            ),
        );
        assert_eq!(r.status, 200, "{}", r.body);
    }

    #[test]
    fn a_missing_precondition_is_specifically_428_not_merely_4xx() {
        // I6. The only route to 428 is `Idempotency-Key` present,
        // `If-Match` absent — every test above either supplies both
        // headers or neither, so a mutation answering 400 here instead
        // passed the whole suite. Task 8's `parameter_defaulting_bypass`
        // is written against this exact status.
        let mut l = Ledger::default();
        let r = handle(
            &FailureModes::boundable(),
            &mut l,
            &post(
                "/v1/transfer",
                r#"{"to":"acct-9","amount":1,"fee_tier":"standard"}"#,
                &[("Idempotency-Key", "k1")],
            ),
        );
        assert_eq!(r.status, 428, "{}", r.body);
    }

    #[test]
    fn boundable_mode_rejects_a_duplicated_precondition_header() {
        // I7. `Request::header` took the first match with no stated
        // policy, so `Idempotency-Key: k1` followed by `Idempotency-Key:
        // k2` silently used `k1` — undefined behaviour on the exact header
        // `transit guard` sits in front of and may resolve differently.
        // Pinned to match the body decoder: strict rejects a duplicate,
        // consistent with `DuplicatePolicy::Reject`.
        let mut l = Ledger::default();
        let r = handle(
            &FailureModes::boundable(),
            &mut l,
            &post(
                "/v1/transfer",
                r#"{"to":"acct-9","amount":1,"fee_tier":"standard"}"#,
                &[
                    ("Idempotency-Key", "k1"),
                    ("Idempotency-Key", "k2"),
                    ("If-Match", "0"),
                ],
            ),
        );
        assert_eq!(r.status, 400, "{}", r.body);
        assert!(r.body.contains("duplicate"), "{}", r.body);
        assert!(l.transfers.is_empty());
    }

    #[test]
    fn the_lenient_configuration_resolves_a_duplicated_header_to_the_last_value() {
        // I7. Matches the lenient body decoder: last-wins, not a rejection.
        let mut l = Ledger::default();
        let r = handle(
            &FailureModes::all_hostile(),
            &mut l,
            &post(
                "/v1/transfer",
                r#"{"to":"acct-9","amount":1,"fee_tier":"standard"}"#,
                &[("Idempotency-Key", "k1"), ("Idempotency-Key", "k2")],
            ),
        );
        assert_eq!(r.status, 200, "{}", r.body);
    }

    #[test]
    fn boundable_mode_rejects_a_duplicated_idempotency_key_on_orders_too() {
        // I7, orders route. Same policy, same header, the other write
        // route that reads it.
        let mut l = Ledger::default();
        let r = handle(
            &FailureModes::boundable(),
            &mut l,
            &post(
                "/v1/orders",
                "{}",
                &[
                    ("Authorization", "Capability nonce=n1"),
                    ("Idempotency-Key", "k1"),
                    ("Idempotency-Key", "k2"),
                ],
            ),
        );
        assert_eq!(r.status, 400, "{}", r.body);
        assert!(l.orders.is_empty());
    }
}
