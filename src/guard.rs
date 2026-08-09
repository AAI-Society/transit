//! `transit guard` — an enforcing reverse proxy.
//!
//! `decide` is the whole policy **and** the whole forward plan: method,
//! normalized path, query, final header list and canonical body. `serve`
//! executes that plan and chooses nothing itself. See the module-level
//! commentary above `decide` and `forward` for why the split is drawn there
//! rather than at the socket boundary.

use crate::corpus::Condition;
use crate::hostile::Request;
use crate::jcs::{canonicalize, digest};
use crate::json::{parse_strict, Json};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;

/// RFC 9110 §9.2.2. `PUT` and `DELETE` are idempotent, so a retry needs no
/// key — but they are emphatically mutating, which is a different question.
const IDEMPOTENT_METHODS: &[&str] = &["GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"];
/// Methods that change state, and therefore need a precondition. Deriving
/// this from idempotency exempted `PUT` and `DELETE` — the two methods that
/// exist to change things.
const MUTATING_METHODS: &[&str] = &["POST", "PUT", "PATCH", "DELETE"];
/// Anything else is refused rather than guessed at.
const ALLOWED_METHODS: &[&str] = &["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"];

/// Connection-specific headers an intermediary must not relay (RFC 9110
/// §7.6.1), plus `Expect` and the proxy-authentication pair. Relaying
/// `Transfer-Encoding` hands an attacker a CL/TE desync; relaying `Expect`
/// desynchronises the forwarding client's connection pool.
const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "expect",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "content-length",
    "host",
];

pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;
/// Rejection reasons are read by operators out of logs. Attacker-controlled
/// substrings reach them, so they are bounded and stripped of control
/// characters.
pub const MAX_REASON_LEN: usize = 200;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Enforcement {
    #[serde(default = "yes")]
    pub strict_ingestion: bool,
    #[serde(default = "yes")]
    pub require_idempotency_key: bool,
    #[serde(default = "yes")]
    pub require_state_precondition: bool,
    #[serde(default = "default_max_body")]
    pub max_body_bytes: usize,
    /// Cap on what the upstream may send back. Without one, a 200 MB response
    /// buffers in full — eight workers, about 1.6 GB resident.
    #[serde(default = "default_max_response")]
    pub max_response_bytes: usize,
    #[serde(default = "default_digest_header")]
    pub digest_header: Option<String>,
}

fn yes() -> bool {
    true
}
fn default_max_body() -> usize {
    DEFAULT_MAX_BODY_BYTES
}
fn default_max_response() -> usize {
    8 * 1024 * 1024
}
fn default_digest_header() -> Option<String> {
    Some("X-Transit-Digest".to_string())
}

impl Default for Enforcement {
    fn default() -> Self {
        Enforcement {
            strict_ingestion: true,
            require_idempotency_key: true,
            require_state_precondition: true,
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
            max_response_bytes: default_max_response(),
            digest_header: default_digest_header(),
        }
    }
}

/// A per-route rule. `require_parameters` is how C1 is enforced: name the
/// fields the endpoint would otherwise fill from its own state, and a request
/// omitting one is refused rather than silently completed downstream.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteRule {
    pub method: String,
    pub path_prefix: String,
    #[serde(default)]
    pub require_idempotency_key: Option<bool>,
    #[serde(default)]
    pub require_state_precondition: Option<bool>,
    #[serde(default)]
    pub require_parameters: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuardConfig {
    pub listen: String,
    pub upstream: String,
    #[serde(default)]
    pub enforce: Enforcement,
    #[serde(default)]
    pub route: Vec<RouteRule>,
}

#[derive(Debug, thiserror::Error)]
pub enum GuardError {
    #[error("could not read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error(
        "`strict_ingestion = false` is refused. It is the one rule this proxy rests on, \
         and a config that could switch it off is a config that can reintroduce the bug \
         it exists to prevent."
    )]
    StrictIngestionOff,
    #[error("could not bind {addr}: {detail}")]
    Bind { addr: String, detail: String },
}

/// Everything the upstream will see. Produced by `decide`, executed verbatim
/// by `serve` — so the request the policy judged is the request that is sent.
#[derive(Clone, Debug)]
pub struct Forward {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub digest: String,
}

#[derive(Clone, Debug)]
pub enum Decision {
    Forward(Forward),
    /// `condition` is `None` where the refusal is not a C1–C4 failure — an
    /// oversized body or an unusable media type is neither.
    Reject {
        status: u16,
        condition: Option<Condition>,
        reason: String,
    },
}

fn reject(status: u16, condition: Option<Condition>, reason: impl AsRef<str>) -> Decision {
    Decision::Reject {
        status,
        condition,
        reason: sanitize(reason.as_ref()),
    }
}

/// Bound the length and strip control characters. Parser errors quote the
/// offending key and numeric literal verbatim, both attacker-controlled, and
/// JSON escapes are decoded before the key is stored — so `{"a\nb":1,"a\nb":2}`
/// would otherwise put a real newline into a log line.
fn sanitize(s: &str) -> String {
    // `char::is_control()` is category Cc only, so U+2028 and U+2029 — line
    // breaks to every JS-based log viewer — survived it.
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_control() || c == '\u{2028}' || c == '\u{2029}' {
                ' '
            } else {
                c
            }
        })
        .collect();
    // Truncated by BYTES, and never mid-character. Taking 200 *chars* of a
    // reason quoting a multi-byte key can exceed the byte budget, and
    // truncating by a raw byte index can split a multi-byte UTF-8 sequence
    // and produce a string that fails to be valid UTF-8 (or, appended to
    // blindly, panics). Walking `chars()` and only pushing a whole character
    // when it still fits avoids both.
    let mut out = String::with_capacity(MAX_REASON_LEN);
    for c in cleaned.chars() {
        if out.len() + c.len_utf8() > MAX_REASON_LEN {
            break;
        }
        out.push(c);
    }
    out
}

/// Split a request target into a normalized path and its query.
///
/// Traversal is **refused, never resolved**. Resolving it would mean the
/// guard deciding on one path and a URL parser downstream deriving another,
/// which is exactly how a relaxed route rule became a way to reach every
/// mutating endpoint with C3 and C4 switched off.
pub fn normalize_target(target: &str) -> Result<(String, String), &'static str> {
    // `#` FIRST. A fragment is not part of a request target, but nothing in
    // HTTP stops a client sending one — and `url::Url`, which `ureq` parses
    // with, drops everything from `#` onward. Splitting only on `?` left the
    // guard deciding `/v1/transfer#z` (matching no route rule, so no
    // `require_parameters`) while the upstream received `/v1/transfer`. That
    // is the parameter-defaulting bypass, through the enforcement point, with
    // the guard's own digest header attached to it. Measured end to end
    // against the real hostile endpoint.
    if target.contains('#') {
        return Err("fragment in the request target");
    }
    let (raw_path, query) = match target.split_once('?') {
        Some((p, q)) => (p, q),
        None => (target, ""),
    };
    if raw_path.is_empty() || !raw_path.starts_with('/') {
        // Also refuses absolute-form (`http://host/path`) and the `*` target.
        // RFC 9112 §3.2.2 permits both to a proxy; refusing them is
        // fail-closed and deliberate, and DEPLOYING.md says so.
        return Err("request target must be an absolute path");
    }
    // An allow-list, not a deny-list. The earlier deny-list missed `#`, and
    // would equally have missed overlong UTF-8 (`%c0%ae`), double encoding
    // (`%2541`) and `;` path parameters, each of which some upstream router
    // normalizes differently from this one. The set is RFC 3986 `pchar`
    // (unreserved / pct-encoded / sub-delims / ":" / "@") minus `;`, so a
    // percent-encoded UTF-8 path segment, `~`, and `:`/`@` later in the path
    // all still pass — only the byte, not the decoded character, is checked
    // here.
    if !raw_path
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b"/-._~!$&'()*+,=:@%".contains(&b))
    {
        return Err("character outside the permitted path set in the request target");
    }
    let lowered = raw_path.to_ascii_lowercase();
    if lowered.contains("%2e") || lowered.contains("%2f") || lowered.contains("%25") {
        return Err("encoded path separator, dot segment or percent in the request target");
    }
    let mut out = String::with_capacity(raw_path.len());
    let trailing = raw_path.ends_with('/');
    for seg in raw_path.split('/') {
        if seg.is_empty() {
            continue;
        }
        if seg == "." || seg == ".." {
            return Err("dot segment in the request target");
        }
        out.push('/');
        out.push_str(seg);
    }
    // One branch, not two: `if out.is_empty() { .. } else if trailing { .. }`
    // has identical blocks and trips `clippy::if_same_then_else`, which is
    // denied.
    if out.is_empty() || trailing {
        out.push('/');
    }
    Ok((out, query.to_string()))
}

fn headers_named<'a>(req: &'a Request, name: &str) -> impl Iterator<Item = &'a str> {
    let name = name.to_ascii_lowercase();
    req.headers
        .iter()
        .filter(move |(k, _)| k.to_ascii_lowercase() == name)
        .map(|(_, v)| v.as_str())
}

fn single_header<'a>(req: &'a Request, name: &str) -> Result<Option<&'a str>, ()> {
    let mut it = headers_named(req, name);
    let first = it.next();
    if it.next().is_some() {
        return Err(());
    }
    Ok(first)
}

/// `application/json` or a `+json` structured suffix, parameters ignored.
/// A prefix match accepted `application/jsonfoo`; a `contains("+json")`
/// matched a parameter value.
fn is_json_media_type(value: &str) -> bool {
    let base = value
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    base == "application/json" || base.ends_with("+json")
}

fn route_matches(rule: &RouteRule, method: &str, path: &str) -> bool {
    if !rule.method.eq_ignore_ascii_case(method) {
        return false;
    }
    let p = rule.path_prefix.trim_end_matches('/');
    // Segment boundary, so `/v1/search` does not lend its relaxation to
    // `/v1/searching`.
    path == p || path.starts_with(&format!("{p}/"))
}

/// The whole policy and the whole forward plan, as a pure function.
pub fn decide(cfg: &GuardConfig, req: &Request) -> Decision {
    let method = req.method.to_ascii_uppercase();
    if !ALLOWED_METHODS.contains(&method.as_str()) {
        return reject(
            405,
            None,
            format!("method {method} is not allowed through this guard"),
        );
    }

    let (path, query) = match normalize_target(&req.path) {
        Ok(v) => v,
        Err(why) => return reject(400, None, why),
    };

    let rule = cfg.route.iter().find(|r| route_matches(r, &method, &path));
    let want_key = rule
        .and_then(|r| r.require_idempotency_key)
        .unwrap_or(cfg.enforce.require_idempotency_key);
    let want_pin = rule
        .and_then(|r| r.require_state_precondition)
        .unwrap_or(cfg.enforce.require_state_precondition);
    let want_params: &[String] = rule.map(|r| r.require_parameters.as_slice()).unwrap_or(&[]);

    if req.body.len() > cfg.enforce.max_body_bytes {
        return reject(
            413,
            None,
            format!(
                "body is {} bytes, over the {}-byte limit",
                req.body.len(),
                cfg.enforce.max_body_bytes
            ),
        );
    }

    let has_body = !req.body.trim().is_empty();
    if has_body && matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS") {
        return reject(400, None, format!("{method} carrying a body is refused"));
    }

    let content_type = match single_header(req, "content-type") {
        Ok(v) => v,
        Err(()) => return reject(400, None, "more than one Content-Type header"),
    };

    // C2 — strict ingestion, before anything else looks at the request.
    let parsed = if !has_body {
        None
    } else {
        match content_type {
            Some(ct) if is_json_media_type(ct) => {}
            _ => return reject(
                415,
                None,
                "body is not application/json; this guard forwards only what it can canonicalize",
            ),
        }
        match parse_strict(&req.body) {
            Ok(v) => Some(v),
            Err(e) => return reject(400, Some(Condition::C2), e.to_string()),
        }
    };

    // C1 — the parameters the endpoint would otherwise fill from its own state.
    if let Some(value) = &parsed {
        // `null` counts as absent. `Json::get` returns `Some(Json::Null)` for
        // `"fee_tier":null`, and the upstream reads the field with
        // `and_then(Json::as_string)` — which yields `None` and falls into
        // exactly the profile-defaulting branch this rule exists to stop. A
        // presence check against a type check is a bypass with no path
        // trickery at all, measured against the shipped vulnerable upstream
        // using the shipped config.
        let missing: Vec<&str> = want_params
            .iter()
            .filter(|p| matches!(value.get(p), None | Some(Json::Null)))
            .map(String::as_str)
            .collect();
        if !missing.is_empty() {
            return reject(
                422,
                Some(Condition::C1),
                format!("required parameters absent: {}", missing.join(", ")),
            );
        }
    } else if !want_params.is_empty() && MUTATING_METHODS.contains(&method.as_str()) {
        return reject(
            422,
            Some(Condition::C1),
            "a body is required and none was sent",
        );
    }

    // C3 — only where a retry could not be told from a replay.
    if want_key && !IDEMPOTENT_METHODS.contains(&method.as_str()) {
        match single_header(req, "idempotency-key") {
            Err(()) => return reject(400, None, "more than one Idempotency-Key header"),
            Ok(None) => {
                return reject(
                    428,
                    Some(Condition::C3),
                    format!("{method} is not idempotent and carries no Idempotency-Key"),
                )
            }
            Ok(Some(_)) => {}
        }
    }

    // C4 — on every method that changes state.
    if want_pin
        && MUTATING_METHODS.contains(&method.as_str())
        && single_header(req, "if-match").unwrap_or(None).is_none()
    {
        return reject(
            428,
            Some(Condition::C4),
            "no If-Match precondition; the effect could depend on state that moved after signing",
        );
    }

    let (body, dg) = match &parsed {
        None => (String::new(), String::new()),
        Some(v) => match (canonicalize(v), digest(v)) {
            (Ok(b), Ok(d)) => (b, d),
            (Err(e), _) | (_, Err(e)) => return reject(400, Some(Condition::C2), e.to_string()),
        },
    };

    // Build the header list the upstream will see. Hop-by-hop headers, every
    // header named by `Connection`, and any client-supplied digest header are
    // all dropped before ours is added.
    let connection_named: Vec<String> = headers_named(req, "connection")
        .flat_map(|v| {
            v.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .collect();
    let digest_name = cfg.enforce.digest_header.clone();
    let mut headers: Vec<(String, String)> = req
        .headers
        .iter()
        .filter(|(k, _)| {
            let lk = k.to_ascii_lowercase();
            !HOP_BY_HOP.contains(&lk.as_str())
                && !connection_named.contains(&lk)
                && !lk.eq_ignore_ascii_case("content-type")
                // Stripped unconditionally, not only when one is added:
                // setting `digest_header = None` otherwise switched off the
                // stripping too and relayed a client-supplied value.
                && !lk.eq_ignore_ascii_case("x-transit-digest")
                && digest_name
                    .as_ref()
                    .map(|d| !lk.eq_ignore_ascii_case(d))
                    .unwrap_or(true)
        })
        .cloned()
        .collect();
    if !body.is_empty() {
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
    }
    if let (Some(name), false) = (digest_name, dg.is_empty()) {
        headers.push((name, dg.clone()));
    }

    Decision::Forward(Forward {
        method,
        path,
        query,
        headers,
        body,
        digest: dg,
    })
}

pub fn parse_config(text: &str) -> Result<GuardConfig, GuardError> {
    let cfg: GuardConfig = toml::from_str(text).map_err(|source| GuardError::Parse {
        path: "<config>".to_string(),
        source,
    })?;
    if !cfg.enforce.strict_ingestion {
        return Err(GuardError::StrictIngestionOff);
    }
    Ok(cfg)
}

pub fn load_config(path: &Path) -> Result<GuardConfig, GuardError> {
    let text = std::fs::read_to_string(path).map_err(|source| GuardError::Io {
        path: path.display().to_string(),
        source,
    })?;
    parse_config(&text).map_err(|e| match e {
        GuardError::Parse { source, .. } => GuardError::Parse {
            path: path.display().to_string(),
            source,
        },
        other => other,
    })
}

/// Execute a decision. Every request is handled on its own thread, because a
/// small fixed pool lets a handful of slow clients occupy every worker's body
/// read forever — and once every worker is stuck, nothing is left calling
/// `server.recv()`, so a perfectly normal request queued behind them never
/// gets served either. Measured directly: eight connections that sent a
/// request head declaring a body and then never finished sending it stopped
/// the proxy outright, including for clients that had nothing to do with
/// those eight. Spawning a thread per request keeps the accept/dispatch step
/// always available, so one slow client can only ever block itself — the
/// `max_body_bytes` cap still bounds how much any single one can make the
/// proxy hold, and `serve` itself performs no reads, so it can never be the
/// thing that blocks.
pub fn serve(cfg: &GuardConfig) -> Result<(), GuardError> {
    let server = tiny_http::Server::http(&cfg.listen).map_err(|e| GuardError::Bind {
        addr: cfg.listen.clone(),
        detail: e.to_string(),
    })?;
    println!(
        "transit guard on http://{} → {}\nfail-closed: strict I-JSON ingestion; \
         idempotency key {}; state precondition {}",
        cfg.listen,
        cfg.upstream,
        if cfg.enforce.require_idempotency_key {
            "required"
        } else {
            "not required"
        },
        if cfg.enforce.require_state_precondition {
            "required"
        } else {
            "not required"
        },
    );

    let cfg = std::sync::Arc::new(cfg.clone());
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(30))
        // `ureq` follows five redirects by default. Left on, an open redirect
        // anywhere upstream turns this proxy into an unauthenticated SSRF
        // pivot *inside* the sidecar's trust boundary: the guard emits a
        // request `decide` never planned, uncanonicalized and unlabelled, to
        // a host the attacker chose — and the client never sees the 3xx,
        // contradicting this function's own promise to relay it.
        .redirects(0)
        .build();

    // A single dispatcher: it does nothing but call `recv()` and hand the
    // request to its own thread, so it is never the thing a slow client can
    // occupy. `ureq::Agent` is cheaply `Clone` (it wraps an `Arc` inside).
    while let Ok(raw) = server.recv() {
        let cfg = cfg.clone();
        let agent = agent.clone();
        std::thread::spawn(move || handle_one(&cfg, &agent, raw));
    }
    Ok(())
}

fn handle_one(cfg: &GuardConfig, agent: &ureq::Agent, mut raw: tiny_http::Request) {
    // `Connection: upgrade` makes tiny_http hand back the raw socket with no
    // length bound, so a client that then sends nothing would block forever.
    if raw.headers().iter().any(|h| {
        h.field.as_str().as_str().eq_ignore_ascii_case("connection")
            && h.value.as_str().to_ascii_lowercase().contains("upgrade")
    }) {
        let _ = raw.respond(json_response(
            400,
            r#"{"error":"upgrade is not supported"}"#,
        ));
        return;
    }

    // Bounded read, and a read error is a refusal — never an empty body.
    // `read_to_string` truncates on invalid UTF-8, which would otherwise turn
    // an unreadable request into a well-formed bodyless one and forward it.
    let limit = cfg.enforce.max_body_bytes as u64;
    let mut body = String::new();
    let reader = raw.as_reader();
    let read = reader.take(limit + 1).read_to_string(&mut body);
    if read.is_err() {
        let _ = raw.respond(json_response(400, r#"{"error":"body is not valid UTF-8"}"#));
        return;
    }
    if body.len() as u64 > limit {
        let _ = raw.respond(json_response(413, r#"{"error":"body too large"}"#));
        return;
    }

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

    let response = match decide(cfg, &req) {
        Decision::Reject {
            status,
            condition,
            reason,
        } => {
            eprintln!(
                "REJECT {} {} [{}] {}",
                sanitize(&req.method),
                sanitize(&req.path),
                condition.map(|c| c.title()).unwrap_or("policy"),
                reason
            );
            let body = format!(
                r#"{{"error":"rejected by transit guard","condition":{},"reason":{}}}"#,
                serde_json::to_string(&condition.map(|c| c.title()))
                    .unwrap_or_else(|_| "null".into()),
                serde_json::to_string(&reason).unwrap_or_else(|_| "\"\"".into())
            );
            json_response(status, &body)
        }
        Decision::Forward(f) => match forward(cfg, agent, &f) {
            Ok(r) => r,
            Err(detail) => json_response(
                502,
                &format!(
                    r#"{{"error":"upstream unreachable","detail":{}}}"#,
                    serde_json::to_string(&sanitize(&detail)).unwrap_or_else(|_| "\"\"".into())
                ),
            ),
        },
    };
    let _ = raw.respond(response);
}

fn json_response(status: u16, body: &str) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let mut r = tiny_http::Response::from_string(body).with_status_code(status);
    if let Ok(h) = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]) {
        r.add_header(h);
    }
    r
}

/// Relay the upstream's status, headers and body back unchanged. Dropping
/// them would break `Location`, `WWW-Authenticate`, `Set-Cookie` and `ETag` —
/// and C4's own `If-Match` flow depends on the client having seen an `ETag`.
fn forward(
    cfg: &GuardConfig,
    agent: &ureq::Agent,
    f: &Forward,
) -> Result<tiny_http::Response<std::io::Cursor<Vec<u8>>>, String> {
    let url = if f.query.is_empty() {
        format!("{}{}", cfg.upstream.trim_end_matches('/'), f.path)
    } else {
        format!(
            "{}{}?{}",
            cfg.upstream.trim_end_matches('/'),
            f.path,
            f.query
        )
    };
    // `agent.request` preserves the method verbatim rather than mapping it.
    let mut out = agent.request(&f.method, &url);
    for (k, v) in &f.headers {
        out = out.set(k, v);
    }
    let sent = if f.body.is_empty() {
        out.call()
    } else {
        out.send_string(&f.body)
    };
    let resp = match sent {
        Ok(r) => r,
        Err(ureq::Error::Status(_, r)) => r,
        Err(e) => return Err(e.to_string()),
    };

    let status = resp.status();
    // The response direction needs the same treatment as the request
    // direction: hop-by-hop headers stripped, and every header the upstream's
    // own `Connection` names stripped with them.
    let conn_named: Vec<String> = resp
        .all("connection")
        .iter()
        .flat_map(|v| {
            v.split(',')
                .map(|s| s.trim().to_ascii_lowercase())
                .collect::<Vec<_>>()
        })
        .collect();
    let mut relayed: Vec<(String, String)> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for name in resp.headers_names() {
        let lower = name.to_ascii_lowercase();
        if HOP_BY_HOP.contains(&lower.as_str()) || conn_named.contains(&lower) {
            continue;
        }
        // `headers_names()` yields a name once per occurrence and `header()`
        // always returns the first, so the naive loop duplicated one value and
        // silently dropped the rest. Measured: `Set-Cookie: a=1` twice, and
        // `b=2` gone — which breaks session rotation, `WWW-Authenticate`,
        // `Link` and `Vary`.
        if seen.contains(&lower) {
            continue;
        }
        seen.push(lower);
        for v in resp.all(&name) {
            relayed.push((name.clone(), v.to_string()));
        }
    }
    // Bounded. `into_reader` sidesteps ureq's 10 MB `into_string` cap, and
    // replacing that cap with none let a 200 MB upstream response buffer in
    // full — about 1.6 GB resident across the eight workers.
    let cap = cfg.enforce.max_response_bytes;
    let mut bytes = Vec::new();
    resp.into_reader()
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > cap {
        return Err(format!("upstream response exceeded {cap} bytes"));
    }

    let mut out = tiny_http::Response::from_data(bytes).with_status_code(status);
    for (k, v) in relayed {
        if let Ok(h) = tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()) {
            out.add_header(h);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> GuardConfig {
        GuardConfig {
            listen: "127.0.0.1:8080".into(),
            upstream: "http://127.0.0.1:8787".into(),
            enforce: Enforcement::default(),
            route: Vec::new(),
        }
    }

    fn req(method: &str, target: &str, body: &str, headers: &[(&str, &str)]) -> Request {
        let mut h: Vec<(String, String)> = headers
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        if !body.is_empty()
            && !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            h.push(("Content-Type".into(), "application/json".into()));
        }
        Request {
            method: method.into(),
            path: target.into(),
            headers: h,
            body: body.into(),
        }
    }

    fn ok() -> Vec<(&'static str, &'static str)> {
        vec![("Idempotency-Key", "k1"), ("If-Match", "0")]
    }

    fn forwarded(d: Decision) -> Forward {
        match d {
            Decision::Forward(f) => f,
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    fn rejected(d: Decision) -> (u16, Option<Condition>, String) {
        match d {
            Decision::Reject {
                status,
                condition,
                reason,
            } => (status, condition, reason),
            other => panic!("expected Reject, got {other:?}"),
        }
    }

    // --- the happy path, and that it is canonical -------------------------

    #[test]
    fn a_conforming_request_forwards_the_canonical_body_not_the_wire_body() {
        let f = forwarded(decide(
            &cfg(),
            &req(
                "POST",
                "/v1/transfer",
                r#"{ "to":"acct-9" , "amount":100 }"#,
                &ok(),
            ),
        ));
        assert_eq!(f.body, r#"{"amount":100,"to":"acct-9"}"#);
        assert_eq!(f.method, "POST");
        assert_eq!(f.path, "/v1/transfer");
        assert_eq!(f.digest.len(), 64);
    }

    // --- the five criticals from the pre-flight ---------------------------

    #[test]
    fn a_dot_segment_cannot_borrow_a_relaxed_route() {
        // Critical 1. With the shipped config's /v1/search relaxation, this
        // reached /v1/transfer with C3 and C4 unenforced.
        let mut c = cfg();
        c.route.push(RouteRule {
            method: "POST".into(),
            path_prefix: "/v1/search".into(),
            require_idempotency_key: Some(false),
            require_state_precondition: Some(false),
            require_parameters: Vec::new(),
        });
        for target in [
            "/v1/search/../transfer",
            "/v1/search/%2e%2e/transfer",
            "/v1/search/..%2Ftransfer",
        ] {
            let (status, _, _) = rejected(decide(&c, &req("POST", target, r#"{"a":1}"#, &[])));
            assert_eq!(status, 400, "{target} was not refused");
        }
    }

    #[test]
    fn a_route_prefix_matches_only_on_a_segment_boundary() {
        // `/v1/searching` must not borrow `/v1/search`'s relaxation.
        let mut c = cfg();
        c.route.push(RouteRule {
            method: "POST".into(),
            path_prefix: "/v1/search".into(),
            require_idempotency_key: Some(false),
            require_state_precondition: Some(false),
            require_parameters: Vec::new(),
        });
        assert!(matches!(
            decide(&c, &req("POST", "/v1/search", r#"{"q":"x"}"#, &[])),
            Decision::Forward(_)
        ));
        let (status, condition, _) = rejected(decide(
            &c,
            &req("POST", "/v1/searching", r#"{"q":"x"}"#, &[]),
        ));
        assert_eq!(status, 428);
        assert_eq!(condition, Some(Condition::C3));
    }

    #[test]
    fn the_method_reaching_the_upstream_is_the_one_the_policy_judged() {
        // Critical 2. Every allowed method must survive unchanged.
        for m in ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"] {
            let body = if m == "GET" || m == "HEAD" || m == "OPTIONS" {
                ""
            } else {
                r#"{"a":1}"#
            };
            let f = forwarded(decide(&cfg(), &req(m, "/v1/thing", body, &ok())));
            assert_eq!(f.method, m);
        }
        // And an unknown method is refused rather than coerced into a POST.
        let (status, _, _) = rejected(decide(&cfg(), &req("FROB", "/v1/thing", "", &ok())));
        assert_eq!(status, 405);
    }

    #[test]
    fn a_head_request_carrying_a_body_is_refused() {
        // Critical 2's delivery vehicle: a body on a method the policy treats
        // as non-mutating.
        let (status, _, _) = rejected(decide(
            &cfg(),
            &req("HEAD", "/v1/transfer", r#"{"to":"x"}"#, &ok()),
        ));
        assert_eq!(status, 400);
    }

    #[test]
    fn a_client_supplied_digest_header_cannot_survive() {
        // Critical 3. The header the guard exists to make trustworthy must
        // never arrive twice, in any casing.
        let f = forwarded(decide(
            &cfg(),
            &req(
                "POST",
                "/v1/transfer",
                r#"{"a":1}"#,
                &[
                    ("Idempotency-Key", "k"),
                    ("If-Match", "0"),
                    ("X-Transit-Digest", "forged"),
                    ("x-transit-digest", "also-forged"),
                ],
            ),
        ));
        let n = f
            .headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("x-transit-digest"))
            .count();
        assert_eq!(n, 1, "exactly one digest header: {:?}", f.headers);
        let (_, v) = f
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-transit-digest"))
            .unwrap();
        assert_eq!(*v, f.digest);
        assert_ne!(v, "forged");
    }

    #[test]
    fn hop_by_hop_headers_are_not_relayed() {
        // Critical 4. RFC 9110 §7.6.1, plus Expect and Proxy-*.
        let f = forwarded(decide(
            &cfg(),
            &req(
                "POST",
                "/v1/transfer",
                r#"{"a":1}"#,
                &[
                    ("Idempotency-Key", "k"),
                    ("If-Match", "0"),
                    ("Connection", "X-Secret, keep-alive"),
                    ("X-Secret", "leak"),
                    ("Transfer-Encoding", "identity"),
                    ("TE", "trailers"),
                    ("Upgrade", "websocket"),
                    ("Expect", "100-continue"),
                    ("Proxy-Authorization", "Basic x"),
                    ("Keep-Alive", "timeout=5"),
                    ("Content-Length", "9999"),
                    ("Host", "elsewhere"),
                ],
            ),
        ));
        for banned in [
            "connection",
            "x-secret",
            "transfer-encoding",
            "te",
            "upgrade",
            "expect",
            "proxy-authorization",
            "keep-alive",
            "content-length",
            "host",
        ] {
            assert!(
                !f.headers
                    .iter()
                    .any(|(k, _)| k.eq_ignore_ascii_case(banned)),
                "{banned} was relayed: {:?}",
                f.headers
            );
        }
        // The ordinary ones survive.
        assert!(f
            .headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("idempotency-key")));
    }

    // --- C1, which the earlier draft did not enforce at all ---------------

    #[test]
    fn a_route_can_require_the_parameters_the_endpoint_would_otherwise_default() {
        // The parameter-defaulting bypass, stopped. Without this the guard
        // forwards `{"to":..,"amount":..}` and the endpoint fills fee_tier
        // from profile state the signature never covered.
        let mut c = cfg();
        c.route.push(RouteRule {
            method: "POST".into(),
            path_prefix: "/v1/transfer".into(),
            require_idempotency_key: None,
            require_state_precondition: None,
            require_parameters: vec!["to".into(), "amount".into(), "fee_tier".into()],
        });
        let (status, condition, reason) = rejected(decide(
            &c,
            &req(
                "POST",
                "/v1/transfer",
                r#"{"to":"acct-9","amount":100}"#,
                &ok(),
            ),
        ));
        assert_eq!(status, 422);
        assert_eq!(condition, Some(Condition::C1));
        assert!(reason.contains("fee_tier"), "{reason}");

        // Supplied explicitly, it goes through.
        let body = r#"{"to":"acct-9","amount":100,"fee_tier":"standard"}"#;
        assert!(matches!(
            decide(&c, &req("POST", "/v1/transfer", body, &ok())),
            Decision::Forward(_)
        ));
    }

    // --- C3 and C4, on the right methods ---------------------------------

    #[test]
    fn an_idempotency_key_is_demanded_only_where_it_is_meaningful() {
        // POST and PATCH are not idempotent; PUT and DELETE are.
        for m in ["POST", "PATCH"] {
            let (_, condition, _) = rejected(decide(
                &cfg(),
                &req(m, "/v1/t", r#"{"a":1}"#, &[("If-Match", "0")]),
            ));
            assert_eq!(condition, Some(Condition::C3), "{m}");
        }
        for m in ["PUT", "DELETE"] {
            assert!(
                matches!(
                    decide(&cfg(), &req(m, "/v1/t", r#"{"a":1}"#, &[("If-Match", "0")])),
                    Decision::Forward(_)
                ),
                "{m}"
            );
        }
    }

    #[test]
    fn a_state_precondition_is_demanded_on_every_mutating_method() {
        // The earlier draft derived this from idempotency and so exempted
        // PUT and DELETE — the two definitionally state-changing methods.
        for m in ["POST", "PUT", "PATCH", "DELETE"] {
            let (status, condition, _) = rejected(decide(
                &cfg(),
                &req(m, "/v1/t", r#"{"a":1}"#, &[("Idempotency-Key", "k")]),
            ));
            assert_eq!(status, 428, "{m}");
            assert_eq!(condition, Some(Condition::C4), "{m}");
        }
        assert!(matches!(
            decide(&cfg(), &req("GET", "/v1/t", "", &[])),
            Decision::Forward(_)
        ));
    }

    // --- content type ----------------------------------------------------

    #[test]
    fn the_content_type_the_guard_judged_is_the_one_the_upstream_receives() {
        // Two Content-Types: the guard read the first, ureq relayed the last.
        let (status, _, _) = rejected(decide(
            &cfg(),
            &req(
                "POST",
                "/v1/t",
                r#"{"a":1}"#,
                &[
                    ("Idempotency-Key", "k"),
                    ("If-Match", "0"),
                    ("Content-Type", "application/json"),
                    ("Content-Type", "text/plain"),
                ],
            ),
        ));
        assert_eq!(status, 400, "a duplicated Content-Type must be refused");

        // Parameters are allowed; the forwarded type is normalized.
        let f = forwarded(decide(
            &cfg(),
            &req(
                "POST",
                "/v1/t",
                r#"{"a":1}"#,
                &[
                    ("Idempotency-Key", "k"),
                    ("If-Match", "0"),
                    ("Content-Type", "Application/JSON; charset=utf-8"),
                ],
            ),
        ));
        let (_, ct) = f
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .unwrap();
        assert_eq!(ct, "application/json");
    }

    #[test]
    fn a_media_type_that_merely_looks_like_json_is_refused() {
        for ct in ["application/jsonfoo", "text/plain; x=+json", "text/plain"] {
            let (status, _, _) = rejected(decide(
                &cfg(),
                &req(
                    "POST",
                    "/v1/t",
                    r#"{"a":1}"#,
                    &[
                        ("Idempotency-Key", "k"),
                        ("If-Match", "0"),
                        ("Content-Type", ct),
                    ],
                ),
            ));
            assert_eq!(status, 415, "{ct}");
        }
    }

    // --- fail closed ------------------------------------------------------

    #[test]
    fn every_corpus_payload_is_refused_for_the_right_reason() {
        // Asserting the status and the condition, not merely that something
        // was refused — a `decide` that answered 413 to everything would pass
        // a bare "is it rejected" loop.
        for case in crate::corpus::cases() {
            let (status, condition, _) =
                rejected(decide(&cfg(), &req("POST", "/v1/t", &case.payload, &ok())));
            assert_eq!(status, 400, "case `{}`", case.name);
            assert_eq!(condition, Some(Condition::C2), "case `{}`", case.name);
        }
        // The negative half: a benign object of the same shape goes through,
        // so the loop above distinguishes "strict" from "refuses everything".
        assert!(matches!(
            decide(
                &cfg(),
                &req("POST", "/v1/t", r#"{"to":"acct-9","amount":100}"#, &ok())
            ),
            Decision::Forward(_)
        ));
    }

    #[test]
    fn an_oversized_body_is_refused_without_a_condition_label() {
        // 413 and 415 are not representation-injectivity failures, and
        // labelling them C2 would pollute the field the whole tool reports on.
        let big = format!(r#"{{"a":"{}"}}"#, "x".repeat(2 * 1024 * 1024));
        let (status, condition, _) = rejected(decide(&cfg(), &req("POST", "/v1/t", &big, &ok())));
        assert_eq!(status, 413);
        assert_eq!(condition, None);
    }

    #[test]
    fn strict_ingestion_cannot_be_switched_off() {
        // The config field exists so a deployment can be audited. It must not
        // be auditable to a lie.
        let toml = r#"
listen = "127.0.0.1:8080"
upstream = "http://127.0.0.1:8787"
[enforce]
strict_ingestion = false
"#;
        assert!(matches!(
            parse_config(toml),
            Err(GuardError::StrictIngestionOff)
        ));
    }

    // --- diagnostics ------------------------------------------------------

    #[test]
    fn a_rejection_reason_cannot_inject_into_a_log_line() {
        // The parser's own errors quote the offending key and numeric
        // literal, both attacker-controlled, and JSON escapes are decoded
        // before the key is stored — so a duplicate key spelled "a\nb" puts a
        // real newline into the reason.
        let (_, _, reason) = rejected(decide(
            &cfg(),
            &req("POST", "/v1/t", "{\"a\\nb\":1,\"a\\nb\":2}", &ok()),
        ));
        assert!(
            !reason.contains('\n'),
            "newline reached the reason: {reason:?}"
        );
        assert!(
            !reason.chars().any(|c| c.is_control()),
            "control char in {reason:?}"
        );
        assert!(reason.len() <= MAX_REASON_LEN);
    }

    #[test]
    fn malformed_input_never_panics() {
        let deep = "[".repeat(200_000);
        for body in ["", "   ", "{", "\u{feff}{}", &deep] {
            let _ = decide(&cfg(), &req("POST", "/v1/t", body, &ok()));
        }
        for target in ["", "//", "/a//b", "/%", "/%zz", "/../..", "/a?b=%2e%2e"] {
            let _ = decide(&cfg(), &req("GET", target, "", &[]));
        }
    }

    #[test]
    fn normalization_keeps_the_query_and_rejects_traversal() {
        assert_eq!(
            normalize_target("/v1/t?a=1&b=2").unwrap(),
            ("/v1/t".to_string(), "a=1&b=2".to_string())
        );
        assert_eq!(normalize_target("/v1//t/").unwrap().0, "/v1/t/");
        for bad in ["/a/../b", "/a/%2e%2e/b", "/a/./b", "../x", "/a/..%2fb"] {
            assert!(normalize_target(bad).is_err(), "{bad}");
        }
    }
}
