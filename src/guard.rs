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
    /// Cap on requests being handled at once. `serve` gives every admitted
    /// request its own thread rather than a small fixed pool, precisely so a
    /// handful of slow clients cannot starve everyone behind them — but a
    /// thread per request with no upper bound is its own failure mode.
    /// Measured directly: 8,305 concurrent idle-body sockets exhausted the
    /// OS thread limit, and the resulting `thread::spawn` failure — a panic,
    /// by design, in `std` — landed on the dispatcher's own thread and took
    /// the whole process down with it. Past this cap, a request is shed with
    /// 503 immediately, without spawning a thread or reading a byte of it.
    #[serde(default = "default_max_concurrent_requests")]
    pub max_concurrent_requests: usize,
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
fn default_max_concurrent_requests() -> usize {
    256
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
            max_concurrent_requests: default_max_concurrent_requests(),
            digest_header: default_digest_header(),
        }
    }
}

/// The JSON type a required parameter must have to count as supplied.
///
/// Fix round 1, C1: a presence check alone is not enough. The shipped
/// upstream reads `fee_tier` with `.and_then(Json::as_string)`, which
/// returns `None` — the same as "absent" — for `false`, `0`, `[]`, `{}` and
/// `null` alike, and then falls into the profile-defaulting branch this rule
/// exists to close. A check that enumerated the rejected shapes (`Json::Null`
/// alone) caught only the one the reviewer happened to name; the class is
/// "any value the reader on the other end cannot use", which is exactly
/// "wrong type", not "specifically null".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ParamType {
    String,
    Number,
    Bool,
    Array,
    Object,
}

impl Default for ParamType {
    /// Most parameters this rule protects are read with `as_string`
    /// upstream (recipients, tiers, identifiers); a parameter read some
    /// other way names its type explicitly in the route config.
    fn default() -> Self {
        ParamType::String
    }
}

impl ParamType {
    fn matches(self, v: &Json) -> bool {
        match self {
            ParamType::String => matches!(v, Json::String(_)),
            ParamType::Number => matches!(v, Json::Number(_)),
            ParamType::Bool => matches!(v, Json::Bool(_)),
            ParamType::Array => matches!(v, Json::Array(_)),
            ParamType::Object => matches!(v, Json::Object(_)),
        }
    }
}

/// One entry in a route's `require_parameters`. In TOML this is either a
/// bare string (`"to"`, defaulting to `type = "string"`) or a table
/// (`{ name = "amount", type = "number" }`) — `Json::Null` never matches
/// either variant's type, so a `null` value is refused the same way a
/// wrong-type one is, with no separate case needed for it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequiredParam {
    Name(String),
    Typed {
        name: String,
        #[serde(default)]
        r#type: ParamType,
    },
}

impl RequiredParam {
    pub fn name(&self) -> &str {
        match self {
            RequiredParam::Name(n) => n,
            RequiredParam::Typed { name, .. } => name,
        }
    }

    pub fn param_type(&self) -> ParamType {
        match self {
            RequiredParam::Name(_) => ParamType::default(),
            RequiredParam::Typed { r#type, .. } => *r#type,
        }
    }
}

impl From<&str> for RequiredParam {
    fn from(name: &str) -> Self {
        RequiredParam::Name(name.to_string())
    }
}

/// A per-route rule. `require_parameters` is how C1 is enforced: name the
/// fields the endpoint would otherwise fill from its own state, and a request
/// omitting one, or supplying it as the wrong JSON type, is refused rather
/// than silently completed downstream.
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
    pub require_parameters: Vec<RequiredParam>,
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
///
/// Fix round 1, C3: the previous version matched route rules against the
/// still-*encoded* text, checking only for the literal substrings `%2e`,
/// `%2f` and `%25` — so it caught a dot-segment or slash spelled exactly
/// those three ways and nothing else. `/v1/tra%6Esfer` (an ordinary `n`,
/// percent-encoded), `/v1/%74ransfer`, `/v1/transfe%72` and `/v1/TRANSFER`
/// all reached `/v1/transfer` at the upstream while matching no route rule
/// here, with `require_parameters` and every other per-route check switched
/// off for them — measured end to end against the shipped hostile endpoint
/// and the shipped config. Percent-encoding is not a small set of
/// dangerous spellings to deny; it is *every* byte a client can choose to
/// write two different ways, so the fix decodes once and matches routes
/// against the result, rather than pattern-matching the encoding.
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
        // Also refuses absolute-form (`http://host/path`) and the `*`
        // target. RFC 9112 §3.2.2 permits both to a proxy; refusing them is
        // fail-closed and deliberate — this proxy has one upstream, named in
        // its own config, and never needs a client to name one for it.
        return Err("request target must be an absolute path");
    }

    // Percent-decode exactly once, and treat that single pass as
    // authoritative for BOTH policy matching and what is forwarded, so the
    // two can never disagree about what the path says. An encoded `/` or a
    // NUL byte is refused rather than decoded: turning `%2f` into a literal
    // `/` would let this proxy and whatever the request eventually reaches
    // disagree about how many path segments there are (most routers do not
    // decode it before matching; some do), which is exactly the
    // two-parsers-one-input situation this function exists to avoid.
    let decoded = percent_decode(raw_path)?;
    // Refused a second time, not decoded a second time: a target that still
    // *looks* like a percent-escape after one decode pass (`%2541` decodes
    // to `%41`, which still reads as an escape) was encoded more than once,
    // and there is no principled way to guess how many passes the client
    // intended — so it is refused rather than resolved, the same policy
    // this function already applies to traversal.
    if contains_percent_escape(&decoded) {
        return Err("ambiguously multiply-encoded request target");
    }

    // An allow-list, checked on the DECODED text rather than the wire text —
    // checking the wire text is exactly what let a re-spelled `%6E` (an
    // ordinary `n`) sail past a check that only ever looked at the bytes the
    // client chose to send. Non-ASCII text is left alone: a percent-encoded
    // UTF-8 path segment decodes to exactly this. Every ASCII byte is
    // checked against RFC 3986 `pchar` (unreserved / sub-delims / ":" / "@"
    // / "%") minus `;`, refused deliberately since some upstream routers
    // treat it as a path-parameter delimiter and this one does not.
    if decoded
        .bytes()
        .any(|b| b.is_ascii() && !(b.is_ascii_alphanumeric() || b"/-._~!$&'()*+,=:@%".contains(&b)))
    {
        return Err("character outside the permitted path set in the request target");
    }

    let mut out = String::with_capacity(decoded.len());
    let trailing = decoded.ends_with('/');
    for seg in decoded.split('/') {
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

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-decode `s`, exactly once. An encoded `/` or NUL is refused rather
/// than decoded (see `normalize_target`); a truncated or malformed escape,
/// or one that decodes to invalid UTF-8 (the overlong and non-shortest-form
/// encodings historically used to smuggle `/` and `.` past a router that
/// validated the wire text), is refused outright.
fn percent_decode(s: &str) -> Result<String, &'static str> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 3 > bytes.len() {
                return Err("truncated percent-escape in the request target");
            }
            let byte = match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                (Some(hi), Some(lo)) => (hi << 4) | lo,
                _ => return Err("invalid percent-escape in the request target"),
            };
            if byte == b'/' || byte == 0 {
                return Err("an encoded path separator or NUL in the request target");
            }
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "the request target decodes to invalid UTF-8")
}

/// True if `s` contains a `%` immediately followed by two hex digits — i.e.,
/// still looks like a percent-escape after one decode pass, which means the
/// original target was encoded more than once. A literal `%` that decoded
/// from `%25` and is not followed by anything hex-shaped (`50%off`) does not
/// trip this, and is left alone: `contains_percent_escape` only ever runs on
/// text that has already survived one full `percent_decode` pass, so a
/// residual escape-shaped substring here can only mean a second layer of
/// encoding, never a decode failure.
fn contains_percent_escape(s: &str) -> bool {
    let b = s.as_bytes();
    (0..b.len()).any(|i| {
        b[i] == b'%'
            && i + 2 < b.len()
            && hex_val(b[i + 1]).is_some()
            && hex_val(b[i + 2]).is_some()
    })
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

/// `path` is `normalize_target`'s decoded, structurally-clean output.
/// Matched case-insensitively (ASCII only — path segments in practice are
/// ASCII identifiers, and a full Unicode case fold is not attempted): some
/// upstreams route case-insensitively, and `/v1/TRANSFER` reaching a
/// route's rules the same as `/v1/transfer` is the conservative direction
/// to be wrong in — the alternative lets a re-cased path carry `C1`'s
/// `require_parameters` off entirely, which was reachable end to end
/// against the shipped hostile endpoint. The path forwarded to the upstream
/// keeps its original case; only the match is case-folded.
fn route_matches(rule: &RouteRule, method: &str, path: &str) -> bool {
    if !rule.method.eq_ignore_ascii_case(method) {
        return false;
    }
    let p = rule.path_prefix.trim_end_matches('/').to_ascii_lowercase();
    let path = path.to_ascii_lowercase();
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
    let want_params: &[RequiredParam] =
        rule.map(|r| r.require_parameters.as_slice()).unwrap_or(&[]);

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

    // C1 — the parameters the endpoint would otherwise fill from its own
    // state. A parameter counts as supplied only when it is present AND of
    // the type its route rule names — never merely present. `Json::Null`
    // matches no `ParamType`, so it is refused the same way `false`, `0`,
    // `[]` and `{}` are: the class is "the reader on the other end cannot
    // use this value", and enumerating only `Json::Null` as that class was
    // itself the bypass (measured: `"fee_tier":false` went through and was
    // silently defaulted to `"priority"` downstream).
    if let Some(value) = &parsed {
        let missing: Vec<&str> = want_params
            .iter()
            .filter(|p| match value.get(p.name()) {
                Some(v) => !p.param_type().matches(v),
                None => true,
            })
            .map(|p| p.name())
            .collect();
        if !missing.is_empty() {
            return reject(
                422,
                Some(Condition::C1),
                format!(
                    "required parameters absent or the wrong type: {}",
                    missing.join(", ")
                ),
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

/// A guard against a permit leaking: releases its slot whether `handle_one`
/// returns normally or panics.
struct ConcurrencyPermit {
    inflight: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl Drop for ConcurrencyPermit {
    fn drop(&mut self) {
        self.inflight
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Admit one more request, or refuse if `max` are already in flight. A
/// simple CAS loop rather than a `Mutex`, so admission never itself blocks —
/// the dispatcher must stay free to keep calling `recv()`.
fn try_admit(
    inflight: &std::sync::Arc<std::sync::atomic::AtomicUsize>,
    max: usize,
) -> Option<ConcurrencyPermit> {
    use std::sync::atomic::Ordering;
    let mut current = inflight.load(Ordering::SeqCst);
    loop {
        if current >= max {
            return None;
        }
        match inflight.compare_exchange(current, current + 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => {
                return Some(ConcurrencyPermit {
                    inflight: inflight.clone(),
                })
            }
            Err(actual) => current = actual,
        }
    }
}

/// Execute a decision. Every ADMITTED request is handled on its own thread,
/// because a small fixed pool lets a handful of slow clients occupy every
/// worker's body read forever — and once every worker is stuck, nothing is
/// left calling `server.recv()`, so a perfectly normal request queued behind
/// them never gets served either. Measured directly: eight connections that
/// sent a request head declaring a body and then never finished sending it
/// stopped the proxy outright, including for clients that had nothing to do
/// with those eight.
///
/// Fix round 1, C2: a thread per request with no upper bound is its own
/// failure mode. `tiny_http` exposes no socket-level read timeout, so a
/// stalled body read holds its thread forever; measured directly, 2,000 idle
/// sockets cost 4,003 threads and 123 MB resident, and at 8,305 sockets the
/// OS thread limit was reached, `std::thread::spawn`'s internal `.expect()`
/// panicked (`std` panics on spawn failure by design — it does not return a
/// silent `Result::Err` for the caller to shed), and because that panic
/// landed on the dispatcher's own thread — the same one this loop runs on —
/// nothing survived it. `max_concurrent_requests` bounds how many requests
/// this function will ever have a thread open for at once; past that count,
/// a request is shed with 503 immediately, without spawning a thread or
/// reading a single byte of it, so admission itself can never be the thing
/// that runs out of OS resources.
pub fn serve(cfg: &GuardConfig) -> Result<(), GuardError> {
    let server = tiny_http::Server::http(&cfg.listen).map_err(|e| GuardError::Bind {
        addr: cfg.listen.clone(),
        detail: e.to_string(),
    })?;
    println!(
        "transit guard on http://{} → {}\nfail-closed: strict I-JSON ingestion; \
         idempotency key {}; state precondition {}; at most {} requests in flight",
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
        cfg.enforce.max_concurrent_requests,
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
    let inflight = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // A single dispatcher: it does nothing but call `recv()`, check the
    // admission cap, and hand admitted requests to their own thread, so it
    // is never the thing a slow client can occupy. `ureq::Agent` is cheaply
    // `Clone` (it wraps an `Arc` inside).
    while let Ok(raw) = server.recv() {
        match try_admit(&inflight, cfg.enforce.max_concurrent_requests) {
            Some(permit) => {
                let cfg = cfg.clone();
                let agent = agent.clone();
                std::thread::spawn(move || {
                    let _permit = permit;
                    handle_one(&cfg, &agent, raw);
                });
            }
            None => {
                // Shed load without reading anything from the client and
                // without spawning a thread: admission control that itself
                // has to read a body, or open a thread, to refuse a request
                // is not admission control.
                let _ = raw.respond(json_response(
                    503,
                    r#"{"error":"transit guard is at capacity"}"#,
                ));
            }
        }
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

    // Fix round 1, I1: a `Transfer-Encoding` header at all — chunked or
    // otherwise — is refused before the body is ever touched, rather than
    // special-cased only when `Content-Length` is *also* present. RFC 9112
    // §6.1 requires 400 for that specific combination because it is the
    // classic request-smuggling ambiguity, but the narrower check left a
    // TE-only request reaching `as_reader()`, which decides how to frame the
    // body from the same header this proxy never inspected — and if what
    // followed was not actually valid chunked data (a client can send
    // whatever bytes it likes after declaring whatever headers it likes),
    // `read_to_string` waited on a terminator that would never arrive, with
    // no deadline. This proxy fully buffers every body before doing anything
    // with it and gains nothing from streaming chunked data, so the whole
    // framing mechanism is refused rather than partially supported.
    if raw.headers().iter().any(|h| {
        h.field
            .as_str()
            .as_str()
            .eq_ignore_ascii_case("transfer-encoding")
    }) {
        let _ = raw.respond(json_response(
            400,
            r#"{"error":"Transfer-Encoding is not supported; send a fixed Content-Length body"}"#,
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
    fn the_digest_is_the_sha256_of_the_canonical_body_not_a_constant() {
        // Fix round 1, I2. `a_client_supplied_digest_header_cannot_survive`
        // above only ever compares `f.digest` against itself, and
        // `a_conforming_request_forwards_the_canonical_body_not_the_wire_body`
        // only asserts `digest.len() == 64` — both pass unchanged if `dg`
        // were computed from a fixed 32-byte constant instead of the parsed
        // body. Pin it against `jcs::digest` of the actual canonical value:
        // the one thing this whole proxy exists to produce correctly.
        let body = r#"{ "to":"acct-9" , "amount":100 }"#;
        let f = forwarded(decide(&cfg(), &req("POST", "/v1/transfer", body, &ok())));
        let parsed = parse_strict(body).expect("the fixture body is strict-valid");
        let expected = digest(&parsed).expect("the fixture body canonicalizes");
        assert_eq!(f.digest, expected);
        let (_, header_value) = f
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-transit-digest"))
            .unwrap();
        assert_eq!(*header_value, expected);

        // And a different body produces a different digest — catches a
        // constant that merely happens to be 64 hex characters.
        let other = r#"{"to":"acct-1","amount":1}"#;
        let f2 = forwarded(decide(&cfg(), &req("POST", "/v1/transfer", other, &ok())));
        assert_ne!(f2.digest, expected);
    }

    #[test]
    fn the_digest_header_is_stripped_even_when_no_digest_header_is_configured() {
        // The comment above the header filter in `decide` claims this is
        // unconditional; nothing exercised the `digest_header = None` path
        // it specifically calls out. Without the unconditional strip, a
        // client-supplied `X-Transit-Digest` would ride through unlabelled
        // as an ordinary header the moment an operator turned digest-adding
        // off.
        let mut c = cfg();
        c.enforce.digest_header = None;
        let f = forwarded(decide(
            &c,
            &req(
                "POST",
                "/v1/transfer",
                r#"{"a":1}"#,
                &[
                    ("Idempotency-Key", "k"),
                    ("If-Match", "0"),
                    ("X-Transit-Digest", "forged"),
                ],
            ),
        ));
        assert!(
            !f.headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("x-transit-digest")),
            "a client-supplied digest header survived with digest_header = None: {:?}",
            f.headers
        );
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
            require_parameters: vec![
                "to".into(),
                RequiredParam::Typed {
                    name: "amount".into(),
                    r#type: ParamType::Number,
                },
                "fee_tier".into(),
            ],
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

    #[test]
    fn a_required_parameter_of_the_wrong_json_type_does_not_satisfy_the_rule() {
        // Fix round 1, C1. `null` was the only shape the earlier check
        // caught; `false`, `0`, `[]` and `{}` all sailed through it exactly
        // the same way, because the upstream reads the field with
        // `.and_then(Json::as_string)`, which returns `None` — the same as
        // "absent" — for every one of them. Measured against the shipped
        // upstream and shipped config: `{"to":"acct-victim","amount":100,
        // "fee_tier":false}` reached the guard as 200 and the upstream's
        // ledger recorded `"fee_tier":"priority"` for a request that never
        // sent a string.
        let mut c = cfg();
        c.route.push(RouteRule {
            method: "POST".into(),
            path_prefix: "/v1/transfer".into(),
            require_idempotency_key: None,
            require_state_precondition: None,
            require_parameters: vec!["fee_tier".into()], // default type: string
        });
        for wrong in [r#"null"#, "false", "0", "[]", "{}"] {
            let body = format!(r#"{{"to":"acct-9","amount":100,"fee_tier":{wrong}}}"#);
            let (status, condition, reason) =
                rejected(decide(&c, &req("POST", "/v1/transfer", &body, &ok())));
            assert_eq!(status, 422, "fee_tier={wrong}");
            assert_eq!(condition, Some(Condition::C1), "fee_tier={wrong}");
            assert!(reason.contains("fee_tier"), "fee_tier={wrong}: {reason}");
        }
        // The correct type still goes through.
        let body = r#"{"to":"acct-9","amount":100,"fee_tier":"standard"}"#;
        assert!(matches!(
            decide(&c, &req("POST", "/v1/transfer", body, &ok())),
            Decision::Forward(_)
        ));
    }

    #[test]
    fn every_param_type_admits_only_its_own_json_shape() {
        // The type-check is a class, not five special cases pinned to one
        // parameter: every declared `ParamType` is exercised against every
        // JSON shape, including `null`, and only the matching shape passes.
        let shapes: &[(&str, &str)] = &[
            ("null", "null"),
            ("bool", "true"),
            ("number", "1"),
            ("string", r#""s""#),
            ("array", "[]"),
            ("object", "{}"),
        ];
        let types = [
            ("string", ParamType::String),
            ("number", ParamType::Number),
            ("bool", ParamType::Bool),
            ("array", ParamType::Array),
            ("object", ParamType::Object),
        ];
        for (type_name, ty) in types {
            let mut c = cfg();
            c.route.push(RouteRule {
                method: "POST".into(),
                path_prefix: "/v1/t".into(),
                require_idempotency_key: None,
                require_state_precondition: None,
                require_parameters: vec![RequiredParam::Typed {
                    name: "x".into(),
                    r#type: ty,
                }],
            });
            for (shape_name, literal) in shapes {
                let body = format!(r#"{{"x":{literal}}}"#);
                let decision = decide(&c, &req("POST", "/v1/t", &body, &ok()));
                if *shape_name == type_name {
                    assert!(
                        matches!(decision, Decision::Forward(_)),
                        "type={type_name} shape={shape_name} should have been admitted: {decision:?}"
                    );
                } else {
                    let (status, condition, _) = rejected(decision);
                    assert_eq!(status, 422, "type={type_name} shape={shape_name}");
                    assert_eq!(
                        condition,
                        Some(Condition::C1),
                        "type={type_name} shape={shape_name}"
                    );
                }
            }
        }
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

    #[test]
    fn percent_encoding_of_an_ordinary_letter_is_decoded_before_matching() {
        // Fix round 1, C3. `route_matches` used to compare the still-encoded
        // wire text, so a route rule for `/v1/transfer` matched none of
        // these, and the earlier substring check (`%2e`/`%2f`/`%25`)
        // wouldn't have refused any of them either — measured end to end
        // against the shipped hostile endpoint and shipped config.
        for target in [
            "/v1/tra%6Esfer", // %6E is an ordinary lowercase 'n'
            "/v1/%74ransfer", // %74 is 't'
            "/v1/transfe%72", // %72 is 'r'
        ] {
            assert_eq!(
                normalize_target(target).unwrap().0,
                "/v1/transfer",
                "{target} did not decode to the plain path"
            );
        }
    }

    #[test]
    fn double_encoding_is_refused_rather_than_decoded_twice() {
        // `%2541` decodes once to `%41` -- which still looks like an escape.
        // Decoding it again would silently resolve it to `A`, exactly the
        // "guard decides one path, something downstream derives another"
        // situation `normalize_target`'s own doc comment refuses to create.
        assert!(normalize_target("/v1/%2541").is_err());
        // A literal, single-encoded `%` followed by non-hex text is NOT
        // ambiguous and must still be allowed through unchanged.
        assert_eq!(normalize_target("/v1/50%25off").unwrap().0, "/v1/50%off");
    }

    #[test]
    fn an_encoded_slash_is_refused_rather_than_folded_into_a_segment_boundary() {
        // Decoding `%2f` to a literal `/` would let this proxy and an
        // upstream that does NOT decode it before routing (nginx, by
        // default) disagree about how many segments the path has.
        assert!(normalize_target("/v1/search/..%2Ftransfer").is_err());
        assert!(normalize_target("/v1/a%2Fb").is_err());
    }

    #[test]
    fn an_overlong_utf8_encoded_slash_is_refused() {
        // The historical IIS/Apache bypass: `%c0%af` is an overlong,
        // non-shortest-form UTF-8 encoding of `/`. It is not literally the
        // byte 0x2F, so it does not trip the encoded-slash check directly --
        // it is refused because 0xC0 is never a valid UTF-8 lead byte, which
        // `String::from_utf8` catches on its own.
        assert!(normalize_target("/v1/search%c0%af../transfer").is_err());
    }

    #[test]
    fn route_matching_on_the_decoded_path_is_case_insensitive() {
        // `/v1/TRANSFER` must match a `/v1/transfer` route rule -- some
        // upstreams route case-insensitively, and treating the two as
        // different targets let `require_parameters` be skipped entirely by
        // recasing the path, with no encoding tricks at all.
        let mut c = cfg();
        c.route.push(RouteRule {
            method: "POST".into(),
            path_prefix: "/v1/transfer".into(),
            require_idempotency_key: None,
            require_state_precondition: None,
            require_parameters: vec!["fee_tier".into()],
        });
        for target in ["/v1/TRANSFER", "/v1/Transfer", "/v1/tra%6Esfer"] {
            let (status, condition, _) = rejected(decide(
                &c,
                &req("POST", target, r#"{"to":"acct-9","amount":100}"#, &ok()),
            ));
            assert_eq!(status, 422, "{target}");
            assert_eq!(condition, Some(Condition::C1), "{target}");
        }
    }
}
