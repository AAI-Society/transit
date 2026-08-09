//! What actually goes out on the wire.
//!
//! Stands up a recording upstream on a loopback port, points a guard at it,
//! and asserts on the bytes the upstream received — not on what `decide`
//! returned. Every finding these tests pin was invisible to the unit suite.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::net::TcpStream;
use std::sync::mpsc;
use std::time::Duration;

/// A one-shot upstream that records the request head and body verbatim and
/// replies with whatever it was told to.
fn recording_upstream(reply: &'static str) -> (u16, mpsc::Receiver<String>) {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = l.local_addr().unwrap().port();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = l.accept() {
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut head = String::new();
            loop {
                let mut line = String::new();
                if r.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                    break;
                }
                head.push_str(&line);
            }
            let len: usize = head
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("content-length:"))
                .and_then(|l| l.split(':').nth(1))
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or(0);
            let mut body = vec![0u8; len];
            let _ = r.read_exact(&mut body);
            head.push_str(&String::from_utf8_lossy(&body));
            let _ = tx.send(head);
            let _ = s.write_all(reply.as_bytes());
        }
    });
    (port, rx)
}

/// Point a fresh guard at `upstream_port` and return the port it is actually
/// listening on, once it is confirmed to be accepting connections.
///
/// `serve` binds and then loops forever, so it gets its own detached thread.
/// There is no public API that hands back the bound port before `serve`
/// blocks in its accept loop, so the port is chosen here by probing a free
/// one, dropping the probe, and immediately telling the guard to bind that
/// exact address — the standard "probe, then reuse" pattern for a server
/// that cannot be handed an already-bound socket. The unavoidable race (some
/// other process steals the port in between) is handled by retrying with a
/// fresh probe on failure, rather than by asserting it can never happen.
fn guard_on(upstream_port: u16, route: Vec<transit::guard::RouteRule>) -> u16 {
    guard_on_with(upstream_port, transit::guard::Enforcement::default(), route)
}

/// Like `guard_on`, but lets a test override `Enforcement` (a tiny
/// `max_response_bytes`, a tiny `max_concurrent_requests`, and so on) —
/// several of the fix-round-1 findings are only observable by actually
/// tripping a bound, which means running the guard with a bound small
/// enough to trip in a test's lifetime.
fn guard_on_with(
    upstream_port: u16,
    enforce: transit::guard::Enforcement,
    route: Vec<transit::guard::RouteRule>,
) -> u16 {
    for attempt in 0..10 {
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind a probe port");
        let guard_port = probe.local_addr().unwrap().port();
        drop(probe);

        let cfg = transit::guard::GuardConfig {
            listen: format!("127.0.0.1:{guard_port}"),
            upstream: format!("http://127.0.0.1:{upstream_port}"),
            enforce: enforce.clone(),
            route: route.clone(),
        };
        std::thread::spawn(move || {
            // A bind race lost here just means this attempt's connect-probe
            // loop below times out and the caller retries with a new port;
            // `serve` returning `Err` on a successful run never happens
            // (it loops forever), so there is nothing else to report.
            let _ = transit::guard::serve(&cfg);
        });

        let deadline = std::time::Instant::now() + Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            if TcpStream::connect(("127.0.0.1", guard_port)).is_ok() {
                return guard_port;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        eprintln!("guard_on: attempt {attempt} on port {guard_port} did not come up, retrying");
    }
    panic!("guard never came up after 10 attempts");
}

/// Build a raw HTTP/1.1 request. `Connection: close` so the response can be
/// read to EOF without needing to know its exact framing.
fn raw_request(method: &str, target: &str, headers: &[(&str, &str)], body: &str) -> Vec<u8> {
    let mut req = format!("{method} {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    req.push_str(body);
    req.into_bytes()
}

/// Send raw bytes to the guard and read the whole response, bounded by a
/// deadline so a regression that reintroduces a deadlock fails the test
/// instead of hanging the suite forever.
fn send(guard_port: u16, request: &[u8]) -> Vec<u8> {
    let mut s = TcpStream::connect(("127.0.0.1", guard_port)).expect("connect to guard");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(request).expect("write request");
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    buf
}

/// Parse `HTTP/1.1 <status> ...` plus headers (kept in wire order, with
/// duplicates, exactly as multi-valued headers require) and the body.
fn parse_response(resp: &[u8]) -> (u16, Vec<(String, String)>, Vec<u8>) {
    let text_head_end = resp
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("a response head");
    let head = String::from_utf8_lossy(&resp[..text_head_end]);
    let body = resp[text_head_end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().expect("a status line");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .expect("a status code")
        .parse()
        .expect("a numeric status code");
    let headers = lines
        .filter(|l| !l.is_empty())
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect();
    (status, headers, body)
}

fn header_values<'a>(headers: &'a [(String, String)], name: &str) -> Vec<&'a str> {
    headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect()
}

const OK: [(&str, &str); 2] = [("Idempotency-Key", "k1"), ("If-Match", "0")];

/// The assertion the entire deployment claim rests on, and which nothing
/// caught before: the upstream must receive the CANONICAL body.
#[test]
fn the_upstream_receives_the_canonical_body_not_the_wire_body() {
    let (up, rx) = recording_upstream("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let guard_port = guard_on(up, Vec::new());

    let wire_body = r#"{ "to":"acct-9" , "amount":100 }"#;
    let mut headers: Vec<(&str, &str)> = OK.to_vec();
    headers.push(("Content-Type", "application/json"));
    let resp = send(
        guard_port,
        &raw_request("POST", "/v1/transfer", &headers, wire_body),
    );
    let (status, _, _) = parse_response(&resp);
    assert_eq!(status, 200, "the conforming request must be forwarded");

    let recorded = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("the upstream must have received a request");
    assert!(
        recorded.contains(r#"{"amount":100,"to":"acct-9"}"#),
        "the canonical body did not reach the upstream: {recorded:?}"
    );
    assert!(
        !recorded.contains(wire_body),
        "the WIRE body reached the upstream verbatim, unforgivably: {recorded:?}"
    );
}

/// A fragment must never let the guard decide one path and send another.
#[test]
fn a_fragment_cannot_split_the_decided_path_from_the_sent_path() {
    // `POST /v1/transfer#z` must be refused. Before the fix the guard decided
    // `/v1/transfer#z` — matching no route rule, so no `require_parameters` —
    // and the upstream received `/v1/transfer`.
    let (up, rx) = recording_upstream("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let guard_port = guard_on(up, Vec::new());

    let mut headers: Vec<(&str, &str)> = OK.to_vec();
    headers.push(("Content-Type", "application/json"));
    let resp = send(
        guard_port,
        &raw_request("POST", "/v1/transfer#z", &headers, r#"{"a":1}"#),
    );
    let (status, _, _) = parse_response(&resp);
    assert_eq!(
        status, 400,
        "a fragment in the request target must be refused"
    );

    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "the upstream must never have been contacted"
    );
}

/// A 3xx must be relayed, not followed.
#[test]
fn an_upstream_redirect_is_relayed_and_never_followed() {
    let (up, _rx) = recording_upstream(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:9/pwned\r\nContent-Length: 0\r\n\r\n",
    );
    let guard_port = guard_on(up, Vec::new());

    let mut headers: Vec<(&str, &str)> = OK.to_vec();
    headers.push(("Content-Type", "application/json"));
    let resp = send(
        guard_port,
        &raw_request("POST", "/v1/transfer", &headers, r#"{"a":1}"#),
    );
    let (status, headers, _) = parse_response(&resp);
    assert_eq!(
        status, 302,
        "the client must see the redirect status itself"
    );
    let location = header_values(&headers, "location");
    assert_eq!(
        location,
        vec!["http://127.0.0.1:9/pwned"],
        "the Location header must survive to the client: {headers:?}"
    );
}

/// Multi-valued response headers must survive intact.
#[test]
fn every_set_cookie_reaches_the_client() {
    let (up, _rx) = recording_upstream(
        "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nContent-Length: 0\r\n\r\n",
    );
    let guard_port = guard_on(up, Vec::new());

    let mut headers: Vec<(&str, &str)> = OK.to_vec();
    headers.push(("Content-Type", "application/json"));
    let resp = send(
        guard_port,
        &raw_request("POST", "/v1/transfer", &headers, r#"{"a":1}"#),
    );
    let (status, headers, _) = parse_response(&resp);
    assert_eq!(status, 200);
    let mut cookies = header_values(&headers, "set-cookie");
    cookies.sort_unstable();
    assert_eq!(
        cookies,
        vec!["a=1", "b=2"],
        "both cookies must arrive exactly once each: {headers:?}"
    );
}

/// Hop-by-hop headers must be stripped in the response direction too.
#[test]
fn an_upstream_connection_header_cannot_leak_its_named_headers() {
    let (up, _rx) = recording_upstream(
        "HTTP/1.1 200 OK\r\nConnection: X-Leak\r\nX-Leak: secret\r\nContent-Length: 0\r\n\r\n",
    );
    let guard_port = guard_on(up, Vec::new());

    let mut headers: Vec<(&str, &str)> = OK.to_vec();
    headers.push(("Content-Type", "application/json"));
    let resp = send(
        guard_port,
        &raw_request("POST", "/v1/transfer", &headers, r#"{"a":1}"#),
    );
    let (status, headers, _) = parse_response(&resp);
    assert_eq!(status, 200);
    assert!(
        header_values(&headers, "x-leak").is_empty(),
        "a header named by the upstream's own Connection header leaked: {headers:?}"
    );
}

/// A slow client must not stop the proxy.
#[test]
fn slow_clients_do_not_stop_the_proxy() {
    // Open more sockets than the old fixed worker pool (8) ever had, send a
    // request head declaring a body, and never finish sending that body.
    // Measured on the previous draft: eight such sockets and about 400 bytes
    // stopped the proxy entirely — every worker got stuck reading a body
    // that never arrived, and with no worker left free to call `recv()`, a
    // completely unrelated, fully-formed request never got served either.
    let (up, rx) = recording_upstream("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let guard_port = guard_on(up, Vec::new());

    let slow_head =
        b"POST /v1/thing HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\nConnection: close\r\n\r\n";
    let mut slow_clients = Vec::new();
    for _ in 0..9 {
        let mut s = TcpStream::connect(("127.0.0.1", guard_port)).expect("connect slow client");
        s.write_all(slow_head).expect("write the slow head");
        s.write_all(b"x")
            .expect("write one byte of the declared body");
        // Deliberately never send the rest, and never close the socket.
        slow_clients.push(s);
    }

    // A normal, complete request must still be served promptly.
    let mut headers: Vec<(&str, &str)> = OK.to_vec();
    headers.push(("Content-Type", "application/json"));
    let resp = send(
        guard_port,
        &raw_request(
            "POST",
            "/v1/transfer",
            &headers,
            r#"{"to":"acct-9","amount":100}"#,
        ),
    );
    let (status, _, _) = parse_response(&resp);
    assert_eq!(
        status,
        200,
        "a normal request must complete despite {} slow clients ahead of it",
        slow_clients.len()
    );

    let recorded = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("the upstream must have received the normal request");
    assert!(recorded.contains("acct-9"), "{recorded:?}");

    // Keep the slow sockets alive until here, so they cannot be dropped (and
    // thus closed, handing the read a clean EOF) before the assertion above
    // has had a chance to prove the deadlock the drop would otherwise mask.
    drop(slow_clients);
}

// --- fix round 1: findings the unit suite could not see ------------------
//
// The reviewer's own count: 8 of 15 mutations survived the unit suite
// unchanged. Every one of the following pins a behaviour that only exists
// in `handle_one`/`forward` -- the socket adapter -- which a pure `decide`
// unit test structurally cannot exercise, no matter how thorough.

/// Fix round 1, I2 survivor: a non-UTF-8 body must be refused outright, not
/// silently truncated to an empty, well-formed one and forwarded. This is
/// the brief's own original Critical 5, and nothing in `guard_wire.rs`
/// exercised it until now.
#[test]
fn a_non_utf8_body_is_refused_and_never_reaches_the_upstream() {
    let (up, rx) = recording_upstream("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let guard_port = guard_on(up, Vec::new());

    let mut req = "POST /v1/transfer HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         Idempotency-Key: k1\r\nIf-Match: 0\r\nContent-Type: application/json\r\n\
         Content-Length: 3\r\n\r\n"
        .as_bytes()
        .to_vec();
    req.extend_from_slice(&[0xff, 0xfe, 0xfd]); // not valid UTF-8, exactly 3 bytes
    let resp = send(guard_port, &req);
    let (status, _, _) = parse_response(&resp);
    assert_eq!(status, 400, "a non-UTF-8 body must be refused");

    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "the upstream must never have been contacted"
    );
}

/// Fix round 1, I2 survivor: `forward` must not drop the query string.
#[test]
fn the_query_string_reaches_the_upstream() {
    let (up, rx) = recording_upstream("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let guard_port = guard_on(up, Vec::new());

    let resp = send(
        guard_port,
        &raw_request("GET", "/v1/thing?a=1&b=2", &[], ""),
    );
    let (status, _, _) = parse_response(&resp);
    assert_eq!(status, 200);

    let recorded = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("the upstream must have received a request");
    assert!(
        recorded.starts_with("GET /v1/thing?a=1&b=2 "),
        "the query string did not reach the upstream: {recorded:?}"
    );
}

/// Fix round 1, I2 survivor: `Connection: upgrade` must be refused rather
/// than handed the raw socket with no length bound.
#[test]
fn connection_upgrade_is_refused_at_the_wire() {
    let (up, rx) = recording_upstream("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let guard_port = guard_on(up, Vec::new());

    let resp = send(
        guard_port,
        &raw_request(
            "GET",
            "/v1/thing",
            &[("Connection", "Upgrade"), ("Upgrade", "websocket")],
            "",
        ),
    );
    let (status, _, _) = parse_response(&resp);
    assert_eq!(status, 400, "an upgrade request must be refused");
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "the upstream must never have been contacted"
    );
}

/// Fix round 1, I2 survivor: an oversized upstream response must be refused,
/// not buffered in full.
#[test]
fn an_oversized_upstream_response_is_refused_not_buffered() {
    let big_body = "x".repeat(4096);
    let reply = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
        big_body.len(),
        big_body
    );
    let (up, _rx) = recording_upstream(Box::leak(reply.into_boxed_str()));
    let enforce = transit::guard::Enforcement {
        max_response_bytes: 16, // far smaller than the 4096-byte reply
        ..transit::guard::Enforcement::default()
    };
    let guard_port = guard_on_with(up, enforce, Vec::new());

    let mut headers: Vec<(&str, &str)> = OK.to_vec();
    headers.push(("Content-Type", "application/json"));
    let resp = send(
        guard_port,
        &raw_request("POST", "/v1/transfer", &headers, r#"{"a":1}"#),
    );
    let (status, _, body) = parse_response(&resp);
    assert_eq!(
        status, 502,
        "an oversized upstream response must be refused, not relayed: body={body:?}"
    );
    assert!(
        body.len() < big_body.len(),
        "the oversized response was buffered in full rather than refused"
    );
}

/// Fix round 1, I2 survivor: the socket-layer body cap must reject an
/// actually-oversized wire body -- not merely `decide`'s own post-hoc size
/// check on a body that was already read in full.
#[test]
fn an_oversized_wire_body_is_refused_at_the_socket_layer() {
    let (up, rx) = recording_upstream("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let enforce = transit::guard::Enforcement {
        max_body_bytes: 16,
        ..transit::guard::Enforcement::default()
    };
    let guard_port = guard_on_with(up, enforce, Vec::new());

    let body = "x".repeat(4096);
    let mut headers: Vec<(&str, &str)> = OK.to_vec();
    headers.push(("Content-Type", "application/json"));
    let resp = send(
        guard_port,
        &raw_request("POST", "/v1/transfer", &headers, &body),
    );
    let (status, _, _) = parse_response(&resp);
    assert_eq!(status, 413, "an oversized wire body must be refused");
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "the upstream must never have been contacted"
    );
}

/// The `413` above is reachable via `decide`'s own post-hoc size check on
/// whatever ended up in `body`, regardless of how it was read -- so it does
/// not, by itself, prove the socket-layer read is actually BOUNDED rather
/// than merely followed by a check. This test forces the distinction: a
/// declared `Content-Length` far larger than `max_body_bytes`, of which only
/// `max_body_bytes + 1` bytes are ever actually sent (the rest never
/// arrives, and the connection is left open). A bounded read (`.take(limit +
/// 1)`) stops there and answers immediately; an unbounded
/// `read_to_string(raw.as_reader())` would block waiting for the declared
/// remainder, holding the thread for as long as the "slow clients" finding
/// already measured being fatal at scale.
#[test]
fn an_oversized_body_is_refused_without_waiting_for_the_rest_of_a_declared_content_length() {
    let (up, rx) = recording_upstream("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let enforce = transit::guard::Enforcement {
        max_body_bytes: 16,
        ..transit::guard::Enforcement::default()
    };
    let guard_port = guard_on_with(up, enforce, Vec::new());

    let mut s = TcpStream::connect(("127.0.0.1", guard_port)).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let head = "POST /v1/transfer HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\
         Idempotency-Key: k1\r\nIf-Match: 0\r\nContent-Type: application/json\r\n\
         Content-Length: 10000000\r\n\r\n";
    s.write_all(head.as_bytes()).expect("write head");
    // 17 bytes -- one more than max_body_bytes (16) -- of a declared
    // 10,000,000-byte body. The rest is never sent.
    s.write_all(&[b'x'; 17]).expect("write partial body");
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf);
    let (status, _, _) = parse_response(&buf);
    assert_eq!(
        status, 413,
        "a bounded read must answer as soon as the cap is exceeded, not wait for the rest"
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "the upstream must never have been contacted"
    );
}

/// Fix round 1, I2's worst finding: nothing anywhere asserted that
/// `X-Transit-Digest` is the SHA-256 of the canonical body rather than a
/// constant. Pinned here on the wire, against the value the upstream
/// actually received.
#[test]
fn the_digest_reaching_the_upstream_is_the_sha256_of_the_canonical_body() {
    let (up, rx) = recording_upstream("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let guard_port = guard_on(up, Vec::new());

    let wire_body = r#"{ "to":"acct-9" , "amount":100 }"#;
    let mut headers: Vec<(&str, &str)> = OK.to_vec();
    headers.push(("Content-Type", "application/json"));
    let resp = send(
        guard_port,
        &raw_request("POST", "/v1/transfer", &headers, wire_body),
    );
    let (status, _, _) = parse_response(&resp);
    assert_eq!(status, 200);

    let recorded = rx
        .recv_timeout(Duration::from_secs(2))
        .expect("the upstream must have received a request");
    let sent_digest = recorded
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("x-transit-digest:"))
        .and_then(|l| l.split_once(':'))
        .map(|(_, v)| v.trim().to_string())
        .expect("an X-Transit-Digest header must have reached the upstream");

    let parsed = transit::parse_strict(wire_body).expect("fixture body is strict-valid");
    let expected = transit::digest(&parsed).expect("fixture body canonicalizes");
    assert_eq!(
        sent_digest, expected,
        "the digest on the wire is not the SHA-256 of the canonical body"
    );
}

/// Fix round 1, C1, reproduced end to end: a required parameter of the
/// wrong JSON type must not satisfy `require_parameters`.
#[test]
fn a_wrong_typed_required_parameter_is_refused_end_to_end() {
    let (up, rx) = recording_upstream("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let route = vec![transit::guard::RouteRule {
        method: "POST".into(),
        path_prefix: "/v1/transfer".into(),
        require_idempotency_key: None,
        require_state_precondition: None,
        require_parameters: vec![
            "to".into(),
            transit::guard::RequiredParam::Typed {
                name: "amount".into(),
                r#type: transit::guard::ParamType::Number,
            },
            "fee_tier".into(),
        ],
    }];
    let guard_port = guard_on(up, route);

    let mut headers: Vec<(&str, &str)> = OK.to_vec();
    headers.push(("Content-Type", "application/json"));
    let resp = send(
        guard_port,
        &raw_request(
            "POST",
            "/v1/transfer",
            &headers,
            r#"{"to":"acct-victim","amount":100,"fee_tier":false}"#,
        ),
    );
    let (status, _, body) = parse_response(&resp);
    assert_eq!(
        status, 422,
        "a boolean fee_tier must not satisfy a string-typed require_parameters entry: {body:?}"
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "the upstream must never have been contacted"
    );
}

/// Fix round 1, C3, reproduced end to end: a percent-encoded re-spelling of
/// an ordinary letter must not let a request bypass its route's
/// `require_parameters` by matching no rule at all.
#[test]
fn a_percent_encoded_path_still_gets_its_routes_parameters_enforced() {
    let (up, rx) = recording_upstream("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let route = vec![transit::guard::RouteRule {
        method: "POST".into(),
        path_prefix: "/v1/transfer".into(),
        require_idempotency_key: None,
        require_state_precondition: None,
        require_parameters: vec!["fee_tier".into()],
    }];
    let guard_port = guard_on(up, route);

    let mut headers: Vec<(&str, &str)> = OK.to_vec();
    headers.push(("Content-Type", "application/json"));
    // %6E is an ordinary 'n' -- this targets the exact same resource as
    // `/v1/transfer`, just re-spelled.
    let resp = send(
        guard_port,
        &raw_request(
            "POST",
            "/v1/tra%6Esfer",
            &headers,
            r#"{"to":"acct-9","amount":100}"#,
        ),
    );
    let (status, _, body) = parse_response(&resp);
    assert_eq!(
        status, 422,
        "the re-spelled path must still be matched to /v1/transfer's route rule: {body:?}"
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "the upstream must never have been contacted"
    );
}

/// Fix round 1, I1: `Transfer-Encoding` must be refused immediately, not
/// left to hang `read_to_string` on chunked framing that never resolves.
#[test]
fn transfer_encoding_is_refused_rather_than_hung_on() {
    let (up, rx) = recording_upstream("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let guard_port = guard_on(up, Vec::new());

    // A `Content-Length` alongside `Transfer-Encoding: chunked`, with a body
    // that is NOT actually chunk-framed -- exactly the shape that hung the
    // previous draft's `read_to_string` forever.
    let mut headers: Vec<(&str, &str)> = OK.to_vec();
    headers.push(("Content-Type", "application/json"));
    headers.push(("Transfer-Encoding", "chunked"));
    let resp = send(
        guard_port,
        &raw_request("POST", "/v1/transfer", &headers, r#"{"a":1}"#),
    );
    let (status, _, _) = parse_response(&resp);
    assert_eq!(
        status, 400,
        "Transfer-Encoding must be refused, not hung on"
    );
    assert!(
        rx.recv_timeout(Duration::from_millis(300)).is_err(),
        "the upstream must never have been contacted"
    );
}

/// Fix round 1, C2: past `max_concurrent_requests`, a request must be shed
/// with 503 immediately rather than given a thread and left to wait
/// forever behind slow clients that will never free theirs.
#[test]
fn requests_past_the_concurrency_cap_are_shed_with_503() {
    let (up, _rx) = recording_upstream("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    let enforce = transit::guard::Enforcement {
        max_concurrent_requests: 2,
        ..transit::guard::Enforcement::default()
    };
    let guard_port = guard_on_with(up, enforce, Vec::new());

    let slow_head =
        b"POST /v1/thing HTTP/1.1\r\nHost: x\r\nContent-Length: 1000000\r\nConnection: close\r\n\r\n";
    let mut slow_clients = Vec::new();
    for _ in 0..2 {
        let mut s = TcpStream::connect(("127.0.0.1", guard_port)).expect("connect slow client");
        s.write_all(slow_head).expect("write the slow head");
        s.write_all(b"x").expect("write one byte of the body");
        slow_clients.push(s);
    }
    // Give the dispatcher a moment to admit both slow clients before probing
    // the cap -- admission happens on `server.recv()`'s own thread, not
    // synchronously with the `write_all` calls above.
    std::thread::sleep(Duration::from_millis(200));

    let resp = send(guard_port, &raw_request("GET", "/v1/thing", &[], ""));
    let (status, _, _) = parse_response(&resp);
    assert_eq!(
        status, 503,
        "a third request past a cap of 2 must be shed immediately"
    );

    drop(slow_clients);
}
