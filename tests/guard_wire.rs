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
    for attempt in 0..10 {
        let probe = TcpListener::bind("127.0.0.1:0").expect("bind a probe port");
        let guard_port = probe.local_addr().unwrap().port();
        drop(probe);

        let cfg = transit::guard::GuardConfig {
            listen: format!("127.0.0.1:{guard_port}"),
            upstream: format!("http://127.0.0.1:{upstream_port}"),
            enforce: transit::guard::Enforcement::default(),
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
