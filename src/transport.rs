use crate::corpus::Evidence;
use crate::hostile::{handle, FailureModes, Ledger};
pub use crate::hostile::{Request, Response};
use std::time::{Duration, Instant};

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("{url}: {message}")]
    Http { url: String, message: String },
}

/// One interface, two implementations: the endpoint in this process, and a
/// real one over HTTP. Everything above this line is written once.
pub trait Transport {
    fn send(&mut self, req: &Request) -> Result<Response, TransportError>;
    fn describe(&self) -> String;
    fn evidence(&self) -> Evidence;
}

/// The hostile endpoint, called directly. No socket, no port, no flake —
/// and the same `handle` the served version runs.
pub struct InProcess {
    modes: FailureModes,
    state: Ledger,
}

impl InProcess {
    pub fn new(modes: FailureModes) -> Self {
        InProcess {
            modes,
            state: Ledger::default(),
        }
    }

    pub fn ledger(&self) -> &Ledger {
        &self.state
    }
}

impl Transport for InProcess {
    fn send(&mut self, req: &Request) -> Result<Response, TransportError> {
        Ok(handle(&self.modes, &mut self.state, req))
    }

    fn describe(&self) -> String {
        format!("in-process hostile endpoint {:?}", self.modes)
    }

    fn evidence(&self) -> Evidence {
        Evidence::HostileServer
    }
}

/// Spacing between calls. `next_delay` is pure so the policy is testable at
/// full speed; `wait` is the wrapper that sleeps.
pub struct RateLimiter {
    min_interval: Duration,
    last: Option<Instant>,
}

impl RateLimiter {
    pub fn per_minute(n: u32) -> Self {
        let min_interval = if n == 0 {
            Duration::from_secs(60)
        } else {
            Duration::from_secs_f64(60.0 / f64::from(n))
        };
        RateLimiter {
            min_interval,
            last: None,
        }
    }

    pub fn unlimited() -> Self {
        RateLimiter {
            min_interval: Duration::ZERO,
            last: None,
        }
    }

    pub fn next_delay(&mut self, now: Instant) -> Duration {
        let wait = match self.last {
            Some(prev) => self.min_interval.saturating_sub(now.duration_since(prev)),
            None => Duration::ZERO,
        };
        self.last = Some(now + wait);
        wait
    }

    pub fn wait(&mut self) {
        let d = self.next_delay(Instant::now());
        if !d.is_zero() {
            std::thread::sleep(d);
        }
    }
}

/// Whether a base URL names this machine.
///
/// Load-bearing rather than cosmetic: `transit fuzz --target` is **not**
/// gated, and `run_all` deliberately executes a non-idempotent operation
/// twice. It may therefore only ever point at a hostile endpoint the operator
/// is running locally. Anything else has to go through `probe` and its
/// authorization gate.
pub fn is_loopback(base: &str) -> bool {
    let authority = base
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(base)
        .split('/')
        .next()
        .unwrap_or("");
    // Strip any userinfo, then take the host out of `host:port`, handling the
    // bracketed IPv6 form before splitting on `:`.
    let hostport = authority.rsplit('@').next().unwrap_or("");
    let host = match hostport.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => hostport.split(':').next().unwrap_or(""),
    };
    host == "localhost" || host == "::1" || host.starts_with("127.")
}

/// A real endpoint. Only ever constructed behind the authorization gate in
/// Task 11, or pointed at the locally served hostile endpoint.
pub struct Http {
    pub base: String,
    pub evidence: Evidence,
    pub limiter: RateLimiter,
}

impl Transport for Http {
    fn send(&mut self, req: &Request) -> Result<Response, TransportError> {
        self.limiter.wait();
        let url = format!("{}{}", self.base.trim_end_matches('/'), req.path);
        let mut r = match req.method.as_str() {
            "GET" => ureq::get(&url),
            "POST" => ureq::post(&url),
            other => {
                return Err(TransportError::Http {
                    url,
                    message: format!("unsupported method {other}"),
                })
            }
        };
        for (k, v) in &req.headers {
            r = r.set(k, v);
        }
        let sent = if req.method == "GET" {
            r.call()
        } else {
            r.set("Content-Type", "application/json")
                .send_string(&req.body)
        };
        match sent {
            Ok(resp) => Ok(Response {
                status: resp.status(),
                body: resp.into_string().unwrap_or_default(),
            }),
            // ureq treats a non-2xx status as an error. For this tool a 409
            // or a 412 is the *answer*, so unwrap it back into a response.
            Err(ureq::Error::Status(code, resp)) => Ok(Response {
                status: code,
                body: resp.into_string().unwrap_or_default(),
            }),
            Err(e) => Err(TransportError::Http {
                url,
                message: e.to_string(),
            }),
        }
    }

    fn describe(&self) -> String {
        self.base.clone()
    }

    fn evidence(&self) -> Evidence {
        self.evidence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::corpus::Evidence;
    use crate::hostile::FailureModes;
    use std::time::{Duration, Instant};

    #[test]
    fn the_in_process_transport_reaches_the_endpoint_and_keeps_its_state() {
        let mut t = InProcess::new(FailureModes::all_hostile());
        let req = Request {
            method: "POST".into(),
            path: "/v1/transfer".into(),
            headers: vec![],
            body: r#"{"to":"acct-9","amount":100}"#.into(),
        };
        assert_eq!(t.send(&req).unwrap().status, 200);
        assert_eq!(t.send(&req).unwrap().status, 200);
        let state = t
            .send(&Request {
                method: "GET".into(),
                path: "/v1/state".into(),
                headers: vec![],
                body: String::new(),
            })
            .unwrap();
        assert!(state.body.contains(r#""version":2"#), "{}", state.body);
    }

    #[test]
    fn the_in_process_transport_is_evidence_from_the_hostile_server() {
        assert_eq!(
            InProcess::new(FailureModes::boundable()).evidence(),
            Evidence::HostileServer
        );
    }

    #[test]
    fn the_rate_limiter_spaces_calls_without_this_test_sleeping() {
        // `next_delay` is pure so the policy can be tested at full speed;
        // `wait` is the thin wrapper that actually sleeps.
        let mut l = RateLimiter::per_minute(60); // one per second
        let t0 = Instant::now();
        assert_eq!(
            l.next_delay(t0),
            Duration::ZERO,
            "the first call waits for nothing"
        );
        assert_eq!(
            l.next_delay(t0 + Duration::from_millis(200)),
            Duration::from_millis(800)
        );
        assert_eq!(l.next_delay(t0 + Duration::from_secs(5)), Duration::ZERO);
    }

    #[test]
    fn an_unlimited_rate_never_waits() {
        let mut l = RateLimiter::unlimited();
        let t0 = Instant::now();
        assert_eq!(l.next_delay(t0), Duration::ZERO);
        assert_eq!(l.next_delay(t0), Duration::ZERO);
    }
}
