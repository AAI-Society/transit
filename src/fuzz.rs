use crate::corpus::{Condition, Evidence};
use crate::json::{parse_strict, Json};
use crate::transport::{Request, Response, Transport, TransportError};
use serde::Serialize;

/// One way an endpoint's effect escaped what the policy approved.
#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub id: String,
    pub condition: Condition,
    pub title: String,
    /// What the policy engine evaluated and signed.
    pub policy_saw: String,
    /// What the endpoint actually did.
    pub endpoint_did: String,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, Serialize)]
pub struct FuzzReport {
    pub target: String,
    pub scenario: String,
    pub evidence: Evidence,
    /// Named so that a check which did not run cannot be mistaken for a
    /// check that found nothing.
    pub checks_run: Vec<String>,
    /// False when the target did not recognise the routes the checks are
    /// built around, so an empty `findings` means "not applicable" rather
    /// than "clean". Always true for the in-process endpoint.
    pub checks_applicable: bool,
    pub findings: Vec<Finding>,
    /// Findings that remain even against a fully conforming endpoint —
    /// structural consequences of the message layer that no endpoint change
    /// can close. Reported separately so a boundable run does not print
    /// "clean" over a gap the paper argues is permanent.
    pub residual: Vec<Finding>,
}

/// The policy the agent's authorization layer is modelling: ordinary
/// transfers are auto-approved, expedited ones are not. It reads the request
/// it was given and nothing else, which is exactly the assumption C1 breaks.
pub fn policy_approves(request: &Json) -> bool {
    match request.get("fee_tier").and_then(Json::as_string) {
        None => true,
        Some(t) => t == "standard",
    }
}

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

fn get(path: &str) -> Request {
    Request {
        method: "GET".into(),
        path: path.into(),
        headers: vec![],
        body: String::new(),
    }
}

fn executed_field(res: &Response, field: &str) -> Option<String> {
    parse_strict(&res.body)
        .ok()?
        .get("executed")?
        .get(field)
        .and_then(Json::as_string)
}

/// C1. The agent omits `fee_tier`; the policy engine sees no fee tier, applies
/// the rule that auto-approves ordinary transfers, and signs. The endpoint
/// fills the gap from profile state the signature never covered, and performs
/// an action the policy would have refused.
pub fn parameter_defaulting_bypass<T: Transport>(
    t: &mut T,
) -> Result<Option<Finding>, TransportError> {
    let signed = r#"{"to":"acct-9","amount":100}"#;
    let Ok(parsed) = parse_strict(signed) else {
        return Ok(None);
    };
    if !policy_approves(&parsed) {
        // The premise of the attack is that the policy said yes. If it did
        // not, there is nothing to report.
        return Ok(None);
    }

    // A well-behaved client sends the preconditions the endpoint asks for.
    // Omitting `If-Match` would get a 428 from every scenario that leaves
    // state pinning on — including `default-injection`, which turns on only
    // the defaulting — and the check would silently find nothing. The bypass
    // being demonstrated is about C1 alone, so C3 and C4 are satisfied here.
    let res = t.send(&post(
        "/v1/transfer",
        signed,
        &[("Idempotency-Key", "fuzz-c1"), ("If-Match", "0")],
    ))?;
    if res.status != 200 {
        return Ok(None);
    }
    let Some(fee_tier) = executed_field(&res, "fee_tier") else {
        return Ok(None);
    };

    // Re-run the policy over what the endpoint actually did. The finding is
    // derived from that comparison rather than asserted.
    let executed = format!(r#"{{"to":"acct-9","amount":100,"fee_tier":"{fee_tier}"}}"#);
    let Ok(executed_parsed) = parse_strict(&executed) else {
        return Ok(None);
    };
    if policy_approves(&executed_parsed) {
        return Ok(None);
    }

    Ok(Some(Finding {
        id: "c1-parameter-defaulting".into(),
        condition: Condition::C1,
        title: "the endpoint executed an action the policy would have refused".into(),
        policy_saw: format!("{signed} — no fee_tier, so the ordinary-transfer rule approved it"),
        endpoint_did: format!("fee_tier resolved to `{fee_tier}` from server-side profile state"),
        evidence: t.evidence(),
    }))
}

/// C2. One wire form, duplicate `to` keys. A first-key-wins policy engine
/// authorizes the first recipient; the endpoint pays whoever its own decoder
/// picked.
pub fn duplicate_key_split<T: Transport>(t: &mut T) -> Result<Option<Finding>, TransportError> {
    let wire = r#"{"to":"acct-1","amount":100,"fee_tier":"standard","to":"acct-9"}"#;
    let res = t.send(&post(
        "/v1/transfer",
        wire,
        &[("Idempotency-Key", "fuzz-c2"), ("If-Match", "0")],
    ))?;
    if res.status != 200 {
        return Ok(None);
    }
    let Some(to) = executed_field(&res, "to") else {
        return Ok(None);
    };
    if to == "acct-1" {
        return Ok(None);
    }
    Ok(Some(Finding {
        id: "c2-duplicate-key".into(),
        condition: Condition::C2,
        title: "the endpoint resolved a duplicate key differently from the policy engine".into(),
        policy_saw: "to = acct-1, the first binding a first-key-wins decoder returns".into(),
        endpoint_did: format!("paid `{to}`"),
        evidence: t.evidence(),
    }))
}

/// C2. Two spellings of one resource: an alias and the identifier it resolves
/// to. Distinct canonical bytes, identical effect.
pub fn alias_collapse<T: Transport>(t: &mut T) -> Result<Option<Finding>, TransportError> {
    let via_alias = t.send(&get("/v1/users/me"))?;
    if via_alias.status != 200 {
        return Ok(None);
    }
    let direct = t.send(&get("/v1/users/usr_99812"))?;
    if direct.status != 200 {
        return Ok(None);
    }
    let same = parse_strict(&via_alias.body)
        .ok()
        .and_then(|v| v.get("id").and_then(Json::as_string))
        == parse_strict(&direct.body)
            .ok()
            .and_then(|v| v.get("id").and_then(Json::as_string));
    if !same {
        return Ok(None);
    }
    Ok(Some(Finding {
        id: "c2-uri-alias".into(),
        condition: Condition::C2,
        title: "two canonical forms name one resource, so canonicalization is not injective".into(),
        policy_saw: "/v1/users/me".into(),
        endpoint_did: "resolved to usr_99812, the same resource /v1/users/usr_99812 names".into(),
        evidence: t.evidence(),
    }))
}

/// One adversarial check. Named rather than written inline as
/// `fn(&mut T) -> _`: an inferred return type in a cast position resolves
/// only while `TransportError` has exactly one applicable `From` impl, so the
/// day someone adds a `#[from]` variant the array stops compiling with
/// "type annotations needed" a long way from the cause.
type Check<T> = fn(&mut T) -> Result<Option<Finding>, TransportError>;

/// Post every corpus payload to the endpoint and report where what it
/// executed disagrees with what a strict decoder reads from the same bytes.
///
/// The corpus exists to be *delivered*, not only compared between decoders.
/// Without this, lone surrogates, NFC/NFD drift, negative zero, underflow and
/// the big-integer case never reach an endpoint at all, and the design's
/// `fuzz` component is only half-built.
pub fn corpus_against_endpoint<T: Transport>(t: &mut T) -> Result<Vec<Finding>, TransportError> {
    let mut out = Vec::new();
    for (i, case) in crate::corpus::cases().into_iter().enumerate() {
        let _ = t.send(&post("/v1/reset", "{}", &[]));
        // Each payload carries a recipient and an amount so the endpoint has
        // something to execute; the corpus case supplies the hostile shape.
        let body = case
            .payload
            .replacen('{', r#"{"amount":1,"fee_tier":"standard","#, 1);
        let res = t.send(&post(
            "/v1/transfer",
            &body,
            &[
                ("Idempotency-Key", &format!("corpus-{i}")),
                ("If-Match", "0"),
            ],
        ))?;
        if res.status != 200 {
            // A refusal is the correct behaviour, and is not a finding.
            continue;
        }
        let Some(executed) = executed_field(&res, "to") else {
            continue;
        };
        // The endpoint executed. What would a strict decoder have read?
        let strict = crate::json::parse_strict(&body)
            .ok()
            .and_then(|v| v.get("to").and_then(Json::as_string));
        if strict.as_deref() == Some(executed.as_str()) {
            continue;
        }
        out.push(Finding {
            id: format!("c2-corpus-{}", case.name),
            condition: case.condition,
            title: format!(
                "`{}` executed against a payload strict ingestion refuses",
                case.name
            ),
            policy_saw: match strict {
                Some(s) => format!("a strict decoder reads `{s}`"),
                None => "a strict decoder refuses these bytes outright".to_string(),
            },
            endpoint_did: format!("executed a transfer to `{executed}`"),
            evidence: t.evidence(),
        });
    }
    Ok(out)
}

pub fn run_all<T: Transport>(t: &mut T, scenario: &str) -> Result<FuzzReport, TransportError> {
    let target = t.describe();
    let evidence = t.evidence();
    let mut findings = Vec::new();
    let mut residual = Vec::new();
    let mut checks_run = Vec::new();

    let checks: [(&str, Check<T>); 4] = [
        ("c1-parameter-defaulting", parameter_defaulting_bypass),
        ("c2-duplicate-key", duplicate_key_split),
        ("c2-uri-alias", alias_collapse),
        ("c3-retry-ambiguity", retry_finding),
    ];
    for (name, f) in checks {
        // Reset between checks so one check's state cannot mask another's.
        let _ = t.send(&post("/v1/reset", "{}", &[]));
        checks_run.push(name.to_string());
        if let Some(finding) = f(t)? {
            findings.push(finding);
        }
    }

    let _ = t.send(&post("/v1/reset", "{}", &[]));
    checks_run.push("c2-corpus".to_string());
    findings.extend(corpus_against_endpoint(t)?);

    // The structural residual, reported separately. Horn one of the retry
    // ambiguity survives every endpoint fix, so a conforming endpoint must
    // not print "clean" over it.
    let _ = t.send(&post("/v1/reset", "{}", &[]));
    checks_run.push("c3-retry-residual".to_string());
    if let Some(f) = retry_residual(t)? {
        residual.push(f);
    }

    Ok(FuzzReport {
        target,
        scenario: scenario.to_string(),
        evidence,
        checks_run,
        // The in-process endpoint always recognises its own routes; `probe`
        // overwrites this after asking a real target.
        checks_applicable: true,
        findings,
        residual,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum RetryBranch {
    /// The proxy retries with the capability it already has.
    SameNonce,
    /// The proxy obtains a fresh signature over a new nonce.
    FreshNonce,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ClientBelief {
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
pub struct RetryOutcome {
    pub branch: RetryBranch,
    pub client_believes: ClientBelief,
    pub orders_committed: usize,
    pub retry_status: u16,
}

fn order_count<T: Transport>(t: &mut T) -> Result<usize, TransportError> {
    let res = t.send(&get("/v1/state"))?;
    Ok(parse_strict(&res.body)
        .ok()
        .and_then(|v| match v.get("orders") {
            Some(Json::Array(a)) => Some(a.len()),
            _ => None,
        })
        .unwrap_or(0))
}

/// The retry ambiguity, run out to both of its ends.
///
/// A non-idempotent POST commits and returns 200. A TCP reset drops the
/// response — modelled here by the client discarding it, which is exactly
/// what the client experiences. Then either the proxy retries with the same
/// capability, and the nonce cache calls it a replay so the client believes
/// the operation failed although the state changed; or the proxy obtains a
/// fresh signature, and the operation executes a second time. Neither branch
/// is right, and no message-level mechanism can tell an adversarial replay
/// from an infrastructure retry, because that distinction does not exist at
/// the message layer.
pub fn retry_ambiguity<T: Transport>(t: &mut T) -> Result<Vec<RetryOutcome>, TransportError> {
    let mut out = Vec::new();

    for branch in [RetryBranch::SameNonce, RetryBranch::FreshNonce] {
        t.send(&post("/v1/reset", "{}", &[]))?;

        // One business idempotency key, held constant across both calls of a
        // branch and carried by a well-behaved client. It must be here, and
        // it must be the same on the retry: the key being *decoupled from the
        // authorization nonce* is precisely the remedy C3 names, so a driver
        // that omitted it would never let the boundable endpoint demonstrate
        // the fix. Measured: without it a conforming endpoint refuses both
        // calls with 400 for the missing key, commits nothing, and the
        // fresh-nonce branch reports zero orders — a driver artefact reading
        // as a clean retry. The hostile `non_idempotent` path ignores the key
        // entirely, so this changes nothing about what that scenario shows.
        let key = ("Idempotency-Key", "retry-order-1");

        // The first call commits. Its response is dropped on the floor.
        let first = post(
            "/v1/orders",
            "{}",
            &[("Authorization", "Capability nonce=n1"), key],
        );
        let _discarded = t.send(&first)?;

        let retry_nonce = match branch {
            RetryBranch::SameNonce => "n1",
            RetryBranch::FreshNonce => "n2",
        };
        let retry = post(
            "/v1/orders",
            "{}",
            &[
                ("Authorization", &format!("Capability nonce={retry_nonce}")),
                key,
            ],
        );
        let res = t.send(&retry)?;

        out.push(RetryOutcome {
            branch,
            client_believes: if (200..300).contains(&res.status) {
                ClientBelief::Succeeded
            } else {
                ClientBelief::Failed
            },
            orders_committed: order_count(t)?,
            retry_status: res.status,
        });
    }

    Ok(out)
}

/// A C3 finding, raised only when *both* branches are wrong: one where the
/// client is told the operation failed although state changed, and one where
/// it executes twice.
pub fn retry_finding<T: Transport>(t: &mut T) -> Result<Option<Finding>, TransportError> {
    let outcomes = retry_ambiguity(t)?;
    let same = outcomes.iter().find(|o| o.branch == RetryBranch::SameNonce);
    let fresh = outcomes
        .iter()
        .find(|o| o.branch == RetryBranch::FreshNonce);
    let (Some(same), Some(fresh)) = (same, fresh) else {
        return Ok(None);
    };

    let believed_failed_but_committed =
        same.client_believes == ClientBelief::Failed && same.orders_committed >= 1;
    let executed_twice = fresh.orders_committed >= 2;
    if !(believed_failed_but_committed && executed_twice) {
        return Ok(None);
    }

    Ok(Some(Finding {
        id: "c3-retry-ambiguity".into(),
        condition: Condition::C3,
        title: "neither branch of a network retry is correct".into(),
        policy_saw: format!(
            "one authorized order; the retry with the same nonce returned {} so the client \
             recorded a failure",
            same.retry_status
        ),
        endpoint_did: format!(
            "committed {} order despite the reported failure, and with a fresh nonce executed \
             twice ({} orders)",
            same.orders_committed, fresh.orders_committed
        ),
        evidence: t.evidence(),
    }))
}

/// Horn one on its own: the client is told the operation failed while the
/// state change stands. This survives **every** endpoint fix, because the
/// message layer cannot distinguish an adversarial replay from an
/// infrastructure retry — the distinction does not exist there. It is
/// reported as `residual` rather than as a finding, so a conforming endpoint
/// does not print "no findings" over a gap the paper argues is permanent.
pub fn retry_residual<T: Transport>(t: &mut T) -> Result<Option<Finding>, TransportError> {
    let outcomes = retry_ambiguity(t)?;
    let Some(same) = outcomes.iter().find(|o| o.branch == RetryBranch::SameNonce) else {
        return Ok(None);
    };
    if !(same.client_believes == ClientBelief::Failed && same.orders_committed >= 1) {
        return Ok(None);
    }
    Ok(Some(Finding {
        id: "c3-retry-residual".into(),
        condition: Condition::C3,
        title: "a committed operation was reported to the client as failed".into(),
        policy_saw: format!("the retry was refused with {}", same.retry_status),
        endpoint_did: format!(
            "kept the {} order it had already committed; no message-level mechanism can tell \
             this retry from a replay",
            same.orders_committed
        ),
        evidence: t.evidence(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostile::FailureModes;
    use crate::transport::InProcess;

    #[test]
    fn the_policy_model_approves_a_standard_transfer_and_refuses_a_priority_one() {
        // The finding below is derived from this function, so if it were
        // wrong every finding would be too.
        assert!(policy_approves(
            &parse_strict(r#"{"to":"a","amount":1}"#).unwrap()
        ));
        assert!(policy_approves(
            &parse_strict(r#"{"to":"a","amount":1,"fee_tier":"standard"}"#).unwrap()
        ));
        assert!(!policy_approves(
            &parse_strict(r#"{"to":"a","amount":1,"fee_tier":"priority"}"#).unwrap()
        ));
    }

    #[test]
    fn the_defaulting_bypass_is_found_against_a_defaulting_endpoint() {
        let mut t = InProcess::new(FailureModes::named("default-injection").unwrap());
        let f = parameter_defaulting_bypass(&mut t)
            .unwrap()
            .expect("a finding");
        assert_eq!(f.condition, Condition::C1);
        assert!(f.endpoint_did.contains("priority"), "{}", f.endpoint_did);
    }

    #[test]
    fn the_defaulting_bypass_disappears_against_a_boundable_endpoint() {
        // Without this, the check could be reporting a constant.
        let mut t = InProcess::new(FailureModes::boundable());
        assert!(parameter_defaulting_bypass(&mut t).unwrap().is_none());
    }

    #[test]
    fn the_duplicate_key_split_is_found_only_when_the_endpoint_is_lenient() {
        let mut bad = InProcess::new(FailureModes::named("duplicate-keys").unwrap());
        assert!(duplicate_key_split(&mut bad).unwrap().is_some());
        let mut good = InProcess::new(FailureModes::boundable());
        assert!(duplicate_key_split(&mut good).unwrap().is_none());
    }

    #[test]
    fn the_alias_collapse_is_found_only_when_aliasing_is_on() {
        let mut bad = InProcess::new(FailureModes::named("alias").unwrap());
        assert!(alias_collapse(&mut bad).unwrap().is_some());
        let mut good = InProcess::new(FailureModes::boundable());
        assert!(alias_collapse(&mut good).unwrap().is_none());
    }

    #[test]
    fn a_report_carries_its_evidence_tag_and_lists_every_check_it_ran() {
        let mut t = InProcess::new(FailureModes::all_hostile());
        let r = run_all(&mut t, "all-hostile").unwrap();
        assert_eq!(r.evidence, Evidence::HostileServer);
        assert!(
            r.checks_run.len() >= 3,
            "a check that did not run is not a pass"
        );
        assert!(!r.findings.is_empty());
    }

    #[test]
    fn a_boundable_endpoint_yields_no_findings_but_still_reports_the_residual() {
        let mut t = InProcess::new(FailureModes::boundable());
        let r = run_all(&mut t, "boundable").unwrap();
        assert!(r.findings.is_empty(), "{:?}", r.findings);
        assert!(r.checks_run.len() >= 6, "and every check still ran");
        assert!(r.checks_applicable);
        // The paper's position is that horn one of the retry ambiguity is
        // structural. Printing "clean" over it would contradict the argument
        // the tool exists to support.
        assert_eq!(r.residual.len(), 1, "the structural residual must survive");
        assert_eq!(r.residual[0].condition, Condition::C3);
    }

    #[test]
    fn the_same_nonce_branch_leaves_the_client_believing_a_committed_write_failed() {
        let mut t = InProcess::new(FailureModes::named("retry-ambiguity").unwrap());
        let outcomes = retry_ambiguity(&mut t).unwrap();
        let a = outcomes
            .iter()
            .find(|o| o.branch == RetryBranch::SameNonce)
            .unwrap();
        assert_eq!(a.client_believes, ClientBelief::Failed);
        assert_eq!(a.orders_committed, 1, "the state change happened anyway");
    }

    #[test]
    fn the_fresh_nonce_branch_executes_the_operation_twice() {
        let mut t = InProcess::new(FailureModes::named("retry-ambiguity").unwrap());
        let outcomes = retry_ambiguity(&mut t).unwrap();
        let b = outcomes
            .iter()
            .find(|o| o.branch == RetryBranch::FreshNonce)
            .unwrap();
        assert_eq!(b.client_believes, ClientBelief::Succeeded);
        assert_eq!(b.orders_committed, 2, "one order too many");
    }

    #[test]
    fn a_boundable_endpoint_makes_the_fresh_nonce_branch_correct() {
        // The point of the paper's C3: decoupling the business idempotency
        // key from the authorization nonce is what removes the second horn.
        let mut t = InProcess::new(FailureModes::boundable());
        let outcomes = retry_ambiguity(&mut t).unwrap();
        let b = outcomes
            .iter()
            .find(|o| o.branch == RetryBranch::FreshNonce)
            .unwrap();
        assert_eq!(
            b.orders_committed, 1,
            "a retry must not duplicate the effect"
        );
    }

    #[test]
    fn the_retry_check_produces_a_c3_finding_only_when_both_branches_are_wrong() {
        let mut bad = InProcess::new(FailureModes::named("retry-ambiguity").unwrap());
        let f = retry_finding(&mut bad).unwrap().expect("a finding");
        assert_eq!(f.condition, Condition::C3);
        assert!(f.endpoint_did.contains("twice"), "{}", f.endpoint_did);

        let mut good = InProcess::new(FailureModes::boundable());
        assert!(retry_finding(&mut good).unwrap().is_none());
    }
}
