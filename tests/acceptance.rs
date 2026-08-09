//! The five acceptance tests from the design. Each is written to fail if the
//! claim the paper makes stops being true, not merely if the code stops
//! compiling.

use transit::classify::{classify_spec, ConditionVerdict, Verdict};
use transit::corpus::{Condition, Evidence};
use transit::differential;
use transit::fuzz;
use transit::fuzz::{ClientBelief, RetryBranch};
use transit::hostile::FailureModes;
use transit::transport::InProcess;

/// Acceptance test 1: `differential` detects the duplicate-key divergence
/// between two decoders present on the host.
///
/// The canonical pair in the literature is Go's last-key-wins against
/// Elixir's first-key-wins. **Elixir is not installed here**, so the pair
/// asserted is `strict-ijson` (which refuses the payload outright, as RFC
/// 8785 requires) against `serde_json` (which accepts it and keeps the last
/// key). Both are genuinely present and independently implemented. The
/// first-key-wins side of the canonical pair is additionally exercised
/// through the Elixir *model* (`model:elixir-otp-json`), which the report
/// labels `Unverified`: first-key-wins on OTP 27 has since been *measured*
/// directly (`results/elixir-measurement.txt`, run on GCP, elixir 1.17.3 /
/// OTP 27), but no Elixir runtime exists on this machine, so that measurement
/// is a fact about a different host, not about this run. The local decoder
/// stays a model regardless of what was measured elsewhere, and its
/// provenance says so.
#[test]
fn differential_detects_the_duplicate_key_divergence() {
    let r = differential::run_payload(r#"{"to":"acct-1","amount":100,"to":"acct-9"}"#);
    let d = r.divergence.expect("this payload must divide the decoders");

    let strict = d.class_of("strict-ijson").expect("strict-ijson took part");
    let serde = d.class_of("serde_json").expect("serde_json took part");
    assert_ne!(strict, serde, "two decoders present on every host disagree");

    // And the disagreement is about the recipient, not about some incidental
    // formatting difference.
    assert!(
        serde.contains(&hex_units("acct-9")),
        "serde_json resolved the duplicate to the last key: {serde}"
    );

    // `strict-ijson` is not external at all — it *is* this crate's own
    // `DuplicatePolicy::Reject` policy (`Config::strict()`) — so only the
    // `serde_json` half of the pair above is genuinely independent of
    // anything this crate decided. That pair alone says nothing about
    // `DuplicatePolicy::FirstWins`/`LastWins`, the two policies this crate
    // actually models. Pin those directly: first-key-wins and last-key-wins
    // must land in different classes, and the first-key class must hold the
    // *first* recipient. (`model:elixir-otp-json` is a model, not a
    // measurement — no Elixir runtime exists here, and the report labels it
    // `Unverified`.)
    let first = d
        .class_of("model:elixir-otp-json")
        .expect("the first-key model took part");
    let last = d
        .class_of("model:go-encoding-json")
        .expect("the last-key model took part");
    assert_ne!(first, last, "the two duplicate policies must disagree");
    assert!(
        first.contains(&hex_units("acct-1")),
        "first-key-wins authorizes the legitimate recipient: {first}"
    );
    assert!(
        last.contains(&hex_units("acct-9")),
        "last-key-wins pays the attacker: {last}"
    );

    // Confirm the Elixir model's own provenance still says what the doc
    // comment above claims: measured elsewhere, unverified here. A crate
    // edit that quietly promoted it (e.g. by hard-coding `RuntimeInstalled`)
    // would be exactly the false-provenance failure this tool exists to
    // catch, and it would not show up in any assertion above.
    let elixir_report = r
        .reports
        .iter()
        .find(|rep| rep.id == "model:elixir-otp-json")
        .expect("the elixir model reported");
    assert!(
        matches!(
            &elixir_report.provenance,
            transit::decoder::Provenance::Modelled {
                verification: transit::decoder::ModelVerification::Unverified { .. },
                ..
            }
        ),
        "the elixir model must stay Unverified on this host: {:?}",
        elixir_report.provenance
    );

    // Any language runtime that is installed joins in; none is required.
    // Fix round 1, I10: the old form here (`if let Some(cls) = ...; assert!(!cls.is_empty())`)
    // is skipped entirely when the runtime is absent, `class_of` can never
    // return an empty string in the first place (a class only exists because
    // some decoder produced it), and it used to pass even for a runtime that
    // had crashed (pre-C1, a crash was misreported as `Rejected`, which is a
    // perfectly non-empty class). Assert something real instead: when a
    // runtime actually took part, it must land in the same class as the
    // in-crate model that claims to model it.
    for (runtime_id, model_id) in [
        ("go", "model:go-encoding-json"),
        ("node", "model:node-json-parse"),
        ("python", "model:python-json"),
        ("ruby", "model:ruby-json"),
    ] {
        if let Some(cls) = d.class_of(runtime_id) {
            let model_cls = d.class_of(model_id).unwrap_or_else(|| {
                panic!("{model_id} took no part despite {runtime_id} being present")
            });
            assert_eq!(
                cls, model_cls,
                "{runtime_id} disagreed with the model that claims to model it"
            );
        }
    }
}

/// Acceptance test 2: `fuzz` against the hostile server in its
/// default-injection scenario reproduces the parameter-defaulting policy
/// bypass — a payload the policy layer approves and the endpoint executes
/// differently.
#[test]
fn fuzz_reproduces_the_parameter_defaulting_policy_bypass() {
    let mut hostile = InProcess::new(FailureModes::named("default-injection").unwrap());
    let f = fuzz::parameter_defaulting_bypass(&mut hostile)
        .unwrap()
        .expect("the bypass must reproduce");

    assert_eq!(f.condition, Condition::C1);
    assert_eq!(f.evidence, Evidence::HostileServer);
    assert!(f.policy_saw.contains("no fee_tier"), "{}", f.policy_saw);
    assert!(f.endpoint_did.contains("priority"), "{}", f.endpoint_did);

    // The same request against an endpoint conforming to the Boundable
    // Profile produces nothing. Without this half, the check could be
    // reporting a constant and would still pass.
    let mut boundable = InProcess::new(FailureModes::boundable());
    assert!(
        fuzz::parameter_defaulting_bypass(&mut boundable)
            .unwrap()
            .is_none(),
        "the finding must be a property of the endpoint, not of the checker"
    );
}

/// Acceptance test 3: `fuzz` against the non-idempotent scenario reproduces
/// the retry ambiguity — one branch where the client believes the operation
/// failed although state changed, one where it executes twice.
#[test]
fn fuzz_reproduces_both_horns_of_the_retry_ambiguity() {
    let mut hostile = InProcess::new(FailureModes::named("retry-ambiguity").unwrap());
    let outcomes = fuzz::retry_ambiguity(&mut hostile).unwrap();
    assert_eq!(outcomes.len(), 2);

    let same = outcomes
        .iter()
        .find(|o| o.branch == RetryBranch::SameNonce)
        .unwrap();
    assert_eq!(same.client_believes, ClientBelief::Failed);
    assert_eq!(
        same.orders_committed, 1,
        "the state change happened regardless"
    );

    let fresh = outcomes
        .iter()
        .find(|o| o.branch == RetryBranch::FreshNonce)
        .unwrap();
    assert_eq!(fresh.client_believes, ClientBelief::Succeeded);
    assert_eq!(fresh.orders_committed, 2, "the effect happened twice");

    // Decoupling the business idempotency key from the authorization nonce
    // is what closes the second horn. Asserting that here is what keeps this
    // test a statement about C3 rather than about the mock.
    let mut boundable = InProcess::new(FailureModes::boundable());
    let fixed = fuzz::retry_ambiguity(&mut boundable).unwrap();
    let fresh = fixed
        .iter()
        .find(|o| o.branch == RetryBranch::FreshNonce)
        .unwrap();
    assert_eq!(fresh.orders_committed, 1);
}

fn classify_example(name: &str) -> transit::classify::Classification {
    let src = std::fs::read_to_string(format!("examples/{name}")).expect("example present");
    classify_spec(&src)
        .expect("valid spec")
        .into_iter()
        .next()
        .unwrap()
}

/// Acceptance test 4: `classify` on an ISO 20022 style spec returns
/// `Qualified`; on a Slack `chat.postMessage` style spec it returns
/// `Non-qualifying`, naming the specific conditions that failed.
#[test]
fn classify_separates_a_bindable_spec_from_an_unbindable_one() {
    let iso = classify_example("iso20022-pain001.openapi.json");
    assert_eq!(iso.verdict, Verdict::Qualified);
    assert!(iso.failing.is_empty(), "{:?}", iso.failing);
    for c in [Condition::C1, Condition::C2, Condition::C3, Condition::C4] {
        assert_eq!(
            iso.verdict_for(c),
            Some(&ConditionVerdict::Satisfied),
            "{c:?}"
        );
    }

    let slack = classify_example("slack-chat-postmessage.openapi.json");
    assert_eq!(slack.verdict, Verdict::NonQualifying);
    // Naming the failing conditions is the requirement, not just the verdict.
    assert!(
        slack.failing.contains(&Condition::C1),
        "{:?}",
        slack.failing
    );
    assert!(
        slack.failing.contains(&Condition::C2),
        "{:?}",
        slack.failing
    );
    assert!(
        slack.failing.contains(&Condition::C3),
        "{:?}",
        slack.failing
    );

    // Every verdict here came from reading a document, and says so.
    assert_eq!(iso.evidence, Evidence::SpecDerived);
    assert_eq!(slack.evidence, Evidence::SpecDerived);
}

/// The middle of the taxonomy, and the S3 case, so the classifier is shown
/// to distinguish three outcomes rather than two.
#[test]
fn classify_places_the_conditional_and_qualified_middle_cases() {
    assert_eq!(
        classify_example("stripe-charges.openapi.json").verdict,
        Verdict::Conditional
    );
    assert_eq!(
        classify_example("s3-put-if-match.openapi.json").verdict,
        Verdict::Qualified
    );
}

/// The observation format renders strings as UTF-16 code units, so an
/// expected value has to be spelled the same way.
fn hex_units(s: &str) -> String {
    let units: Vec<String> = s.encode_utf16().map(|c| format!("{c:04x}")).collect();
    units.join(",")
}
