//! Run one payload through every decoder this crate can reach — the in-crate
//! models, `serde_json`, and any external language runtime `external::discover`
//! found on this host — and report where they disagree.
//!
//! Divergence is reported by *meaning*, not by *representation*: identity is
//! load-bearing throughout this crate (see `decoder::render` and
//! `decoder::Key`), and this module is the one place that consumes it to
//! decide what counts as a disagreement. Two decoders that stored one value
//! differently — Python's exact integer against Node's rounded double — have
//! not disagreed about anything, and grouping them together would drown the
//! real findings the corpus is built to surface.
//!
//! This module touches no network: it names no HTTP client, spawns no
//! request. `external::discover` runs local subprocesses only. The
//! `differential_touches_no_network` test below asserts that against the
//! source rather than trusting this comment.

use crate::corpus::{cases, Condition};
use crate::decoder::{in_crate_verified_against, DecoderReport, Observation, Provenance};
use crate::external::{discover, External, ExternalError};
use serde::Serialize;
use std::collections::BTreeMap;

/// The decoders that produced each distinct observation. Two or more classes
/// means the decoders disagree about what the payload says.
#[derive(Clone, Debug, Serialize)]
pub struct Divergence {
    /// `(observation, decoder ids)`, ordered by observation so the output is
    /// stable across runs. Keyed by *meaning*: this is the disagreement.
    /// A decoder whose `Observation` is `Unavailable` never appears here —
    /// it did not see the payload, so it has nothing to say about what it
    /// means. See `classify`.
    pub classes: Vec<(String, Vec<String>)>,
    /// How many distinct *representations* the same decoders produced. Always
    /// at least `classes.len()`. A payload where this exceeds `classes.len()`
    /// had decoders that stored one value differently while agreeing about
    /// what it was — worth recording, never worth calling a divergence.
    pub representation_classes: usize,
}

impl Divergence {
    /// The observation class a given decoder landed in, or `None` if that
    /// decoder did not take part in this run (including a decoder present
    /// in `CaseReport::reports` whose observation was `Unavailable`).
    pub fn class_of(&self, decoder_id: &str) -> Option<&str> {
        self.classes
            .iter()
            .find(|(_, ids)| ids.iter().any(|i| i == decoder_id))
            .map(|(obs, _)| obs.as_str())
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct CaseReport {
    pub case: String,
    /// `None` for an ad-hoc payload run through `run_payload`, which has no
    /// corpus entry to attach a condition to.
    pub condition: Option<Condition>,
    pub why: String,
    pub reports: Vec<DecoderReport>,
    /// `None` when every decoder that took part agreed.
    pub divergence: Option<Divergence>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Run {
    pub cases: Vec<CaseReport>,
    /// Runtimes this crate looked for and did not find. Carried into the
    /// output because a differential over fewer decoders is a weaker result.
    pub missing: Vec<String>,
}

/// Every runtime resolved once, and what it means for reporting.
///
/// Fix round 1, M12: `observe_all` used to call `external::discover()` for
/// every case — eleven times per `run()`, each a fresh `prepare(EXPECTED)`
/// (four `--version` spawns, one of them a `go build` cache check). `run()`
/// then called `external::missing_runtimes()` on top of that: a *twelfth*,
/// independent `prepare(EXPECTED)` call. The two calls agree in practice,
/// but nothing enforces it — they are two separate reads of host state, and
/// `missing` is derived here from the exact same `external` this struct's
/// caller uses for every case, so a runtime cannot appear both in a case's
/// reports and in `missing`.
struct Discovery {
    external: Vec<External>,
    present: Vec<String>,
    missing: Vec<String>,
}

fn discovery() -> Discovery {
    let external = discover();
    let present: Vec<String> = external.iter().map(|e| e.id.clone()).collect();
    // Derived from `EXPECTED` minus what this exact `discover()` call found,
    // rather than a second call to `external::missing_runtimes()` — see this
    // struct's doc comment. `prepare()`'s own invariant (every `Expected`
    // ends up in exactly one of `found`/`missing`, never both, never
    // neither — see `external::tests::a_runtime_that_is_absent_is_reported_rather_than_dropped`)
    // is what makes this equivalent to calling `missing_runtimes()` here.
    let missing: Vec<String> = crate::external::EXPECTED
        .iter()
        .map(|e| e.id.to_string())
        .filter(|id| !present.contains(id))
        .collect();
    Discovery {
        external,
        present,
        missing,
    }
}

fn observe_all(payload: &str, external: &[External], present: &[String]) -> Vec<DecoderReport> {
    // The models learn what was actually found, so `RuntimeInstalled` is a
    // consequence of this host rather than a label shipped in the source.
    let mut out: Vec<DecoderReport> = in_crate_verified_against(present)
        .iter()
        .map(|d| d.observe(payload))
        .collect();
    for e in external {
        match e.observe(payload) {
            Ok(r) => out.push(r),
            Err(err) => out.push(on_external_error(&e.id, e.provenance(), err)),
        }
    }
    out
}

/// A runtime that will not run is not a divergence; it is an absence, and
/// `Observation::Unavailable` records it as one.
///
/// Fix round 1, C1: this used to construct `Observation::Rejected` here,
/// which folded a crashed helper into the same meaning class as a decoder
/// that genuinely looked at the payload and refused it — `differential`
/// would print `strict-ijson, ruby   REJECTED` for a `ruby` that never ran
/// at all, with the real reason (`detail`) never surfacing anywhere a
/// reader would look, and `Run::missing` staying empty because the runtime
/// *was* discovered. `Unavailable` is excluded from every comparison in
/// `classify`, so a crash can neither manufacture nor hide a divergence.
fn on_external_error(id: &str, provenance: Provenance, err: ExternalError) -> DecoderReport {
    DecoderReport {
        id: id.to_string(),
        provenance,
        observation: Observation::Unavailable,
        representation: None,
        detail: Some(format!("could not run: {err}")),
    }
}

fn group<'a>(
    reports: &'a [DecoderReport],
    key: impl Fn(&'a DecoderReport) -> String,
) -> BTreeMap<String, Vec<String>> {
    let mut out: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for r in reports {
        out.entry(key(r)).or_default().push(r.id.clone());
    }
    out
}

fn classify(reports: &[DecoderReport]) -> Option<Divergence> {
    // A runtime that never ran contributes nothing to what the payload
    // means or how it was stored — it is excluded up front, not folded into
    // whichever class happens to already exist. See `Observation::Unavailable`
    // and `on_external_error`.
    let considered: Vec<DecoderReport> = reports
        .iter()
        .filter(|r| !matches!(r.observation, Observation::Unavailable))
        .cloned()
        .collect();
    let by_meaning = group(&considered, |r| match &r.observation {
        Observation::Value { rendered } => rendered.clone(),
        Observation::Rejected => "REJECTED".to_string(),
        Observation::Unavailable => unreachable!("filtered out above"),
    });
    if by_meaning.len() < 2 {
        return None;
    }
    // Reported alongside, never grouped on. Two decoders that store one value
    // differently — Python's exact integer against Node's double — have not
    // disagreed about what the payload says, and a report that called that a
    // divergence would inflate every count the paper quotes.
    let by_representation = group(&considered, |r| match (&r.observation, &r.representation) {
        (Observation::Value { .. }, Some(x)) => x.clone(),
        (Observation::Value { rendered }, None) => rendered.clone(),
        (Observation::Rejected, _) => "REJECTED".to_string(),
        (Observation::Unavailable, _) => unreachable!("filtered out above"),
    });
    Some(Divergence {
        classes: by_meaning.into_iter().collect(),
        representation_classes: by_representation.len(),
    })
}

pub fn run_payload(payload: &str) -> CaseReport {
    let d = discovery();
    let reports = observe_all(payload, &d.external, &d.present);
    let divergence = classify(&reports);
    CaseReport {
        case: "ad-hoc".to_string(),
        condition: None,
        why: String::new(),
        reports,
        divergence,
    }
}

pub fn run() -> Run {
    let d = discovery();
    let cases = cases()
        .into_iter()
        .map(|c| {
            let reports = observe_all(&c.payload, &d.external, &d.present);
            let divergence = classify(&reports);
            CaseReport {
                case: c.name.to_string(),
                condition: Some(c.condition),
                why: c.why.to_string(),
                reports,
                divergence,
            }
        })
        .collect();
    Run {
        cases,
        missing: d.missing,
    }
}

/// Runtimes this crate looked for and did not find, independent of any
/// particular payload or `Run`.
///
/// Fix round 1, I6: `--payload` produces one `CaseReport`, which has no
/// field to carry this, so a host missing every runtime ran a materially
/// weaker differential with nothing in either `--format` saying so. The CLI
/// calls this directly instead of reaching past this module into `external`
/// itself.
pub fn missing() -> Vec<String> {
    discovery().missing
}

/// The corpus through the in-crate decoders only. Every host produces
/// byte-identical output, which is what makes `results/` diff-gateable in
/// CI; the cross-language run is a property of an environment and is
/// recorded separately, with that environment attached.
///
/// `in_crate()` rather than `in_crate_verified_against(&discovery().present)`
/// on purpose. The latter promotes a model's provenance to `RuntimeInstalled`
/// wherever that runtime happens to exist, which is exactly the host
/// dependence this function exists to avoid: the same corpus would serialize
/// differently on a machine with Go installed than on one without, and the
/// CI diff gate would fail for a reason that has nothing to do with a code
/// change. Here every model reports `Unverified`, on every host.
pub fn run_in_crate_only() -> Run {
    let cases = cases()
        .into_iter()
        .map(|c| {
            let reports: Vec<DecoderReport> = crate::decoder::in_crate()
                .iter()
                .map(|d| d.observe(&c.payload))
                .collect();
            let divergence = classify(&reports);
            CaseReport {
                case: c.name.to_string(),
                condition: Some(c.condition),
                why: c.why.to_string(),
                reports,
                divergence,
            }
        })
        .collect();
    Run {
        cases,
        missing: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_payload_every_decoder_agrees_on_shows_no_divergence() {
        // Without this, "divergence found" could mean the comparison is
        // simply broken and reports disagreement for everything. The payload
        // deliberately includes an integer: keying numbers by value rather
        // than by the host language's type model is what makes this pass, and
        // an implementation that regressed to `I:`/`F:` would fail here.
        let r = run_payload(r#"{"a":1,"b":"x","c":true,"d":null,"e":[1,2.5]}"#);
        assert!(r.divergence.is_none(), "{:?}", r.divergence);
    }

    #[test]
    fn the_duplicate_key_payload_diverges_among_decoders_that_are_all_present() {
        // strict-ijson and serde_json are in-crate, so this holds on any
        // host — no runtime needs to be installed for the central claim.
        let r = run_payload(r#"{"to":"acct-1","to":"acct-9"}"#);
        let d = r
            .divergence
            .expect("strict rejects it, serde_json accepts it");
        assert!(d.classes.len() >= 2, "{d:?}");
        let strict = d.class_of("strict-ijson").expect("strict took part");
        let serde = d.class_of("serde_json").expect("serde took part");
        assert_ne!(strict, serde);
    }

    #[test]
    fn the_first_and_last_key_models_land_in_different_classes() {
        let r = run_payload(r#"{"to":"acct-1","to":"acct-9"}"#);
        let d = r.divergence.unwrap();
        assert_ne!(
            d.class_of("model:elixir-otp-json").unwrap(),
            d.class_of("model:go-encoding-json").unwrap(),
            "first-key-wins and last-key-wins must not share a class"
        );
    }

    #[test]
    fn a_run_reports_the_runtimes_it_could_not_find() {
        // Fix round 1, I3: `assert_eq!(r.missing.len(), missing_runtimes().len())`
        // is a tautology on any host where both sides are computed the same
        // way (and passes trivially at 0 == 0 on a host with everything
        // installed) — replacing the whole `missing` expression with
        // `Vec::new()`, or with a list of nonsense strings of the right
        // length, would still pass. Check content: every id `run()` reports
        // missing has to be one this crate actually looks for, and the
        // discovered ids plus the missing ids must together account for
        // exactly `external::EXPECTED`, with no overlap.
        let r = run();
        let expected: Vec<String> = crate::external::EXPECTED
            .iter()
            .map(|e| e.id.to_string())
            .collect();
        for id in &r.missing {
            assert!(
                expected.contains(id),
                "`{id}` is not a runtime this crate looks for: {expected:?}"
            );
        }
        let discovered: Vec<String> = crate::external::discover()
            .iter()
            .map(|e| e.id.clone())
            .collect();
        for id in &r.missing {
            assert!(
                !discovered.contains(id),
                "`{id}` is reported both missing and discovered"
            );
        }
        let mut accounted: Vec<String> = r
            .missing
            .iter()
            .cloned()
            .chain(discovered.iter().cloned())
            .collect();
        accounted.sort();
        let mut want = expected;
        want.sort();
        assert_eq!(
            accounted, want,
            "missing + discovered must exactly account for EXPECTED"
        );
        assert!(!r.cases.is_empty());
    }

    #[test]
    fn run_covers_the_whole_corpus() {
        // Fix round 1, I4: `cases().into_iter().take(1)` inside `run()`
        // would pass every other test in this suite while silently
        // reporting one of eleven corpus cases — `corpus_size_is_pinned`
        // (`corpus.rs`) pins `cases()` itself, not that `run()` actually
        // iterates all of it.
        let got: Vec<String> = run().cases.iter().map(|c| c.case.clone()).collect();
        let want: Vec<String> = crate::corpus::cases()
            .iter()
            .map(|c| c.name.to_string())
            .collect();
        assert_eq!(got, want, "run() must report every corpus case, in order");
    }

    #[test]
    fn representation_classes_can_exceed_or_equal_meaning_classes() {
        // Fix round 1, I5: `representation_classes` was computed correctly
        // but entirely untested — even `representation_classes: 0 *
        // by_representation.len()` passed every other test here.
        //
        // `duplicate-key-recipient` carries an `"amount":100` field: the
        // decoders that agree on the last-key-wins *meaning* (one class)
        // still disagree on whether it is stored as an exact integer or a
        // double (two representations), purely from the in-crate models —
        // no external runtime is required for this to hold. So
        // `representation_classes` must exceed `classes.len()` here.
        let with_a_number = run_payload(r#"{"to":"acct-1","amount":100,"to":"acct-9"}"#);
        let d = with_a_number.divergence.unwrap();
        assert!(
            d.representation_classes > d.classes.len(),
            "amount:100 should split by representation within a meaning class: {d:?}"
        );

        // A payload with no numbers has nothing left for the two identities
        // to disagree about beyond meaning (`render_with` renders a string
        // identically under `Key::Material` and `Key::Exact`), so the two
        // counts must land on the same number.
        let strings_only = run_payload(r#"{"to":"acct-1","to":"acct-9"}"#);
        let d2 = strings_only.divergence.unwrap();
        assert_eq!(
            d2.representation_classes,
            d2.classes.len(),
            "a numberless payload has no representation-only split: {d2:?}"
        );
    }

    #[test]
    fn every_discovered_runtime_appears_in_every_report() {
        // Fix round 1, C2 — the pre-flight's worst mutation: make
        // `observe_all` drop all external decoders and keep only the
        // in-crate models. The whole suite stayed green, and `differential`
        // could silently discard the four measured runtimes that are the
        // paper's entire evidence base.
        let ids: Vec<String> = crate::external::discover()
            .iter()
            .map(|e| e.id.clone())
            .collect();
        let r = run_payload(r#"{"to":"acct-1","to":"acct-9"}"#);
        for id in &ids {
            let rep = r
                .reports
                .iter()
                .find(|x| &x.id == id)
                .unwrap_or_else(|| panic!("runtime `{id}` vanished from the differential"));
            assert!(matches!(rep.provenance, Provenance::External { .. }));
        }
    }

    #[test]
    fn a_model_whose_runtime_was_discovered_reports_runtime_installed() {
        // Fix round 1, C2 (related): `observe_all` calling `in_crate()`
        // instead of `in_crate_verified_against(&present)` also leaves the
        // whole suite green, while every model reports itself permanently
        // `Unverified` even on a host where its runtime is right there.
        fn model_id(runtime: &str) -> &'static str {
            match runtime {
                "go" => "model:go-encoding-json",
                "node" => "model:node-json-parse",
                "python" => "model:python-json",
                "ruby" => "model:ruby-json",
                other => panic!("no model declared for runtime `{other}`"),
            }
        }
        let discovered: Vec<String> = crate::external::discover()
            .iter()
            .map(|e| e.id.clone())
            .collect();
        let r = run_payload(r#"{"a":1}"#);
        let mut checked = 0usize;
        for id in &discovered {
            let rep = r
                .reports
                .iter()
                .find(|x| x.id == model_id(id))
                .unwrap_or_else(|| panic!("{} did not report", model_id(id)));
            assert!(
                matches!(
                    &rep.provenance,
                    Provenance::Modelled {
                        verification: crate::decoder::ModelVerification::RuntimeInstalled,
                        ..
                    }
                ),
                "{} should report RuntimeInstalled once `{id}` is discovered: {:?}",
                model_id(id),
                rep.provenance
            );
            checked += 1;
        }
        assert!(
            checked > 0,
            "this test needs at least one runtime installed to mean anything"
        );
    }

    #[test]
    fn an_external_error_becomes_unavailable_not_rejected() {
        // Fix round 1, C1 (part one): the conversion from a failed spawn to
        // a `DecoderReport` must never produce `Rejected` — that would say
        // the runtime looked at the payload and refused it, when it never
        // ran at all.
        let err = ExternalError::Spawn {
            id: "fake".to_string(),
            source: std::io::Error::other("boom"),
        };
        let r = on_external_error(
            "fake",
            Provenance::External {
                runtime: "fake".to_string(),
                version: "0".to_string(),
            },
            err,
        );
        assert_eq!(r.observation, Observation::Unavailable);
        assert_ne!(r.observation, Observation::Rejected);
        assert!(r.detail.unwrap().contains("could not run"));
    }

    #[test]
    fn an_unavailable_report_does_not_change_divergence_or_the_rejected_class() {
        // Fix round 1, C1 (part two): even with `Observation::Unavailable`
        // existing, `classify` has to actually exclude it rather than tally
        // it into whichever class already says REJECTED. Inject one
        // directly into a real, already-classified set of reports and
        // confirm nothing about the divergence moves.
        let baseline = run_payload(r#"{"to":"acct-1","to":"acct-9"}"#);
        let before = classify(&baseline.reports);
        let before_rejected = before.as_ref().and_then(|d| d.class_of("strict-ijson"));

        let mut reports = baseline.reports.clone();
        reports.push(DecoderReport {
            id: "fake-crashed-runtime".to_string(),
            provenance: Provenance::External {
                runtime: "fake".to_string(),
                version: "0".to_string(),
            },
            observation: Observation::Unavailable,
            representation: None,
            detail: Some("could not run: spawn failed".to_string()),
        });
        let after = classify(&reports);
        let after_rejected = after.as_ref().and_then(|d| d.class_of("strict-ijson"));

        assert_eq!(
            before.as_ref().map(|d| d.classes.len()),
            after.as_ref().map(|d| d.classes.len()),
            "an unavailable runtime must not change the number of divergence classes"
        );
        assert_eq!(
            before_rejected, after_rejected,
            "an unavailable runtime must not join the REJECTED class"
        );
        assert_eq!(
            after.unwrap().class_of("fake-crashed-runtime"),
            None,
            "an unavailable decoder must not appear in any divergence class"
        );
    }

    #[test]
    fn every_corpus_case_diverges_somewhere() {
        // Not a test that catches a corpus case with no divergence at all:
        // `corpus.rs`'s own
        // `every_case_is_syntactically_valid_json_that_strict_mode_still_refuses`
        // already guarantees strict rejects while some lenient decoder
        // accepts every case, so `classify` returning `None` here is
        // structurally impossible by construction — a comment claiming
        // otherwise was corrected in fix round 1. What this test actually
        // catches: `observe_all`/`run()` ignoring `c.payload` and observing
        // some fixed string instead of the real corpus content.
        for c in run().cases {
            assert!(
                c.divergence.is_some(),
                "case `{}` produced no divergence",
                c.case
            );
        }
    }

    #[test]
    fn differential_touches_no_network() {
        // The contract is architectural, so assert it against the source
        // rather than trusting a comment. The needles match `use <crate>`
        // and `<crate>::` for the HTTP client specifically, not the bare
        // crate name, so a comment that merely mentions it in prose cannot
        // fail the build with a misleading "touches the network" message —
        // fix round 1, I2.
        //
        // Split so that this assertion's own source does not contain either
        // needle — `include_str!` reads the file this test lives in, so a
        // literal needle would always match itself and the test would fail
        // against a perfectly clean module.
        let ureq = concat!("ur", "eq");
        let needles = [format!("use {ureq}"), format!("{ureq}::")];
        for src in [
            include_str!("differential.rs"),
            include_str!("decoder.rs"),
            include_str!("external.rs"),
            include_str!("corpus.rs"),
            include_str!("json.rs"),
            include_str!("jcs.rs"),
            include_str!("lib.rs"),
        ] {
            for needle in &needles {
                assert!(
                    !src.contains(needle.as_str()),
                    "the differential path must not use the HTTP client"
                );
            }
        }
    }
}
