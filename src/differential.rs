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
use crate::decoder::{in_crate_verified_against, DecoderReport, Observation};
use crate::external::{discover, missing_runtimes};
use serde::Serialize;
use std::collections::BTreeMap;

/// The decoders that produced each distinct observation. Two or more classes
/// means the decoders disagree about what the payload says.
#[derive(Clone, Debug, Serialize)]
pub struct Divergence {
    /// `(observation, decoder ids)`, ordered by observation so the output is
    /// stable across runs. Keyed by *meaning*: this is the disagreement.
    pub classes: Vec<(String, Vec<String>)>,
    /// How many distinct *representations* the same decoders produced. Always
    /// at least `classes.len()`. A payload where this exceeds `classes.len()`
    /// had decoders that stored one value differently while agreeing about
    /// what it was — worth recording, never worth calling a divergence.
    pub representation_classes: usize,
}

impl Divergence {
    /// The observation class a given decoder landed in, or `None` if that
    /// decoder did not take part in this run.
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
    /// `None` when every decoder agreed.
    pub divergence: Option<Divergence>,
}

#[derive(Clone, Debug, Serialize)]
pub struct Run {
    pub cases: Vec<CaseReport>,
    /// Runtimes this crate looked for and did not find. Carried into the
    /// output because a differential over fewer decoders is a weaker result.
    pub missing: Vec<String>,
}

fn observe_all(payload: &str) -> Vec<DecoderReport> {
    let external = discover();
    // The models learn what was actually found, so `RuntimeInstalled` is a
    // consequence of this host rather than a label shipped in the source.
    let present: Vec<String> = external.iter().map(|e| e.id.clone()).collect();
    let mut out: Vec<DecoderReport> = in_crate_verified_against(&present)
        .iter()
        .map(|d| d.observe(payload))
        .collect();
    for e in external {
        match e.observe(payload) {
            Ok(r) => out.push(r),
            // A runtime that will not run is not a divergence; it is an
            // absence, and it is recorded as one.
            Err(err) => out.push(DecoderReport {
                id: e.id.clone(),
                provenance: e.provenance(),
                observation: Observation::Rejected,
                representation: None,
                detail: Some(format!("could not run: {err}")),
            }),
        }
    }
    out
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
    let by_meaning = group(reports, |r| match &r.observation {
        Observation::Value { rendered } => rendered.clone(),
        Observation::Rejected => "REJECTED".to_string(),
    });
    if by_meaning.len() < 2 {
        return None;
    }
    // Reported alongside, never grouped on. Two decoders that store one value
    // differently — Python's exact integer against Node's double — have not
    // disagreed about what the payload says, and a report that called that a
    // divergence would inflate every count the paper quotes.
    let by_representation = group(reports, |r| match (&r.observation, &r.representation) {
        (Observation::Value { .. }, Some(x)) => x.clone(),
        (Observation::Value { rendered }, None) => rendered.clone(),
        (Observation::Rejected, _) => "REJECTED".to_string(),
    });
    Some(Divergence {
        classes: by_meaning.into_iter().collect(),
        representation_classes: by_representation.len(),
    })
}

pub fn run_payload(payload: &str) -> CaseReport {
    let reports = observe_all(payload);
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
    let cases = cases()
        .into_iter()
        .map(|c| {
            let reports = observe_all(&c.payload);
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
        missing: missing_runtimes()
            .iter()
            .map(|m| m.id.to_string())
            .collect(),
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
        let r = run();
        assert_eq!(r.missing.len(), crate::external::missing_runtimes().len());
        assert!(!r.cases.is_empty());
    }

    #[test]
    fn every_corpus_case_diverges_somewhere() {
        // A corpus case that no decoder disagrees about is dead weight, and
        // this is where that would show up.
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
        // rather than trusting a comment.
        // Split so that this assertion's own source does not contain the
        // four characters it searches for — `include_str!` reads the file
        // this test lives in, so a literal needle would always match itself
        // and the test would fail against a perfectly clean module.
        let needle = concat!("ur", "eq");
        for src in [
            include_str!("differential.rs"),
            include_str!("decoder.rs"),
            include_str!("external.rs"),
        ] {
            assert!(
                !src.contains(needle),
                "the differential path must not use the HTTP client"
            );
        }
    }
}
