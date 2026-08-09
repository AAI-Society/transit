use serde::Serialize;

/// The four conditions of the restated theorem. Defined here because the
/// corpus, the fuzzer and the classifier all speak in terms of them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Condition {
    /// Parameter completeness and default invariance.
    C1,
    /// Representation injectivity.
    C2,
    /// Strict idempotency with nonce-decoupled retries.
    C3,
    /// Contextual state pinning.
    C4,
}

impl Condition {
    pub fn title(&self) -> &'static str {
        match self {
            Condition::C1 => "C1 parameter completeness",
            Condition::C2 => "C2 representation injectivity",
            Condition::C3 => "C3 strict idempotency",
            Condition::C4 => "C4 contextual state pinning",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Case {
    pub name: &'static str,
    pub payload: String,
    pub condition: Condition,
    pub why: &'static str,
}

pub fn case(name: &str) -> Option<Case> {
    cases().into_iter().find(|c| c.name == name)
}

/// The adversarial corpus. Fixed rather than random: random JSON finds
/// syntax bugs, and every case here is a semantic disagreement some row of
/// the desk study's decoder table predicts.
pub fn cases() -> Vec<Case> {
    // U+00E9 precomposed, versus U+0065 U+0301 decomposed. Same account to a
    // human and to any resolver that normalizes; different bytes to a signer
    // that does not.
    let nfc = "caf\u{e9}-acct";
    let nfd = "cafe\u{301}-acct";

    vec![
        Case {
            name: "duplicate-key-recipient",
            payload: r#"{"to":"acct-1","amount":100,"to":"acct-9"}"#.to_string(),
            condition: Condition::C2,
            why: "a first-key-wins policy engine authorizes acct-1 while a \
                  last-key-wins backend pays acct-9, over bytes both accept",
        },
        Case {
            name: "duplicate-key-amount",
            payload: r#"{"to":"acct-1","amount":1,"amount":100000}"#.to_string(),
            condition: Condition::C2,
            why: "the same split applied to the amount rather than the recipient",
        },
        Case {
            name: "lone-surrogate-high",
            payload: r#"{"to":"acct-\ud800-9"}"#.to_string(),
            condition: Condition::C2,
            why: "Go substitutes U+FFFD, Node and Python retain the unpaired \
                  unit, Ruby refuses; three different identifiers from one wire form",
        },
        Case {
            name: "lone-surrogate-low",
            payload: r#"{"to":"acct-\udc00-9"}"#.to_string(),
            condition: Condition::C2,
            why: "an unpaired low surrogate, which some decoders treat \
                  differently from an unpaired high one",
        },
        Case {
            // Measured on ruby 2.6.10 / json 2.1.0 and node v26.7.0, after a
            // reviewer and an implementer disagreed about this and both were
            // wrong. Ruby does NOT pair with a raw character —
            // `"\ud800A"` is rejected as an incomplete pair. What it does is
            // pair with any following `\u` escape, *including another high
            // surrogate*, masking with 0x3FF without checking it is low.
            name: "two-high-surrogates-collapse-into-one-character",
            payload: r#"{"to":"acct-\ud800\ud800-9"}"#.to_string(),
            condition: Condition::C2,
            why: "Ruby folds `\\ud800\\ud800` into the single character U+10000 \
                  (bytes f0 90 80 80) while Node keeps both code units and strict \
                  ingestion refuses the payload — two escapes that are each invalid \
                  become one valid character, silently shortening the identifier \
                  being authorized",
        },
        Case {
            name: "nan-literal",
            payload: r#"{"amount":NaN}"#.to_string(),
            condition: Condition::C2,
            why: "`NaN` is not a JSON token at all, but CPython's json.loads accepts it \
                  by default (allow_nan) while Go, Node and Ruby reject it — so a policy \
                  engine written in Python reads an amount its backend never sees",
        },
        Case {
            name: "nfc-nfd-recipient",
            // The duplicate `to_nfc` repeats the *same* spelling. It is here
            // only so strict mode rejects the payload, as every corpus case
            // must. Giving the duplicate the NFD spelling instead would make
            // `to_nfc` and `to_nfd` resolve to one value under last-key-wins,
            // and the case would silently stop testing normalization at all.
            payload: format!(r#"{{"to_nfc":"{nfc}","to_nfd":"{nfd}","to_nfc":"{nfc}"}}"#),
            condition: Condition::C2,
            why: "the signing engine hashes one normalization form while the \
                  resource resolver normalizes to the other",
        },
        Case {
            name: "negative-zero",
            payload: r#"{"amount":-0.0,"amount":0.0}"#.to_string(),
            condition: Condition::C2,
            why: "negative zero has no canonical form distinct from zero, so \
                  canonicalization is not injective over it",
        },
        Case {
            name: "underflow-1e-400",
            payload: r#"{"amount":1e-400,"floor":0}"#.to_string(),
            condition: Condition::C2,
            why: "a non-zero amount the policy engine may read exactly and the \
                  endpoint flushes to zero",
        },
        Case {
            name: "integer-beyond-2-53",
            payload: r#"{"account_id":9007199254740993,"amount":1}"#.to_string(),
            condition: Condition::C2,
            why: "Python and Ruby keep the identifier exactly; Node and Go round \
                  it to a different account",
        },
        Case {
            name: "percent-encoding-alias",
            payload: r#"{"path":"/v1/users/me","alias":"/v1/users%2Fme","amount":1e-400}"#
                .to_string(),
            // C2, not C1. Aliasing is a representation-injectivity failure in
            // both P02 and the desk study: two spellings, one resource.
            condition: Condition::C2,
            why: "two spellings of one resource, carried alongside a value that \
                  keeps strict mode from accepting the payload",
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::{parse, parse_strict, Config};

    #[test]
    fn every_case_is_syntactically_valid_json_that_strict_mode_still_refuses() {
        // The corpus is not a syntax fuzzer. Each payload parses under a
        // lenient decoder and is refused by a strict one — that gap is the
        // whole attack surface. A case that no lenient decoder accepts, or
        // that strict mode accepts, is testing nothing.
        for c in cases() {
            assert!(
                parse(&c.payload, Config::node_json_parse()).is_ok()
                    || parse(&c.payload, Config::python_json()).is_ok(),
                "case `{}` is rejected by every lenient decoder, so it exercises nothing",
                c.name
            );
            assert!(
                parse_strict(&c.payload).is_err(),
                "case `{}` is accepted by strict mode, so it is not adversarial",
                c.name
            );
        }
    }

    #[test]
    fn case_names_are_unique() {
        let mut names: Vec<&str> = cases().iter().map(|c| c.name).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), before);
    }

    #[test]
    fn the_corpus_covers_every_failure_the_desk_study_names() {
        for want in [
            "duplicate-key-recipient",
            "duplicate-key-amount",
            "lone-surrogate-high",
            "lone-surrogate-low",
            // Both measured against real runtimes during Task 4, not taken
            // from the desk study — Ruby swallows a character after a high
            // surrogate, and CPython accepts `NaN` where every other runtime
            // refuses it.
            "two-high-surrogates-collapse-into-one-character",
            "nan-literal",
            "nfc-nfd-recipient",
            "negative-zero",
            "underflow-1e-400",
            "integer-beyond-2-53",
            "percent-encoding-alias",
        ] {
            assert!(case(want).is_some(), "missing corpus case {want}");
        }
    }

    #[test]
    fn the_nfc_nfd_pair_differs_in_bytes_and_not_in_meaning() {
        // If these two ever became byte-identical the case would be vacuous
        // and would still pass a naive "the corpus exists" test.
        let c = case("nfc-nfd-recipient").unwrap();
        let v = parse(&c.payload, Config::node_json_parse()).unwrap();
        let (Some(a), Some(b)) = (v.get("to_nfc"), v.get("to_nfd")) else {
            panic!("both spellings present")
        };
        assert_ne!(
            a, b,
            "the two normalization forms must differ in code units"
        );
        use unicode_normalization::UnicodeNormalization;
        let (Some(a), Some(b)) = (a.as_string(), b.as_string()) else {
            panic!("both well formed")
        };
        assert_eq!(
            a.nfc().collect::<String>(),
            b.nfc().collect::<String>(),
            "and must mean the same account once normalized"
        );
    }

    #[test]
    fn every_case_names_the_condition_it_attacks() {
        for c in cases() {
            assert!(!c.why.is_empty(), "case `{}` explains nothing", c.name);
            // Every case here is a C2 attack, and that is not an oversight:
            // this corpus is delivered by comparing *decoders*, and what two
            // decoders can disagree about is representation. C1, C3 and C4
            // are properties of an endpoint's behaviour, so they are attacked
            // by `fuzz` against the hostile server, not by this corpus.
            assert_eq!(c.condition, Condition::C2, "case `{}`", c.name);
        }
    }
}
