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
            // Fix round 1: the earlier payload duplicated `amount`, and
            // every last-key-wins decoder actually installed on this host
            // (node, python, ruby, go) resolves the member to plain `+0.0`
            // before any decoder gets a chance to disagree about the sign
            // -- the `-0.0` never survives to be observed at all, so the
            // case was really a fourth duplicate-key case wearing this
            // label. Only first-key-wins (Elixir, not installed here) would
            // ever see it. A single-member payload puts `-0.0` where every
            // decoder actually reads it.
            name: "negative-zero",
            payload: r#"{"amount":-0.0}"#.to_string(),
            condition: Condition::C2,
            why: "negative zero has no canonical form distinct from zero, so \
                  canonicalization is not injective over it",
        },
        Case {
            name: "underflow-1e-400",
            payload: r#"{"amount":1e-400,"floor":0}"#.to_string(),
            condition: Condition::C2,
            // Fix round 1: reworded. Every lenient config modelled here
            // reads `1e-400` as exactly `0.0` -- `f64`'s parse underflows it
            // the same way regardless of `NumberPolicy` -- so there is no
            // numeric divergence between the lenient decoders to point to.
            // The finding is narrower: strict mode is the only one of these
            // configs that treats the underflow as an error at all, so a
            // wire form that *looks* like a non-zero amount to a human
            // auditor is silently accepted as zero by every production
            // decoder and refused only by the one component built to catch
            // it.
            why: "every lenient decoder here silently reads this as exactly zero, so a \
                  wire form that looks non-zero to a human auditor passes production \
                  decoders unnoticed while strict mode is the one component that refuses it",
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

/// How a fact was come by. Attached to every verdict and every finding,
/// because the methodological crux of this whole paper is that a
/// documentation-derived classification and a measurement are not the same
/// kind of claim and must not print the same way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// Read out of an OpenAPI document. A claim about the document.
    SpecDerived,
    /// Measured against the hostile endpoint in this repository.
    HostileServer,
    /// Measured against a real endpoint, under the authorization gate.
    LiveProbed,
    /// Taken from the desk study's documentation review. **A hypothesis.**
    DeskStudy,
}

impl Evidence {
    /// One line, printed next to every result. Nobody reading output should
    /// have to go and look this up.
    pub fn caveat(&self) -> &'static str {
        match self {
            Evidence::SpecDerived => {
                "derived from a specification; C1 and C4 are properties of an \
                 implementation and no document reveals them"
            }
            Evidence::HostileServer => {
                "measured against this repository's deliberately hostile endpoint"
            }
            Evidence::LiveProbed => "measured against a live endpoint",
            Evidence::DeskStudy => {
                "HYPOTHESIS from a documentation review, never measured; \
                 verifying it is work this paper has not done"
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::{parse, parse_strict, Config, Json, Num};

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
    fn corpus_size_is_pinned() {
        // `every_case_is_syntactically_valid_json_that_strict_mode_still_refuses`
        // and the coverage test above both stay green if a filler case is
        // appended alongside the eleven above -- neither one bounds the
        // list from growing. Pin the count so a corpus that silently grows
        // (or shrinks) without the `cases()` literal above changing is
        // caught here.
        assert_eq!(
            cases().len(),
            11,
            "the corpus grew or shrank without the list above changing"
        );
    }

    #[test]
    fn negative_zero_case_actually_carries_a_negative_zero_to_every_decoder() {
        // Fix round 1: the original payload duplicated `amount` (`-0.0`
        // first, `0.0` second), so every last-key-wins decoder -- which is
        // every decoder actually installed on this host -- resolved to
        // plain `+0.0` before any decoder had a chance to observe the sign
        // at all. The `-0.0` was discarded before the phenomenon the case
        // is named for could occur, making it a duplicate-key case wearing
        // a negative-zero label. Nothing above pins that the corrected
        // single-member payload actually keeps the sign, so a regression
        // back to the duplicated form would pass every other test in this
        // module silently. Check it directly, under every modelled config,
        // not only the ones happening to be installed here.
        let c = case("negative-zero").unwrap();
        for cfg in [
            Config::node_json_parse(),
            Config::go_encoding_json(),
            Config::python_json(),
            Config::ruby_json(),
            Config::elixir_otp_json(),
        ] {
            let v = parse(&c.payload, cfg).unwrap();
            let Some(Json::Number(Num::Float(f))) = v.get("amount") else {
                panic!("expected a float `amount` under {cfg:?}")
            };
            assert_eq!(*f, 0.0, "must be zero under {cfg:?}");
            assert!(
                f.is_sign_negative(),
                "the payload's negative sign must survive parsing under {cfg:?}, \
                 not be discarded before any decoder observes it"
            );
        }
    }

    #[test]
    fn the_measured_cases_pin_the_behaviour_they_were_measured_for() {
        // Every other test in this module only asks "does some lenient
        // decoder accept this and strict mode refuse it" -- a shape nearly
        // any junk payload satisfies. Nothing above binds a case's *name*
        // to its *payload*, so a payload substitution that keeps the
        // accept/reject shape (e.g. swapping in a second duplicate-key
        // payload, or the specific wrong `\ud800A` spelling the comment on
        // `two-high-surrogates-collapse-into-one-character` warns against)
        // passes every test above unnoticed. These two cases carry the
        // entirety of Task 4's expensive measurement round, so pin the
        // measured behaviour directly rather than trusting the name.
        use crate::decoder::render;

        let p = &case("two-high-surrogates-collapse-into-one-character")
            .unwrap()
            .payload;
        assert!(
            p.contains(r"\ud800\ud800"),
            "must be two back-to-back high-surrogate escapes, not a raw \
             character (`\\ud800A`) or anything else satisfying the weaker shape"
        );
        assert!(
            render(&parse(p, Config::ruby_json()).unwrap()).contains("d800,dc00"),
            "ruby folds the pair into the single character U+10000"
        );
        assert!(
            render(&parse(p, Config::node_json_parse()).unwrap()).contains("d800,d800"),
            "node keeps both high-surrogate code units distinct"
        );

        let n = &case("nan-literal").unwrap().payload;
        assert!(
            parse(n, Config::python_json()).is_ok(),
            "python accepts the bare NaN token"
        );
        for c in [
            Config::node_json_parse(),
            Config::go_encoding_json(),
            Config::ruby_json(),
        ] {
            assert!(
                parse(n, c).is_err(),
                "every other modelled runtime rejects it"
            );
        }
    }

    #[test]
    fn condition_titles_are_pinned() {
        // Destined for the paper's report output with no other caller and
        // no other test; cheap to pin now rather than leave free to drift.
        assert_eq!(Condition::C1.title(), "C1 parameter completeness");
        assert_eq!(Condition::C2.title(), "C2 representation injectivity");
        assert_eq!(Condition::C3.title(), "C3 strict idempotency");
        assert_eq!(Condition::C4.title(), "C4 contextual state pinning");
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
