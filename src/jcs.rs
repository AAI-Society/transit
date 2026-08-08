use crate::json::{lossy, Json, Num, Utf16};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum JcsError {
    #[error(
        "lone surrogate U+{cp:04X} cannot be encoded as UTF-8, so this value has no canonical form"
    )]
    LoneSurrogate { cp: u32 },
    #[error("`{value}` is not finite and has no canonical form")]
    NonFinite { value: String },
    #[error(
        "duplicate object key `{key}` after canonicalization; RFC 8785 section 3.1 forbids duplicate keys"
    )]
    DuplicateKey { key: String },
}

/// RFC 8785 canonical JSON.
pub fn canonicalize(v: &Json) -> Result<String, JcsError> {
    let mut out = String::new();
    write_value(v, &mut out)?;
    Ok(out)
}

/// The digest a capability signs over: SHA-256 of the canonical bytes.
pub fn digest(v: &Json) -> Result<String, JcsError> {
    let c = canonicalize(v)?;
    Ok(hex::encode(Sha256::digest(c.as_bytes())))
}

fn write_value(v: &Json, out: &mut String) -> Result<(), JcsError> {
    match v {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Number(n) => out.push_str(&canonical_number(n)?),
        Json::String(u) => write_string(u, out)?,
        Json::Array(a) => {
            // RFC 8785 section 3.2.3: "array element order MUST NOT be
            // changed." Unlike object members, arrays are not sorted —
            // position is itself part of the document's meaning.
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(x, out)?;
            }
            out.push(']');
        }
        Json::Object(m) => {
            // RFC 8785 section 3.2.3 sorts by UTF-16 code unit, and
            // `Vec<u16>`'s lexicographic ordering is exactly that order.
            // This is the reason strings are held as UTF-16 at all.
            let mut members: Vec<&(Utf16, Json)> = m.iter().collect();
            members.sort_by(|a, b| a.0.cmp(&b.0));
            // Every `Config` in `json.rs` resolves duplicate keys down to
            // one (reject, first-wins, or last-wins) during parsing, so a
            // parsed `Json::Object` never has two equal keys. But
            // `Json::Object` is a public constructor, and later tasks
            // (5/7/8) build values directly rather than through a decoder.
            // A hand-built duplicate would otherwise canonicalize to
            // `{"a":1,"a":2}`, which RFC 8785 section 3.1 forbids and which
            // does not even round-trip: re-parsing it under a last-wins
            // policy produces a different canonical form, and therefore a
            // different digest, than the value that produced it. Checked
            // after sorting, so it is a simple adjacent-pair scan.
            for pair in members.windows(2) {
                if pair[0].0 == pair[1].0 {
                    return Err(JcsError::DuplicateKey {
                        key: lossy(&pair[0].0),
                    });
                }
            }
            out.push('{');
            for (i, (k, val)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(k, out)?;
                out.push(':');
                write_value(val, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// The RFC 8785 canonical serialization of one number: the question this
/// answers is "what does every conformant JCS implementation sign for this
/// value?" ECMAScript's "Number" type is an IEEE-754 double with no
/// arbitrary-precision integer variant, so RFC 8785 section 3.2.2.3 has
/// nothing to say about integers beyond what a double can hold exactly —
/// there is no other representation to fall back to. A `Num::Int` kept
/// exact by an arbitrary-precision decoder is therefore coerced through the
/// double it would become (`i as f64`) before formatting. Leaving it exact
/// here would make `digest` sign a byte sequence no other JCS
/// implementation produces, which defeats the entire point of canonicalizing
/// at all. See `es_number` below for the *other* question, which this
/// deliberately disagrees with above 2^53.
fn canonical_number(n: &Num) -> Result<String, JcsError> {
    match n {
        Num::Int(i) => Ok(es_float(*i as f64)),
        Num::Float(f) => {
            if !f.is_finite() {
                return Err(JcsError::NonFinite {
                    value: f.to_string(),
                });
            }
            Ok(es_float(*f))
        }
    }
}

/// The material key `decoder::render` (Task 3) compares numbers by: the
/// question this answers is "would two decoders agree about this value?"
/// Unlike `canonical_number`, an exact `Num::Int` is rendered as its exact
/// decimal digits, *not* coerced through a double. That difference is
/// deliberate and is the property Task 3's differential rests on:
///
/// - `es_number(&Num::Int(100)) == es_number(&Num::Float(100.0))` — Python
///   keeping `100` exact and Node parsing it to a double name the same
///   value, so they must agree.
/// - `es_number(&Num::Int(9007199254740993)) != es_number(&Num::Float(9007199254740992.0))`
///   — Python keeping `9007199254740993` exact and Go rounding the same
///   literal to `9007199254740992` genuinely disagree about what the
///   literal *means*, and that disagreement is exactly what a capability
///   digest needs exposed, not silently coerced away.
///
/// This is not what `canonicalize`/`digest` use: those answer "what does
/// every JCS implementation sign," and coerce (see `canonical_number`).
/// Two different questions, two different identities — conflating them
/// either breaks RFC 8785 conformance or erases the divergence this crate
/// exists to measure.
pub fn es_number(n: &Num) -> Result<String, JcsError> {
    match n {
        Num::Int(i) => Ok(i.to_string()),
        Num::Float(f) => {
            if !f.is_finite() {
                return Err(JcsError::NonFinite {
                    value: f.to_string(),
                });
            }
            Ok(es_float(*f))
        }
    }
}

/// ECMAScript `Number::toString` for a finite double, which is what RFC 8785
/// section 3.2.2.3 requires. Rust's `Display` is not this function: it never
/// uses exponent form, so it prints `1e21` as twenty-two digits and `1e-7`
/// as `0.0000001`, both of which ECMAScript writes differently.
fn es_float(f: f64) -> String {
    // Do NOT derive the digits from `format!("{:e}", f)`. The case structure
    // of ECMA-262 §7.1.12.1 is easy to get right and the *tie-break* is not:
    // when two shortest decimal representations are equidistant, RFC 8785
    // §3.2.2.3 requires the "Note 2" enhancement — round half to even — and
    // Rust rounds half away from zero. Measured over 4,979,995 doubles that
    // is 10,762 disagreements (0.216%), every one of which changes the
    // SHA-256 and so makes this crate's capability digest differ from every
    // conformant JCS implementation. `1424953923781206.25` must serialize as
    // `1424953923781206.2`; Rust gives `...206.3`.
    //
    // `ryu-js` is Ryū with ECMAScript `Number::toString` semantics, and
    // RFC 8785 §3.2.2.3 names Ryū as a compatible reference. It already
    // collapses -0.0 to "0" (RFC 8785 serializes negative zero as `0`), so
    // no separate zero special-case is needed here; strict parsing rejects
    // the `-0` literal precisely because that step is lossy.
    let mut buf = ryu_js::Buffer::new();
    buf.format_finite(f).to_string()
}

fn write_string(u: &[u16], out: &mut String) -> Result<(), JcsError> {
    out.push('"');
    let mut i = 0;
    while i < u.len() {
        let c = u[i];
        match c {
            0x22 => out.push_str("\\\""),
            0x5C => out.push_str("\\\\"),
            0x08 => out.push_str("\\b"),
            0x09 => out.push_str("\\t"),
            0x0A => out.push_str("\\n"),
            0x0C => out.push_str("\\f"),
            0x0D => out.push_str("\\r"),
            0x00..=0x1F => out.push_str(&format!("\\u{c:04x}")),
            0xD800..=0xDBFF => {
                let lo = u
                    .get(i + 1)
                    .copied()
                    .filter(|l| (0xDC00..0xE000).contains(l))
                    .ok_or(JcsError::LoneSurrogate { cp: c as u32 })?;
                let cp = 0x10000 + (((c as u32) - 0xD800) << 10) + ((lo as u32) - 0xDC00);
                // `cp` is in 0x10000..=0x10FFFF by construction (a
                // well-formed surrogate pair can only decode into that
                // range), which `char::from_u32` always accepts, so this
                // cannot fail.
                out.push(
                    char::from_u32(cp).expect("surrogate pair decodes to a valid scalar value"),
                );
                i += 2;
                continue;
            }
            0xDC00..=0xDFFF => return Err(JcsError::LoneSurrogate { cp: c as u32 }),
            _ => {
                // `c` is a `u16` that already excluded the control-character
                // and surrogate ranges above, so every remaining value is a
                // valid Unicode scalar value and `char::from_u32` cannot
                // fail.
                out.push(
                    char::from_u32(c as u32)
                        .expect("non-surrogate code unit is a valid scalar value"),
                )
            }
        }
        i += 1;
    }
    out.push('"');
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::{parse, parse_strict, utf16, Config, Json, Num};

    /// RFC 8785 Appendix B, as `(IEEE-754 bit pattern in hex, expected
    /// serialization)`.
    ///
    /// Transcribed from <https://www.rfc-editor.org/rfc/rfc8785#appendix-B>
    /// (Table 1). The RFC's table has 26 rows; two of them (the `NaN` and
    /// `Infinity` bit patterns) have no JSON representation at all — note
    /// (3) in the RFC says such values "are not permitted in JSON" — so they
    /// are omitted here, leaving the 24 rows that actually serialize. Those
    /// two rows are not dropped, just moved: see
    /// `nan_and_infinity_have_no_canonical_form` below, which pins them as
    /// errors and restores the 26-row accounting.
    const APPENDIX_B: &[(&str, &str)] = &[
        // Zero.
        ("0000000000000000", "0"),
        // Minus zero.
        ("8000000000000000", "0"),
        // Min pos number.
        ("0000000000000001", "5e-324"),
        // Min neg number.
        ("8000000000000001", "-5e-324"),
        // Max pos number.
        ("7fefffffffffffff", "1.7976931348623157e+308"),
        // Max neg number.
        ("ffefffffffffffff", "-1.7976931348623157e+308"),
        // Max pos int (RFC note (1)).
        ("4340000000000000", "9007199254740992"),
        // Max neg int (RFC note (1)).
        ("c340000000000000", "-9007199254740992"),
        // ~2**68 (RFC note (2)).
        ("4430000000000000", "295147905179352830000"),
        ("44b52d02c7e14af5", "9.999999999999997e+22"),
        ("44b52d02c7e14af6", "1e+23"),
        ("44b52d02c7e14af7", "1.0000000000000001e+23"),
        ("444b1ae4d6e2ef4e", "999999999999999700000"),
        ("444b1ae4d6e2ef4f", "999999999999999900000"),
        ("444b1ae4d6e2ef50", "1e+21"),
        ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
        ("3eb0c6f7a0b5ed8d", "0.000001"),
        ("41b3de4355555553", "333333333.3333332"),
        ("41b3de4355555554", "333333333.33333325"),
        ("41b3de4355555555", "333333333.3333333"),
        ("41b3de4355555556", "333333333.3333334"),
        ("41b3de4355555557", "333333333.33333343"),
        ("becbf647612f3696", "-0.0000033333333333333333"),
        // Round to even (RFC note (4)): the reason this table exists.
        ("43143ff3c1cb0959", "1424953923781206.2"),
    ];

    fn canon(src: &str) -> String {
        canonicalize(&parse_strict(src).unwrap()).unwrap()
    }

    #[test]
    fn keys_sort_by_utf16_code_unit_not_by_code_point() {
        // U+FB33 is the single unit 0xFB33; U+1F600 is the pair 0xD83D 0xDE00.
        // By code point the emoji is larger; by UTF-16 code unit it is
        // smaller. RFC 8785 section 3.2.3 specifies the UTF-16 order, so the
        // emoji must come first. A canonicalizer that sorts by code point
        // passes every other test in this file and fails this one.
        let got = canon("{\"\u{fb33}\":2,\"\u{1f600}\":1}");
        assert_eq!(got, "{\"\u{1f600}\":1,\"\u{fb33}\":2}");
    }

    #[test]
    fn keys_sort_and_whitespace_disappears() {
        assert_eq!(canon("{ \"b\" : 1 , \"a\" : 2 }"), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn array_element_order_is_never_changed() {
        // RFC 8785 section 3.2.3: "array element order MUST NOT be
        // changed." Unlike the key-sort test above, `[3,1,2]` is not
        // sorted-looking on either side of a reversal, so this pins the
        // rule directly rather than through a digest-equality assertion
        // that a symmetric mutation (e.g. reversing both sides) could
        // cancel out.
        assert_eq!(canon(r#"{"a":[3,1,2]}"#), r#"{"a":[3,1,2]}"#);
    }

    #[test]
    fn numbers_follow_the_ecmascript_algorithm() {
        // The thresholds where ECMAScript switches representation, and the
        // ordinary cases either side of them.
        //
        // Built directly as `Json::Object`/`Num::Float`, not via `canon()`
        // (i.e. not via `parse_strict`): `1e20`, `1e21`, and `1.2e21` are all
        // integer-valued once parsed as `f64` (their fractional part is
        // exactly zero), and `Config::strict()`'s `RejectOutOfRange` policy
        // deliberately rejects an exponential/fractional *spelling* of an
        // integer outside the I-JSON interoperable range — see
        // `json.rs::classify_number` and
        // `the_number_policies_disagree_beyond_two_to_the_fifty_three` in
        // `json.rs`, which pins exactly that behaviour. That I-JSON range
        // policy is orthogonal to what this test checks (the ECMAScript
        // `Number::toString` exponent thresholds), so this test constructs
        // the `Json::Number(Num::Float(_))` value directly rather than
        // route every literal through the strict parser, the same way the
        // Appendix B test below does.
        for (src, want) in [
            ("1.0", "1"),
            ("100", "100"),
            ("1.5", "1.5"),
            ("0.1", "0.1"),
            ("-1.5", "-1.5"),
            ("1e-6", "0.000001"),
            ("1e-7", "1e-7"),
            ("1e20", "100000000000000000000"),
            ("1e21", "1e+21"),
            ("9007199254740991", "9007199254740991"),
            // The exponential branch with more than one significant digit.
            // Without these two, an implementation that omitted the decimal
            // point in that branch passes every other row, because `1e21`
            // and `1e-7` both have an empty tail.
            ("1.2e21", "1.2e+21"),
            ("1.2e-7", "1.2e-7"),
        ] {
            let f: f64 = src.parse().unwrap();
            let v = Json::Object(vec![(utf16("n"), Json::Number(Num::Float(f)))]);
            let got = canonicalize(&v).unwrap();
            assert_eq!(got, format!("{{\"n\":{want}}}"), "input {src}");
        }

        // F1: `canonicalize` must coerce a `Num::Int` through the same
        // ECMAScript double formatting as `Num::Float` — the loop above
        // exercises only the `Float` branch, which is exactly why the
        // `Int` branch was able to serialize `9007199254740993` as itself
        // (not RFC 8785 conformant: ECMAScript numbers have no
        // arbitrary-precision integer, so every implementation actually
        // signs the double `9007199254740992`) without any test noticing.
        let exact_int = Json::Object(vec![(
            utf16("n"),
            Json::Number(Num::Int(9_007_199_254_740_993)),
        )]);
        assert_eq!(
            canonicalize(&exact_int).unwrap(),
            r#"{"n":9007199254740992}"#,
            "Num::Int must be coerced through the double it would become"
        );
    }

    #[test]
    fn the_rfc_8785_appendix_b_vectors_all_pass() {
        // Transcribe all 24 rows of RFC 8785 Appendix B here as
        // `(hex bit pattern, expected serialization)` and assert each. Fetch
        // them from the RFC itself rather than from any secondary source.
        //
        // The last row exists solely to pin the round-half-to-even tie-break:
        //   43143ff3c1cb0959 -> 1424953923781206.2
        // A hand-rolled serializer built on Rust's float formatting produces
        // `...206.3` and passes every other row, so this table is the only
        // thing standing between this crate and a digest that disagrees with
        // every other JCS implementation.
        for (bits, want) in APPENDIX_B {
            let f = f64::from_bits(u64::from_str_radix(bits, 16).unwrap());
            assert_eq!(
                canonicalize(&Json::Number(Num::Float(f))).unwrap(),
                *want,
                "RFC 8785 Appendix B row {bits}"
            );
        }
        assert_eq!(APPENDIX_B.len(), 24, "all of Appendix B, not a selection");
    }

    #[test]
    fn nan_and_infinity_have_no_canonical_form() {
        // The two RFC 8785 Appendix B rows `APPENDIX_B` omits: `7fffffffffffffff`
        // (NaN) and `7ff0000000000000` (Infinity) have a blank "JSON
        // Representation" column in the RFC's own table, and note (3)
        // explains why — such values "are not permitted in JSON." An
        // implementation that emitted bare `NaN`/`inf` into canonical JSON
        // text (invalid JSON, and not what any conformant JCS
        // implementation produces) would pass every other test in this
        // file, so this pins both as errors instead. 24 (APPENDIX_B) + 2
        // (here) = 26, the RFC's full table.
        for bits in ["7fffffffffffffff", "7ff0000000000000"] {
            let f = f64::from_bits(u64::from_str_radix(bits, 16).unwrap());
            assert!(
                matches!(
                    canonicalize(&Json::Number(Num::Float(f))),
                    Err(JcsError::NonFinite { .. })
                ),
                "RFC 8785 Appendix B row {bits} (NaN/Infinity) must not canonicalize"
            );
        }
    }

    #[test]
    fn strings_escape_the_minimum_and_no_more() {
        // RFC 8785 section 3.2.2.2's full escape table in one string: the
        // six named short forms (\b \t \n \f \r plus the ones below), one
        // control character with no short form (0x0B and 0x1F, which must
        // fall through to \u00XX — lowercase, which is why the fixture
        // needs a hex digit that has a case at all), the two characters
        // JSON always escapes (`"` and `\`), and two characters JSON must
        // NOT escape even though other conventions sometimes do (`/`, and
        // DEL 0x7F, which is >= 0x20 and so passes through raw).
        let got = canonicalize(&Json::String(vec![
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x1F, 0x22, 0x2F, 0x5C, 0x7F,
        ]))
        .unwrap();
        let want = "\"\\b\\t\\n\\u000b\\f\\r\\u001f\\\"/\\\\\u{7f}\"";
        assert_eq!(got, want);
    }

    #[test]
    fn a_lone_surrogate_cannot_be_canonicalized() {
        // A lenient decoder can produce one; UTF-8 cannot represent it. This
        // is the point at which "the signature covers the bytes" stops being
        // a coherent claim. Three shapes are pinned: a lone high surrogate
        // at end of string, a lone low surrogate (which can only ever be
        // observed alone — a well-formed pair always consumes its low
        // surrogate before one could appear unpaired), and a high surrogate
        // immediately followed by an ordinary character, which exercises
        // the *following-unit-exists-but-is-wrong* branch rather than the
        // *no following unit* branch.
        let hi = parse(r#"{"a":"\ud800"}"#, Config::node_json_parse()).unwrap();
        assert!(matches!(
            canonicalize(&hi),
            Err(JcsError::LoneSurrogate { cp: 0xD800 })
        ));

        let lo = parse(r#"{"a":"\udc00"}"#, Config::node_json_parse()).unwrap();
        assert!(matches!(
            canonicalize(&lo),
            Err(JcsError::LoneSurrogate { cp: 0xDC00 })
        ));

        let hi_then_x = parse(r#"{"a":"\ud800x"}"#, Config::node_json_parse()).unwrap();
        assert!(matches!(
            canonicalize(&hi_then_x),
            Err(JcsError::LoneSurrogate { cp: 0xD800 })
        ));
    }

    #[test]
    fn two_wire_forms_of_one_document_share_a_digest() {
        // This is what a capability signs over, and the reason it is worth
        // signing at all.
        let a = digest(&parse_strict(r#"{"b":1,"a":[1,2]}"#).unwrap()).unwrap();
        let b = digest(&parse_strict("  {\n \"a\" : [1, 2] ,\"b\":1 }  ").unwrap()).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64, "sha-256 as lowercase hex");
    }

    #[test]
    fn digest_matches_a_known_answer() {
        // A known-answer test: without it, replacing `digest`'s body with
        // (say) `Sha256::digest(b"")` still passes every equality-based test
        // above, because both sides of every comparison would be equally
        // wrong. Independently confirmed outside this crate with
        // `printf '%s' '{"a":[1,2],"b":1}' | shasum -a 256`.
        let got = digest(&parse_strict(r#"{"b":1,"a":[1,2]}"#).unwrap()).unwrap();
        assert_eq!(
            got,
            "94a786c3662bc7beeb598efa7d8cb58d7bea25d6c275ea9785a0230ff1f8c2ba"
        );
    }

    #[test]
    fn the_duplicate_key_attack_produces_one_wire_form_and_two_meanings() {
        // The centrepiece, stated as an assertion. Two decoders accept the
        // same bytes, canonicalize to different documents, and disagree about
        // the recipient. The signature is valid for whichever one the
        // verifier happened to use.
        let wire = r#"{"to":"acct-1","to":"acct-9","amount":100}"#;
        let policy = parse(wire, Config::elixir_otp_json()).unwrap();
        let backend = parse(wire, Config::go_encoding_json()).unwrap();
        let pc = canonicalize(&policy).unwrap();
        let bc = canonicalize(&backend).unwrap();
        assert_ne!(pc, bc, "same bytes, two canonical forms");
        assert!(
            pc.contains("acct-1"),
            "policy engine saw the first key: {pc}"
        );
        assert!(bc.contains("acct-9"), "backend saw the last key: {bc}");
    }

    #[test]
    fn a_hand_built_object_with_a_duplicate_key_cannot_be_canonicalized() {
        // No `Config` can produce this: every duplicate-key policy in
        // `json.rs` collapses to one key per name during parsing. But
        // `Json::Object` is a public constructor, and later tasks (5/7/8)
        // build values directly rather than through a decoder. Left
        // unchecked this would canonicalize to `{"a":1,"a":2}`, which RFC
        // 8785 section 3.1 forbids outright, and which breaks identity: a
        // last-wins re-parse of that text produces a different canonical
        // form (and digest) than the value that produced it.
        let v = Json::Object(vec![
            (utf16("a"), Json::Number(Num::Int(1))),
            (utf16("a"), Json::Number(Num::Int(2))),
        ]);
        assert!(matches!(
            canonicalize(&v),
            Err(JcsError::DuplicateKey { .. })
        ));
    }

    #[test]
    fn digest_coerces_arbitrary_precision_integers_to_the_double_they_would_become() {
        // F1, agreement direction: `canonicalize`/`digest` answer "what does
        // every conformant JCS implementation sign for this value?" There is
        // no arbitrary-precision integer in ECMAScript's "Number", so a
        // `Num::Int` an arbitrary-precision decoder (Python) kept exact must
        // digest identically to the same literal as an IEEE-754 decoder (Go)
        // parsed it — anything else signs bytes no other implementation
        // produces.
        let wire = r#"{"n":9007199254740993}"#;
        let py = parse(wire, Config::python_json()).unwrap();
        let go = parse(wire, Config::go_encoding_json()).unwrap();
        assert_eq!(
            canonicalize(&py).unwrap(),
            r#"{"n":9007199254740992}"#,
            "coerced to the double ECMAScript would produce"
        );
        assert_eq!(digest(&py).unwrap(), digest(&go).unwrap());
    }

    #[test]
    fn es_number_is_the_material_key_and_disagrees_with_canonicalize_on_purpose() {
        // F1, the other half: `es_number` is the identity Task 3's
        // differential compares by, and it must NOT coerce, or the very
        // divergence the paper exists to surface — an arbitrary-precision
        // decoder keeping a literal exact while an IEEE-754 decoder rounds
        // it — would vanish at the one place meant to detect it.
        let exact = Num::Int(9_007_199_254_740_993);
        let rounded = Num::Float(9_007_199_254_740_992.0);
        assert_ne!(
            es_number(&exact).unwrap(),
            es_number(&rounded).unwrap(),
            "an arbitrary-precision decoder and an IEEE-754 decoder must be seen to disagree"
        );

        // The agreement direction, so the disagreement above is not just
        // `es_number` being generically strict: two spellings of the *same*
        // value, one exact and one a double, must still agree.
        assert_eq!(
            es_number(&Num::Int(100)).unwrap(),
            es_number(&Num::Float(100.0)).unwrap(),
            "the same value under two decoders' number policies must agree"
        );
    }
}
