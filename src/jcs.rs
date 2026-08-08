use crate::json::{Json, Num, Utf16};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum JcsError {
    #[error(
        "lone surrogate U+{cp:04X} cannot be encoded as UTF-8, so this value has no canonical form"
    )]
    LoneSurrogate { cp: u32 },
    #[error("`{value}` is not finite and has no canonical form")]
    NonFinite { value: String },
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
        Json::Number(n) => out.push_str(&number(n)?),
        Json::String(u) => write_string(u, out)?,
        Json::Array(a) => {
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

/// The canonical serialization of one number. Public because it is also the
/// numeric identity `decoder::render` compares by: two decoders agree about a
/// number exactly when they would canonicalize it the same way, which is the
/// property a capability digest actually rests on.
pub fn es_number(n: &Num) -> Result<String, JcsError> {
    number(n)
}

fn number(n: &Num) -> Result<String, JcsError> {
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
    if f == 0.0 {
        // Covers -0.0 too: RFC 8785 serializes negative zero as `0`. Strict
        // parsing rejects the literal precisely because this step is lossy.
        return "0".to_string();
    }
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
    // RFC 8785 §3.2.2.3 names Ryū as a compatible reference.
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
                out.push(char::from_u32(cp).ok_or(JcsError::LoneSurrogate { cp })?);
                i += 2;
                continue;
            }
            0xDC00..=0xDFFF => return Err(JcsError::LoneSurrogate { cp: c as u32 }),
            _ => {
                out.push(char::from_u32(c as u32).ok_or(JcsError::LoneSurrogate { cp: c as u32 })?)
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
    /// are omitted here, leaving the 24 rows that actually serialize.
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
    fn strings_escape_the_minimum_and_no_more() {
        let got = canon("{\"a\":\"x\\\"\\\\\\n\\u0001y\u{e9}\u{1f600}\"}");
        assert_eq!(got, "{\"a\":\"x\\\"\\\\\\n\\u0001y\u{e9}\u{1f600}\"}");
    }

    #[test]
    fn a_lone_surrogate_cannot_be_canonicalized() {
        // A lenient decoder can produce one; UTF-8 cannot represent it. This
        // is the point at which "the signature covers the bytes" stops being
        // a coherent claim.
        let v = parse(r#"{"a":"\ud800"}"#, Config::node_json_parse()).unwrap();
        assert!(matches!(
            canonicalize(&v),
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
}
