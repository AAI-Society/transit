/// The largest integer RFC 7493 §2.2 guarantees is interoperable: 2^53 - 1.
pub const I_JSON_INT_MAX: i128 = 9_007_199_254_740_991;

/// Recursion cap. Hostile input is the *design* input here, so a deeply
/// nested document must be an error rather than a stack overflow.
pub const MAX_DEPTH: usize = 128;

/// A JSON string as UTF-16 code units.
///
/// Not a `String`, deliberately: a lone surrogate is unrepresentable in a
/// Rust `String`, and a lone surrogate silently swallowed is one of the
/// failures this crate exists to expose. It is also the unit RFC 8785 sorts
/// object keys by.
pub type Utf16 = Vec<u16>;

pub fn utf16(s: &str) -> Utf16 {
    s.encode_utf16().collect()
}

/// For diagnostics only. Lossy by name and by nature — never use it where a
/// comparison depends on the result.
pub fn lossy(u: &[u16]) -> String {
    String::from_utf16_lossy(u)
}

#[derive(Clone, Debug, PartialEq)]
pub enum Num {
    /// An integer kept exactly, as arbitrary-precision decoders do.
    Int(i128),
    /// An IEEE-754 double, as ECMAScript-shaped decoders produce.
    Float(f64),
}

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(Num),
    String(Utf16),
    Array(Vec<Json>),
    /// Key order is preserved exactly as parsed and is **not** sorted here.
    /// Which key won is the measurement.
    Object(Vec<(Utf16, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        let k = utf16(key);
        match self {
            Json::Object(m) => m.iter().find(|(kk, _)| *kk == k).map(|(_, v)| v),
            _ => None,
        }
    }

    /// `None` when the string is not well-formed Unicode — which is a fact
    /// worth knowing, not an inconvenience to paper over.
    pub fn as_string(&self) -> Option<String> {
        match self {
            Json::String(u) => String::from_utf16(u).ok(),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Number(Num::Int(i)) => Some(*i as f64),
            Json::Number(Num::Float(f)) => Some(*f),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DuplicatePolicy {
    /// RFC 8785. The only correct answer.
    Reject,
    /// Elixir OTP `:json`, and any policy engine that retains the first.
    FirstWins,
    /// Go `encoding/json`, Node `JSON.parse`, Python, Ruby.
    LastWins,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurrogatePolicy {
    /// Strict, and Ruby's `JSON.parse`, which raises.
    Reject,
    /// Go `encoding/json`: silently substitutes U+FFFD, changing the bytes.
    Replace,
    /// Node and Python: the unpaired code unit survives into the value.
    Retain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumberPolicy {
    /// Strict: reject anything outside the I-JSON interoperable range,
    /// anything that underflows, and negative zero.
    RejectOutOfRange,
    /// Node and Go: every number becomes a double.
    Ieee754Double,
    /// Python and Ruby: integer literals stay exact.
    ArbitraryPrecision,
}

/// RFC 7493 §2.1 forbids noncharacters as well as surrogates. It is a
/// separate knob from `SurrogatePolicy` because Ruby rejects lone surrogates
/// while still accepting noncharacters, so the two do not travel together in
/// any real decoder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoncharacterPolicy {
    /// RFC 7493. Only strict mode does this; no production decoder does.
    Reject,
    Accept,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub duplicates: DuplicatePolicy,
    pub surrogates: SurrogatePolicy,
    pub numbers: NumberPolicy,
    pub noncharacters: NoncharacterPolicy,
}

impl Config {
    /// RFC 7493 + RFC 8785. What an authorization pipeline must use.
    pub const fn strict() -> Self {
        Config {
            duplicates: DuplicatePolicy::Reject,
            surrogates: SurrogatePolicy::Reject,
            numbers: NumberPolicy::RejectOutOfRange,
            noncharacters: NoncharacterPolicy::Reject,
        }
    }

    pub const fn go_encoding_json() -> Self {
        Config {
            duplicates: DuplicatePolicy::LastWins,
            surrogates: SurrogatePolicy::Replace,
            numbers: NumberPolicy::Ieee754Double,
            noncharacters: NoncharacterPolicy::Accept,
        }
    }

    pub const fn node_json_parse() -> Self {
        Config {
            duplicates: DuplicatePolicy::LastWins,
            surrogates: SurrogatePolicy::Retain,
            numbers: NumberPolicy::Ieee754Double,
            noncharacters: NoncharacterPolicy::Accept,
        }
    }

    pub const fn python_json() -> Self {
        Config {
            duplicates: DuplicatePolicy::LastWins,
            surrogates: SurrogatePolicy::Retain,
            numbers: NumberPolicy::ArbitraryPrecision,
            noncharacters: NoncharacterPolicy::Accept,
        }
    }

    pub const fn ruby_json() -> Self {
        Config {
            duplicates: DuplicatePolicy::LastWins,
            surrogates: SurrogatePolicy::Reject,
            numbers: NumberPolicy::ArbitraryPrecision,
            noncharacters: NoncharacterPolicy::Accept,
        }
    }

    /// Elixir OTP `:json`. **Modelled from documentation and not verified**:
    /// no Elixir runtime is installed on the development host, so this
    /// configuration is a claim of exactly the kind this tool exists to
    /// distrust. Task 4 records that distinction in its provenance.
    pub const fn elixir_otp_json() -> Self {
        Config {
            duplicates: DuplicatePolicy::FirstWins,
            surrogates: SurrogatePolicy::Reject,
            numbers: NumberPolicy::ArbitraryPrecision,
            noncharacters: NoncharacterPolicy::Accept,
        }
    }
}

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum JsonError {
    #[error("duplicate object key `{key}` at byte {at}; RFC 8785 forbids duplicate keys")]
    DuplicateKey { key: String, at: usize },
    #[error("lone surrogate U+{cp:04X} at byte {at}; RFC 7493 requires well-formed Unicode")]
    LoneSurrogate { cp: u32, at: usize },
    #[error("noncharacter U+{cp:04X} at byte {at}; RFC 7493 §2.1 forbids noncharacters")]
    NonCharacter { cp: u32, at: usize },
    #[error("number `{literal}` at byte {at} is outside the I-JSON interoperable range")]
    NumberOutOfRange { literal: String, at: usize },
    #[error("number `{literal}` at byte {at} underflows to zero")]
    NumberUnderflow { literal: String, at: usize },
    #[error("negative zero at byte {at} has no canonical form distinct from zero")]
    NegativeZero { at: usize },
    #[error("nesting deeper than {limit} levels at byte {at}")]
    TooDeep { limit: usize, at: usize },
    #[error("{what} at byte {at}")]
    Syntax { what: String, at: usize },
}

pub fn parse_strict(src: &str) -> Result<Json, JsonError> {
    parse(src, Config::strict())
}

pub fn parse(src: &str, cfg: Config) -> Result<Json, JsonError> {
    let mut p = P {
        b: src.as_bytes(),
        i: 0,
        depth: 0,
        cfg,
    };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != p.b.len() {
        return Err(p.syntax("trailing content"));
    }
    Ok(v)
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
    cfg: Config,
}

fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        _ => 4,
    }
}

impl<'a> P<'a> {
    fn syntax(&self, what: &str) -> JsonError {
        JsonError::Syntax {
            what: what.to_string(),
            at: self.i,
        }
    }

    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> Result<(), JsonError> {
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(self.syntax(&format!("expected `{}`", c as char)))
        }
    }

    fn enter(&mut self) -> Result<(), JsonError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(JsonError::TooDeep {
                limit: MAX_DEPTH,
                at: self.i,
            });
        }
        Ok(())
    }

    fn value(&mut self) -> Result<Json, JsonError> {
        match self.peek() {
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Json::String(self.string()?)),
            Some(b't') => {
                self.lit(b"true")?;
                Ok(Json::Bool(true))
            }
            Some(b'f') => {
                self.lit(b"false")?;
                Ok(Json::Bool(false))
            }
            Some(b'n') => {
                self.lit(b"null")?;
                Ok(Json::Null)
            }
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(_) => Err(self.syntax("unexpected character")),
            None => Err(self.syntax("unexpected end of input")),
        }
    }

    fn lit(&mut self, w: &[u8]) -> Result<(), JsonError> {
        if self.b[self.i..].starts_with(w) {
            self.i += w.len();
            Ok(())
        } else {
            Err(self.syntax("invalid literal"))
        }
    }

    fn array(&mut self) -> Result<Json, JsonError> {
        self.enter()?;
        self.eat(b'[')?;
        let mut out = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            self.depth -= 1;
            return Ok(Json::Array(out));
        }
        loop {
            self.ws();
            out.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(self.syntax("expected `,` or `]`")),
            }
        }
        self.depth -= 1;
        Ok(Json::Array(out))
    }

    fn object(&mut self) -> Result<Json, JsonError> {
        self.enter()?;
        self.eat(b'{')?;
        let mut out: Vec<(Utf16, Json)> = Vec::new();
        // A side index for the duplicate check. A linear scan per member is
        // O(n^2), and 20k distinct keys — a 250 KB object anyone can post —
        // takes about a second, which is a CPU-exhaustion vector in a tool
        // whose whole purpose is to accept hostile input. The `Vec` still
        // owns member order, which is the thing being measured.
        let mut seen: std::collections::HashMap<Utf16, usize> = std::collections::HashMap::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            self.depth -= 1;
            return Ok(Json::Object(out));
        }
        loop {
            self.ws();
            let at = self.i;
            let k = self.string()?;
            self.ws();
            self.eat(b':')?;
            self.ws();
            let v = self.value()?;
            match seen.get(&k).copied() {
                None => {
                    seen.insert(k.clone(), out.len());
                    out.push((k, v));
                }
                Some(pos) => match self.cfg.duplicates {
                    DuplicatePolicy::Reject => {
                        return Err(JsonError::DuplicateKey { key: lossy(&k), at })
                    }
                    // The first binding stays, in place.
                    DuplicatePolicy::FirstWins => {}
                    // The value is overwritten; the key keeps its position,
                    // which is what Go's map and JS's object both do.
                    DuplicatePolicy::LastWins => out[pos].1 = v,
                },
            }
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err(self.syntax("expected `,` or `}`")),
            }
        }
        self.depth -= 1;
        Ok(Json::Object(out))
    }

    fn string(&mut self) -> Result<Utf16, JsonError> {
        self.eat(b'"')?;
        let mut out: Utf16 = Vec::new();
        loop {
            let c = self
                .peek()
                .ok_or_else(|| self.syntax("unterminated string"))?;
            match c {
                b'"' => {
                    self.i += 1;
                    break;
                }
                b'\\' => {
                    self.i += 1;
                    self.escape(&mut out)?;
                }
                0x00..=0x1F => return Err(self.syntax("unescaped control character")),
                _ => {
                    let start = self.i;
                    let end = start + utf8_len(c);
                    if end > self.b.len() {
                        return Err(self.syntax("truncated UTF-8 sequence"));
                    }
                    let s = std::str::from_utf8(&self.b[start..end])
                        .map_err(|_| self.syntax("invalid UTF-8"))?;
                    // RFC 7493 §2.1 applies "both to characters encoded
                    // directly in UTF-8 and to those which are escaped", so
                    // the raw path is checked as well as the escape path.
                    for ch in s.chars() {
                        self.reject_noncharacter(ch as u32, start)?;
                    }
                    out.extend(s.encode_utf16());
                    self.i = end;
                }
            }
        }
        Ok(out)
    }

    fn escape(&mut self, out: &mut Utf16) -> Result<(), JsonError> {
        let c = self
            .peek()
            .ok_or_else(|| self.syntax("unterminated escape"))?;
        self.i += 1;
        let u: u16 = match c {
            b'"' => 0x22,
            b'\\' => 0x5C,
            b'/' => 0x2F,
            b'b' => 0x08,
            b'f' => 0x0C,
            b'n' => 0x0A,
            b'r' => 0x0D,
            b't' => 0x09,
            b'u' => return self.unicode_escape(out),
            _ => return Err(self.syntax("unknown escape")),
        };
        out.push(u);
        Ok(())
    }

    fn hex4(&mut self) -> Result<u16, JsonError> {
        if self.i + 4 > self.b.len() {
            return Err(self.syntax("truncated \\u escape"));
        }
        let s = std::str::from_utf8(&self.b[self.i..self.i + 4])
            .map_err(|_| self.syntax("bad \\u escape"))?;
        let v = u16::from_str_radix(s, 16).map_err(|_| self.syntax("bad \\u escape"))?;
        self.i += 4;
        Ok(v)
    }

    fn unicode_escape(&mut self, out: &mut Utf16) -> Result<(), JsonError> {
        let at = self.i;
        let hi = self.hex4()?;
        if (0xD800..0xDC00).contains(&hi) {
            // A high surrogate is only well-formed when a low surrogate
            // follows. Look ahead, and rewind if it does not.
            if self.b[self.i..].starts_with(b"\\u") {
                let save = self.i;
                self.i += 2;
                let lo = self.hex4()?;
                if (0xDC00..0xE000).contains(&lo) {
                    // A well-formed pair can still encode a noncharacter:
                    // 􏿿 is U+10FFFF.
                    let cp = 0x10000 + (((hi as u32) - 0xD800) << 10) + ((lo as u32) - 0xDC00);
                    self.reject_noncharacter(cp, at)?;
                    out.push(hi);
                    out.push(lo);
                    return Ok(());
                }
                self.i = save;
            }
            return self.lone(hi as u32, at, out);
        }
        if (0xDC00..0xE000).contains(&hi) {
            return self.lone(hi as u32, at, out);
        }
        self.reject_noncharacter(hi as u32, at)?;
        out.push(hi);
        Ok(())
    }

    /// The 66 noncharacters: U+FDD0..=U+FDEF, and the last two code points of
    /// every plane.
    fn reject_noncharacter(&self, cp: u32, at: usize) -> Result<(), JsonError> {
        if self.cfg.noncharacters == NoncharacterPolicy::Accept {
            return Ok(());
        }
        if (0xFDD0..=0xFDEF).contains(&cp) || (cp & 0xFFFE) == 0xFFFE {
            return Err(JsonError::NonCharacter { cp, at });
        }
        Ok(())
    }

    fn lone(&mut self, cp: u32, at: usize, out: &mut Utf16) -> Result<(), JsonError> {
        match self.cfg.surrogates {
            SurrogatePolicy::Reject => Err(JsonError::LoneSurrogate { cp, at }),
            SurrogatePolicy::Replace => {
                out.push(0xFFFD);
                Ok(())
            }
            SurrogatePolicy::Retain => {
                out.push(cp as u16);
                Ok(())
            }
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let at = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            // A leading zero may not be followed by more digits.
            Some(b'0') => self.i += 1,
            Some(c) if c.is_ascii_digit() => {
                while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                    self.i += 1;
                }
            }
            _ => return Err(self.syntax("expected a digit")),
        }
        let mut fractional = false;
        if self.peek() == Some(b'.') {
            fractional = true;
            self.i += 1;
            if !matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                return Err(self.syntax("expected a digit after `.`"));
            }
            while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            fractional = true;
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                return Err(self.syntax("expected a digit in the exponent"));
            }
            while matches!(self.peek(), Some(d) if d.is_ascii_digit()) {
                self.i += 1;
            }
        }
        let lit = std::str::from_utf8(&self.b[at..self.i])
            .map_err(|_| self.syntax("bad number"))?
            .to_string();
        self.classify_number(&lit, fractional, at)
    }

    fn classify_number(&self, lit: &str, fractional: bool, at: usize) -> Result<Json, JsonError> {
        let as_f64 = || -> Result<f64, JsonError> {
            lit.parse::<f64>().map_err(|_| JsonError::Syntax {
                what: "unparseable number".into(),
                at,
            })
        };
        match self.cfg.numbers {
            NumberPolicy::Ieee754Double => Ok(Json::Number(Num::Float(as_f64()?))),

            NumberPolicy::ArbitraryPrecision => {
                if fractional {
                    return Ok(Json::Number(Num::Float(as_f64()?)));
                }
                // i128 is this crate's honest ceiling for "exact"; a literal
                // beyond it is reported rather than quietly rounded.
                match lit.parse::<i128>() {
                    Ok(v) => Ok(Json::Number(Num::Int(v))),
                    Err(_) => Err(JsonError::NumberOutOfRange {
                        literal: lit.into(),
                        at,
                    }),
                }
            }

            NumberPolicy::RejectOutOfRange => {
                if !fractional {
                    let v: i128 = lit.parse().map_err(|_| JsonError::NumberOutOfRange {
                        literal: lit.into(),
                        at,
                    })?;
                    if v == 0 && lit.starts_with('-') {
                        return Err(JsonError::NegativeZero { at });
                    }
                    // Not `v.abs()`: `i128::MIN.abs()` overflows, which panics
                    // in debug and wraps in release — and a wrapped compare is
                    // false, so `parse_strict` would *accept* an integer 10^22
                    // outside the interoperable range. Compare both bounds
                    // (written as a range check because clippy's
                    // `manual_range_contains` denies the `||` form under
                    // `-D warnings`; the semantics are unchanged).
                    if !(-I_JSON_INT_MAX..=I_JSON_INT_MAX).contains(&v) {
                        return Err(JsonError::NumberOutOfRange {
                            literal: lit.into(),
                            at,
                        });
                    }
                    return Ok(Json::Number(Num::Int(v)));
                }
                let f = as_f64()?;
                if !f.is_finite() {
                    return Err(JsonError::NumberOutOfRange {
                        literal: lit.into(),
                        at,
                    });
                }
                // A fractional *spelling* of an out-of-range integer must not
                // slip through. `9007199254740993` is rejected above, and
                // `9007199254740993.0` names the same value, so it has to be
                // rejected too — otherwise one extra character bypasses the
                // strict decoder, inside the very component this paper offers
                // as the correct reference.
                if f.fract() == 0.0 && f.abs() > I_JSON_INT_MAX as f64 {
                    return Err(JsonError::NumberOutOfRange {
                        literal: lit.into(),
                        at,
                    });
                }
                if f == 0.0 {
                    if f.is_sign_negative() {
                        return Err(JsonError::NegativeZero { at });
                    }
                    // A literal with a non-zero digit that arrived at zero
                    // underflowed. `1e-400` is the case the desk study names.
                    if lit.chars().any(|c| c.is_ascii_digit() && c != '0') {
                        return Err(JsonError::NumberUnderflow {
                            literal: lit.into(),
                            at,
                        });
                    }
                }
                Ok(Json::Number(Num::Float(f)))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DUP: &str = r#"{"to":"acct-1","to":"acct-9"}"#;

    fn s(j: &Json, key: &str) -> String {
        j.get(key).and_then(Json::as_string).expect("string value")
    }

    #[test]
    fn strict_rejects_duplicate_keys() {
        // RFC 8785 §3.1 prohibits them. Everything else in this crate follows
        // from the fact that production decoders do not.
        let err = parse_strict(DUP).unwrap_err();
        assert!(matches!(err, JsonError::DuplicateKey { .. }), "got {err}");
    }

    #[test]
    fn the_two_duplicate_policies_disagree_on_the_same_bytes() {
        let first = parse(DUP, Config::elixir_otp_json()).unwrap();
        let last = parse(DUP, Config::go_encoding_json()).unwrap();
        assert_eq!(s(&first, "to"), "acct-1", "first-key-wins");
        assert_eq!(s(&last, "to"), "acct-9", "last-key-wins");
    }

    #[test]
    fn last_key_wins_keeps_the_original_key_position() {
        // Go and Node overwrite the value but do not move the key. Position
        // matters because the observation format in Task 3 sorts, and a
        // reordering bug would hide behind that sort.
        let j = parse(r#"{"a":1,"b":2,"a":3}"#, Config::node_json_parse()).unwrap();
        let Json::Object(m) = &j else {
            panic!("object")
        };
        assert_eq!(m.len(), 2);
        assert_eq!(lossy(&m[0].0), "a");
    }

    #[test]
    fn the_three_surrogate_policies_disagree_on_a_lone_surrogate() {
        let src = r#"{"a":"\ud800"}"#;
        assert!(matches!(
            parse(src, Config::strict()).unwrap_err(),
            JsonError::LoneSurrogate { cp: 0xD800, .. }
        ));
        let go = parse(src, Config::go_encoding_json()).unwrap();
        assert_eq!(
            go.get("a"),
            Some(&Json::String(vec![0xFFFD])),
            "Go replaces"
        );
        let node = parse(src, Config::node_json_parse()).unwrap();
        assert_eq!(
            node.get("a"),
            Some(&Json::String(vec![0xD800])),
            "Node retains"
        );
    }

    #[test]
    fn a_well_formed_surrogate_pair_survives_every_policy() {
        for cfg in [
            Config::strict(),
            Config::go_encoding_json(),
            Config::node_json_parse(),
        ] {
            let j = parse(r#"{"a":"😀"}"#, cfg).unwrap();
            assert_eq!(
                j.get("a"),
                Some(&Json::String(vec![0xD83D, 0xDE00])),
                "{cfg:?}"
            );
        }
    }

    #[test]
    fn the_number_policies_disagree_beyond_two_to_the_fifty_three() {
        let src = r#"{"n":9007199254740993}"#;
        assert!(matches!(
            parse(src, Config::strict()).unwrap_err(),
            JsonError::NumberOutOfRange { .. }
        ));
        assert_eq!(
            parse(src, Config::python_json()).unwrap().get("n"),
            Some(&Json::Number(Num::Int(9_007_199_254_740_993))),
            "arbitrary precision keeps it"
        );
        assert_eq!(
            parse(src, Config::node_json_parse()).unwrap().get("n"),
            Some(&Json::Number(Num::Float(9_007_199_254_740_992.0))),
            "IEEE-754 rounds it down"
        );
    }

    #[test]
    fn strict_rejects_underflow_and_negative_zero() {
        assert!(matches!(
            parse_strict(r#"{"n":1e-400}"#).unwrap_err(),
            JsonError::NumberUnderflow { .. }
        ));
        assert!(matches!(
            parse_strict(r#"{"n":-0}"#).unwrap_err(),
            JsonError::NegativeZero { .. }
        ));
        assert!(matches!(
            parse_strict(r#"{"n":-0.0}"#).unwrap_err(),
            JsonError::NegativeZero { .. }
        ));
        // A zero that is genuinely zero is fine, and so is a legitimate small
        // number. Without these two the rule above could be "reject anything
        // near zero" and the tests would not notice.
        assert!(parse_strict(r#"{"n":0}"#).is_ok());
        assert!(parse_strict(r#"{"n":1e-300}"#).is_ok());
    }

    #[test]
    fn deep_nesting_is_an_error_not_a_stack_overflow() {
        let src = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(matches!(
            parse_strict(&src).unwrap_err(),
            JsonError::TooDeep { .. }
        ));
    }

    #[test]
    fn malformed_input_errors_rather_than_panicking() {
        for bad in [
            "",
            "{",
            "[",
            r#"{"a"}"#,
            r#"{"a":}"#,
            r#"{"a":1,}"#,
            r#"{"a":1} x"#,
            r#""\u00"#,
            r#""unterminated"#,
            r#"{"a":01}"#,
            r#"{"a":.5}"#,
            r#"{"a":1e}"#,
            "\"\u{1}\"",
            r#"{"a":tru}"#,
        ] {
            assert!(parse_strict(bad).is_err(), "expected an error for {bad:?}");
        }
    }
}
