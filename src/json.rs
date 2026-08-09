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
    /// Strict.
    Reject,
    /// Go `encoding/json`: silently substitutes U+FFFD, changing the bytes.
    Replace,
    /// Node and Python: the unpaired code unit survives into the value.
    Retain,
    /// Ruby `JSON.parse` (measured against json gem 2.1.0 on Ruby 2.6.10;
    /// a fix-round-1 correction — the desk study modelled Ruby as uniformly
    /// `Reject`, and a direct measurement contradicted that on both halves).
    /// Ruby's surrogate handling is genuinely asymmetric and does not fit
    /// the uniform Reject/Replace/Retain shape at all:
    ///   * A lone *low* surrogate (no preceding high surrogate) is accepted
    ///     and retained verbatim: `"\udc00"` parses successfully, keeping
    ///     the raw code unit — measured as the WTF-8-ish byte sequence
    ///     `ed b0 80`, i.e. `S:dc00` once rendered as UTF-16 units.
    ///   * A lone *high* surrogate — one not immediately followed by
    ///     another `\uXXXX` escape — is rejected: `"\ud800"` raises
    ///     `incomplete surrogate pair`. So does a high surrogate followed by
    ///     a raw, unescaped letter `A` rather than a second `\u` escape —
    ///     the source text `\ud800` + a literal `A` character also raises.
    ///     Measured directly; an earlier draft of this correction assumed a
    ///     raw character paired too, and it does not.
    ///   * A high surrogate immediately followed by ANY `\uXXXX` escape —
    ///     even one that is not itself a valid low surrogate — is combined:
    ///     both halves are masked with `0x3FF` and combined as though the
    ///     second one were the low half, with no range validation at all.
    ///     A high-surrogate escape followed by a *second* `\u` escape
    ///     naming plain U+0041 (the letter A, spelled as an escape rather
    ///     than raw) parses to U+10041, and that character is not emitted
    ///     on its own — it is consumed into the surrogate arithmetic.
    ///     A high-surrogate escape followed by a `\u` escape naming
    ///     U+DBFF (itself a *high* surrogate, not a low one) parses to
    ///     U+103FF by the identical formula.
    RubyPairAnyEscape,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NumberPolicy {
    /// Strict: reject anything outside the I-JSON interoperable range,
    /// anything that underflows, and negative zero.
    RejectOutOfRange,
    /// Node, Go, Ruby, Elixir: every number becomes a double (integers
    /// included — an arbitrary-precision decoder keeps the integer exact
    /// instead; see `ArbitraryPrecision`). Whether an out-of-range literal
    /// silently becomes an infinity or is rejected is `OverflowPolicy`, an
    /// orthogonal knob — see that type.
    Ieee754Double,
    /// Python and Ruby: integer literals stay exact. A fractional literal
    /// still becomes a double, and is still subject to `OverflowPolicy`.
    ArbitraryPrecision,
}

/// Whether a literal whose magnitude overflows a `f64`'s finite range (e.g.
/// `1e400`) is accepted as +/-Infinity or rejected outright. Orthogonal to
/// `NumberPolicy` on purpose: it cross-cuts both `Ieee754Double` (Go
/// rejects, Node does not) and `ArbitraryPrecision` (Elixir rejects, Python
/// and Ruby do not), so folding it into a fourth/fifth `NumberPolicy`
/// variant would have meant duplicating every finite-range branch instead of
/// checking one extra flag in each.
///
/// Go: measured — `encoding/json.Unmarshal` surfaces `strconv.ParseFloat`'s
/// `ErrRange` as `json: cannot unmarshal number 1e400 into Go value of type
/// float64`, a Task 4 correction (the desk study modelled Go identically to
/// Node here). Elixir: measured on GCP (`results/elixir-measurement.txt`) —
/// real `:json` rejects `1e400` with `{:unexpected_sequence, "1.0e400"}`
/// where the model previously parsed it to infinity and accepted, the same
/// mistake Task 4 found and fixed for Go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Node, Python, Ruby: silently overflows to +/-Infinity. Measured:
    /// `JSON.parse("1e400")` is `Infinity` in both Node and Ruby, and
    /// `json.loads("1e400")` is `inf` in Python — not an error in any of
    /// the three.
    Permit,
    /// Go, Elixir: a literal that would overflow to +/-Infinity is a parse
    /// error instead.
    Reject,
}

/// Whether the bare (non-standard, not RFC 8259) tokens `NaN`, `Infinity`
/// and `-Infinity` are accepted as number values. This is lexer-level, not
/// `NumberPolicy`: these are not spelled as JSON numbers at all (no digits),
/// so `classify_number` never sees them — `value()` recognizes the literal
/// token directly, the same way it already recognizes `true`/`false`/`null`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonFiniteLiteralPolicy {
    /// RFC 8259 §6 does not define these as JSON tokens, and every decoder
    /// modelled here except Python rejects them. The default.
    Reject,
    /// CPython's `json.loads` default (`parse_constant`/`allow_nan` both
    /// default to allowing them, measured): bare `NaN`, `Infinity` and
    /// `-Infinity` tokens parse to the IEEE-754 special value they name.
    Accept,
}

/// RFC 7493 §2.1 forbids noncharacters as well as surrogates. It is a
/// separate knob from `SurrogatePolicy` because every lenient decoder
/// modelled here accepts noncharacters while disagreeing with each other
/// about surrogates, so the two do not travel together in any real decoder.
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
    pub overflow: OverflowPolicy,
    pub non_finite: NonFiniteLiteralPolicy,
    pub noncharacters: NoncharacterPolicy,
}

impl Config {
    /// RFC 7493 + RFC 8785, **plus** a deliberate policy choice stricter
    /// than either RFC requires: `NumberPolicy::RejectOutOfRange` rejects
    /// any integer-valued literal outside ±(2^53 − 1), full stop. Neither
    /// RFC actually forbids `1e20` or `1e21` — RFC 7493 §2.2's guidance
    /// there is a `SHOULD NOT`, not a `MUST`, and it targets magnitude or
    /// precision *beyond* what an IEEE-754 double provides; `1e20` and
    /// `1e21` are exactly representable, so nothing in either RFC would
    /// reject them. The blunt ±(2^53 − 1) cutoff is a fail-closed choice
    /// made here on purpose, because the actual hazard is integers that are
    /// *not* exactly representable, which is precisely where real decoders
    /// (arbitrary-precision vs. IEEE-754) are observed to disagree — see
    /// `jcs::es_number`. What an authorization pipeline must use.
    pub const fn strict() -> Self {
        Config {
            duplicates: DuplicatePolicy::Reject,
            surrogates: SurrogatePolicy::Reject,
            numbers: NumberPolicy::RejectOutOfRange,
            // Irrelevant to `RejectOutOfRange`, which independently rejects
            // any non-finite result on its own path, but every `Config`
            // needs a value.
            overflow: OverflowPolicy::Reject,
            non_finite: NonFiniteLiteralPolicy::Reject,
            noncharacters: NoncharacterPolicy::Reject,
        }
    }

    pub const fn go_encoding_json() -> Self {
        Config {
            duplicates: DuplicatePolicy::LastWins,
            surrogates: SurrogatePolicy::Replace,
            numbers: NumberPolicy::Ieee754Double,
            // Fix round 1, C1: measured against the real `go` binary — see
            // `OverflowPolicy`'s doc comment for the evidence.
            overflow: OverflowPolicy::Reject,
            non_finite: NonFiniteLiteralPolicy::Reject,
            noncharacters: NoncharacterPolicy::Accept,
        }
    }

    pub const fn node_json_parse() -> Self {
        Config {
            duplicates: DuplicatePolicy::LastWins,
            surrogates: SurrogatePolicy::Retain,
            numbers: NumberPolicy::Ieee754Double,
            overflow: OverflowPolicy::Permit,
            non_finite: NonFiniteLiteralPolicy::Reject,
            noncharacters: NoncharacterPolicy::Accept,
        }
    }

    pub const fn python_json() -> Self {
        Config {
            duplicates: DuplicatePolicy::LastWins,
            surrogates: SurrogatePolicy::Retain,
            numbers: NumberPolicy::ArbitraryPrecision,
            overflow: OverflowPolicy::Permit,
            // Fix round 1, C4: `json.loads`'s `allow_nan` default accepts
            // bare `NaN`/`Infinity`/`-Infinity` — measured, and the only one
            // of the four modelled runtimes that does.
            non_finite: NonFiniteLiteralPolicy::Accept,
            noncharacters: NoncharacterPolicy::Accept,
        }
    }

    pub const fn ruby_json() -> Self {
        Config {
            duplicates: DuplicatePolicy::LastWins,
            // Fix round 1, C3: measured against the real `ruby` binary —
            // see `SurrogatePolicy::RubyPairAnyEscape`'s doc comment. Plain
            // `Reject` (this crate's original model) was wrong for a lone
            // low surrogate and for a high surrogate paired with any
            // subsequent escape.
            surrogates: SurrogatePolicy::RubyPairAnyEscape,
            numbers: NumberPolicy::ArbitraryPrecision,
            overflow: OverflowPolicy::Permit,
            non_finite: NonFiniteLiteralPolicy::Reject,
            noncharacters: NoncharacterPolicy::Accept,
        }
    }

    /// Elixir OTP `:json`. Measured on GCP (elixir 1.17.3 / OTP 27); see
    /// `results/elixir-measurement.txt`. First-key-wins, exact integers,
    /// rejecting both surrogate halves, accepting noncharacters, and
    /// accepting negative zero / underflow are all confirmed as modelled.
    /// Overflow was not: fix round 1, C6, corrects it below.
    pub const fn elixir_otp_json() -> Self {
        Config {
            duplicates: DuplicatePolicy::FirstWins,
            surrogates: SurrogatePolicy::Reject,
            numbers: NumberPolicy::ArbitraryPrecision,
            // Measured: real `:json` rejects `1e400` with
            // `{:unexpected_sequence, "1.0e400"}` rather than parsing it to
            // infinity. See `OverflowPolicy`'s doc comment.
            overflow: OverflowPolicy::Reject,
            non_finite: NonFiniteLiteralPolicy::Reject,
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
    #[error(
        "number `{literal}` at byte {at} overflows the finite range of a 64-bit float; this \
         decoder rejects it rather than silently producing an infinity"
    )]
    NumberOverflowsFloat64 { literal: String, at: usize },
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
            // Fix round 1, C4: `NaN`/`Infinity`/`-Infinity` are not JSON
            // number literals — RFC 8259 §6 has no such tokens — so this is
            // handled here, at the same level as `true`/`false`/`null`, and
            // never reaches `number()`/`classify_number` at all. Gated on
            // `NonFiniteLiteralPolicy`, which only `Config::python_json()`
            // sets to `Accept`.
            Some(b'N') if self.cfg.non_finite == NonFiniteLiteralPolicy::Accept => {
                self.lit(b"NaN")?;
                Ok(Json::Number(Num::Float(f64::NAN)))
            }
            Some(b'I') if self.cfg.non_finite == NonFiniteLiteralPolicy::Accept => {
                self.lit(b"Infinity")?;
                Ok(Json::Number(Num::Float(f64::INFINITY)))
            }
            Some(b'-')
                if self.cfg.non_finite == NonFiniteLiteralPolicy::Accept
                    && self.b[self.i + 1..].starts_with(b"Infinity") =>
            {
                self.i += 1;
                self.lit(b"Infinity")?;
                Ok(Json::Number(Num::Float(f64::NEG_INFINITY)))
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
        let raw = &self.b[self.i..self.i + 4];
        // RFC 8259 §7: `\u` is followed by exactly `4HEXDIG`, no sign.
        // `u16::from_str_radix` accepts a leading `+` (and would accept `-`
        // if the target type allowed negatives), which would let
        // `\u+041` parse as U+0041 — input every real decoder rejects as a
        // syntax error.
        if !raw.iter().all(u8::is_ascii_hexdigit) {
            return Err(self.syntax("bad \\u escape"));
        }
        let s = std::str::from_utf8(raw).map_err(|_| self.syntax("bad \\u escape"))?;
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
                let second = self.hex4()?;
                if (0xDC00..0xE000).contains(&second) {
                    // A well-formed pair can still encode a noncharacter:
                    // 􏿿 is U+10FFFF.
                    let cp = 0x10000 + (((hi as u32) - 0xD800) << 10) + ((second as u32) - 0xDC00);
                    self.reject_noncharacter(cp, at)?;
                    out.push(hi);
                    out.push(second);
                    return Ok(());
                }
                // `second` is a `\u` escape, but not a valid low surrogate.
                // Every policy except Ruby's rewinds and treats `hi` as
                // lone. Fix round 1, C3: measured, Ruby does not — it pairs
                // regardless, masking both halves with 0x3FF with no range
                // validation on `second` at all. See
                // `SurrogatePolicy::RubyPairAnyEscape`'s doc comment for the
                // measured evidence (`"\ud800\udbff"` -> U+103FF, etc).
                if self.cfg.surrogates == SurrogatePolicy::RubyPairAnyEscape {
                    let lo = 0xDC00 + (second & 0x03FF);
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
            // Fix round 1, C3: measured asymmetry. `cp` in 0xD800..0xDC00
            // only reaches `lone` when no `\u` escape followed it at all
            // (`unicode_escape` handles the paired-with-any-escape case
            // itself before ever calling `lone`), and Ruby rejects that —
            // `incomplete surrogate pair`. `cp` in 0xDC00..0xE000 is a lone
            // low surrogate, which Ruby accepts and retains verbatim.
            SurrogatePolicy::RubyPairAnyEscape => {
                if (0xD800..0xDC00).contains(&cp) {
                    Err(JsonError::LoneSurrogate { cp, at })
                } else {
                    out.push(cp as u16);
                    Ok(())
                }
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
        // `OverflowPolicy` is orthogonal to `NumberPolicy` (see its doc
        // comment) — Go and Elixir both reject a literal that overflows to
        // an infinity, but arrive via different `NumberPolicy` branches
        // below, so the check is one shared closure rather than duplicated
        // in each.
        let overflow_checked = |f: f64| -> Result<f64, JsonError> {
            if self.cfg.overflow == OverflowPolicy::Reject && !f.is_finite() {
                Err(JsonError::NumberOverflowsFloat64 {
                    literal: lit.into(),
                    at,
                })
            } else {
                Ok(f)
            }
        };
        match self.cfg.numbers {
            NumberPolicy::Ieee754Double => {
                Ok(Json::Number(Num::Float(overflow_checked(as_f64()?)?)))
            }

            NumberPolicy::ArbitraryPrecision => {
                if fractional {
                    return Ok(Json::Number(Num::Float(overflow_checked(as_f64()?)?)));
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

        // The identity the duplicate check uses is the *decoded* key, not
        // the source spelling: `"a"` and `"\u0061"` are two spellings of the
        // same key and must still collide. `DUP` uses byte-identical
        // spellings on both sides and so pins nothing about this; this is
        // RFC 8785 §3.1's confusable-key case.
        let escaped = "{\"a\":1,\"\\u0061\":2}";
        let err2 = parse_strict(escaped).unwrap_err();
        assert!(matches!(err2, JsonError::DuplicateKey { .. }), "got {err2}");
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

        // RFC 7493 §2.1 forbids an unpaired surrogate in *either* direction.
        // The cases above only exercise a lone high surrogate; a lone low
        // surrogate takes a separate branch in `unicode_escape` and must be
        // rejected by strict mode too.
        let lo_src = r#"{"a":"\udc00"}"#;
        assert!(matches!(
            parse(lo_src, Config::strict()).unwrap_err(),
            JsonError::LoneSurrogate { cp: 0xDC00, .. }
        ));
    }

    #[test]
    fn a_well_formed_surrogate_pair_survives_every_policy() {
        // The raw emoji takes the direct-UTF-8 branch in `string()` and
        // never enters `unicode_escape` at all. The escaped spelling is a
        // separate code path — the paired-surrogate branch — and needs its
        // own coverage, or a mutation there (e.g. the lookahead check that
        // confirms the second half is really a low surrogate) can pass
        // every existing test while breaking that branch outright.
        let raw = "{\"a\":\"\u{1F600}\"}";
        let escaped = "{\"a\":\"\\ud83d\\ude00\"}";
        for src in [raw, escaped] {
            for cfg in [
                Config::strict(),
                Config::go_encoding_json(),
                Config::node_json_parse(),
                // Ruby's pairing logic is genuinely different code (see
                // `SurrogatePolicy::RubyPairAnyEscape`), so a *bona fide*
                // well-formed pair needs to be pinned there too, or that
                // branch could regress and only the escape-masking tests
                // below would ever exercise `unicode_escape` for Ruby.
                Config::ruby_json(),
            ] {
                let j = parse(src, cfg).unwrap();
                assert_eq!(
                    j.get("a"),
                    Some(&Json::String(vec![0xD83D, 0xDE00])),
                    "{src} {cfg:?}"
                );
            }
        }
    }

    #[test]
    fn a_high_surrogate_followed_by_an_unrelated_escape_keeps_both() {
        // The second escape here is a `u`-escape, so the lookahead in
        // `unicode_escape` starts speculatively decoding it as a candidate
        // low surrogate — but it decodes to a value outside the
        // low-surrogate range, so the parser must rewind to before that
        // escape and re-emit it as its own character, not swallow it while
        // discovering the pairing failed. A silently dropped character is
        // exactly the failure class this crate exists to expose.
        let src = "{\"a\":\"\\ud800\\u0041\"}";
        let j = parse(src, Config::node_json_parse()).unwrap();
        assert_eq!(j.get("a"), Some(&Json::String(vec![0xD800, 0x0041])));
    }

    #[test]
    fn ruby_accepts_a_lone_low_surrogate_but_rejects_a_lone_high_one() {
        // Fix round 1, C3: measured against the real `ruby` binary (json
        // gem 2.1.0 on Ruby 2.6.10). Ruby's surrogate handling is
        // genuinely asymmetric between the two bands, unlike every other
        // config's uniform Reject/Replace/Retain.
        let hi_src = r#"{"a":"\ud800"}"#;
        assert!(
            matches!(
                parse(hi_src, Config::ruby_json()).unwrap_err(),
                JsonError::LoneSurrogate { cp: 0xD800, .. }
            ),
            "a lone high surrogate is rejected -- `incomplete surrogate pair`, measured"
        );

        let lo_src = r#"{"a":"\udc00"}"#;
        let v = parse(lo_src, Config::ruby_json()).unwrap();
        assert_eq!(
            v.get("a"),
            Some(&Json::String(vec![0xDC00])),
            "a lone low surrogate is accepted and retained verbatim -- measured as \
             the WTF-8-ish bytes `ed b0 80`, i.e. this code unit once rendered"
        );
    }

    #[test]
    fn ruby_pairs_a_high_surrogate_with_any_escape_but_not_a_raw_character() {
        // Fix round 1, C3: measured. Node keeps a high-surrogate escape
        // followed by an escape naming plain U+0041 as two separate units
        // (see `a_high_surrogate_followed_by_an_unrelated_escape_keeps_both`
        // above) because 0x0041 is not a valid low surrogate. Ruby instead
        // combines the two regardless of validity, masking both halves
        // with `0x3FF` -- the same source below parses to U+10041 under
        // Ruby, and the character the escape named is never emitted on its
        // own.
        let src = "{\"a\":\"\\ud800\\u0041\"}";
        let v = parse(src, Config::ruby_json()).unwrap();
        assert_eq!(
            v.get("a"),
            Some(&Json::String(vec![0xD800, 0xDC41])),
            "U+10041, not two separate units the way Node keeps it"
        );

        // The second escape need not even be a low surrogate -- a second
        // *high* surrogate escape is paired by the identical formula.
        let src2 = "{\"a\":\"\\ud800\\udbff\"}";
        let v2 = parse(src2, Config::ruby_json()).unwrap();
        assert_eq!(
            v2.get("a"),
            Some(&Json::String(vec![0xD800, 0xDFFF])),
            "U+103FF, from masking 0xDBFF with 0x3FF the same as any other escape"
        );

        // But a high surrogate followed by a raw, unescaped character
        // (rather than a second `\u` escape) is not paired at all -- it is
        // rejected, the same as a lone high surrogate with nothing
        // following. Measured directly; an earlier draft of this
        // correction wrongly assumed a raw character paired too.
        let raw_src = r#"{"a":"\ud800A"}"#;
        assert!(
            matches!(
                parse(raw_src, Config::ruby_json()).unwrap_err(),
                JsonError::LoneSurrogate { cp: 0xD800, .. }
            ),
            "a raw character does not pair -- measured, only a second \\u escape does"
        );
    }

    #[test]
    fn python_accepts_the_non_standard_nan_and_infinity_tokens() {
        // Fix round 1, C4: measured against the real `python3` binary.
        // `json.loads`'s `allow_nan` defaults to true, so these bare
        // (non-RFC-8259) tokens are accepted -- the only one of the four
        // modelled runtimes that does.
        let nan = parse(r#"{"n":NaN}"#, Config::python_json()).unwrap();
        let Some(Json::Number(Num::Float(f))) = nan.get("n") else {
            panic!("expected a float")
        };
        assert!(f.is_nan());

        assert_eq!(
            parse(r#"{"n":Infinity}"#, Config::python_json())
                .unwrap()
                .get("n"),
            Some(&Json::Number(Num::Float(f64::INFINITY)))
        );
        assert_eq!(
            parse(r#"{"n":-Infinity}"#, Config::python_json())
                .unwrap()
                .get("n"),
            Some(&Json::Number(Num::Float(f64::NEG_INFINITY)))
        );

        // Every other config rejects all three -- these are not JSON
        // number literals under RFC 8259 section 6.
        for cfg in [
            Config::strict(),
            Config::go_encoding_json(),
            Config::node_json_parse(),
            Config::ruby_json(),
            Config::elixir_otp_json(),
        ] {
            for bad in [r#"{"n":NaN}"#, r#"{"n":Infinity}"#, r#"{"n":-Infinity}"#] {
                assert!(parse(bad, cfg).is_err(), "{cfg:?} must reject {bad:?}");
            }
        }
    }

    #[test]
    fn elixir_rejects_overflow_but_keeps_arbitrary_precision_integers() {
        // Fix round 1, C6: measured on GCP, results/elixir-measurement.txt.
        // `Config::elixir_otp_json()` combines `ArbitraryPrecision` (exact
        // integers survive, unlike Go) with `OverflowPolicy::Reject` (an
        // overflowing literal errors, unlike Python and Ruby) -- a
        // combination no single `NumberPolicy` variant expresses alone,
        // which is why overflow is its own orthogonal knob.
        assert!(
            matches!(
                parse(r#"{"n":1e400}"#, Config::elixir_otp_json()).unwrap_err(),
                JsonError::NumberOverflowsFloat64 { .. }
            ),
            "real :json rejects 1e400 with {{:unexpected_sequence, \"1.0e400\"}}"
        );
        assert_eq!(
            parse(r#"{"n":9007199254740993}"#, Config::elixir_otp_json())
                .unwrap()
                .get("n"),
            Some(&Json::Number(Num::Int(9_007_199_254_740_993))),
            "integers stay exact, measured"
        );

        // Negative zero and underflow are both accepted silently, also
        // measured, and were already correct before this fix round --
        // pinned here so a future change to overflow handling cannot
        // regress them unnoticed.
        let neg_zero = parse(r#"{"n":-0.0}"#, Config::elixir_otp_json()).unwrap();
        let Some(Json::Number(Num::Float(f))) = neg_zero.get("n") else {
            panic!("expected a float")
        };
        assert_eq!(*f, 0.0);
        assert!(
            f.is_sign_negative(),
            "sign preserved, measured F:8000000000000000"
        );

        let underflow = parse(r#"{"n":1e-400}"#, Config::elixir_otp_json()).unwrap();
        assert_eq!(
            underflow.get("n"),
            Some(&Json::Number(Num::Float(0.0))),
            "underflows silently rather than erroring, measured"
        );
    }

    #[test]
    fn noncharacters_are_rejected_by_strict_and_accepted_by_a_lenient_config() {
        // RFC 7493 §2.1 forbids noncharacters (U+FDD0..=U+FDEF, and the
        // last two code points of every plane), whether the source spells
        // one as a `\u` escape or as raw UTF-8, whether it comes from a
        // single escape or a well-formed surrogate pair, and whether it
        // appears as a key or a value. `NoncharacterPolicy` has two
        // settings and a lenient config must accept every one of these.

        // Escaped spellings, single-unit noncharacters.
        for esc in ["\\ufdd0", "\\ufdef", "\\ufffe", "\\uffff"] {
            let src = format!("{{\"a\":\"{esc}\"}}");
            assert!(
                matches!(
                    parse_strict(&src).unwrap_err(),
                    JsonError::NonCharacter { .. }
                ),
                "expected NonCharacter for {src:?}"
            );
            assert!(
                parse(&src, Config::node_json_parse()).is_ok(),
                "lenient config must accept {src:?}"
            );
        }

        // Raw UTF-8 spellings, exercising the direct (non-escaped) code
        // path in `string()` rather than `unicode_escape`.
        for cp in ['\u{FDD0}', '\u{FFFE}', '\u{1FFFE}'] {
            let src = format!("{{\"a\":\"{cp}\"}}");
            assert!(
                matches!(
                    parse_strict(&src).unwrap_err(),
                    JsonError::NonCharacter { .. }
                ),
                "expected NonCharacter for raw U+{:04X}",
                cp as u32
            );
            assert!(
                parse(&src, Config::node_json_parse()).is_ok(),
                "lenient config must accept raw U+{:04X}",
                cp as u32
            );
        }

        // Surrogate-pair spellings that decode to a noncharacter.
        for (esc, cp) in [
            ("\\udbff\\udfff", 0x10_FFFFu32),
            ("\\ud83f\\udffe", 0x1_FFFEu32),
        ] {
            let src = format!("{{\"a\":\"{esc}\"}}");
            assert!(
                matches!(
                    parse_strict(&src).unwrap_err(),
                    JsonError::NonCharacter { cp: found, .. } if found == cp
                ),
                "expected NonCharacter U+{cp:04X} for {src:?}"
            );
            assert!(
                parse(&src, Config::node_json_parse()).is_ok(),
                "lenient config must accept {src:?}"
            );
        }

        // In a key, not only a value.
        let key_src = "{\"\\ufdd0\":1}";
        assert!(matches!(
            parse_strict(key_src).unwrap_err(),
            JsonError::NonCharacter { .. }
        ));
        assert!(parse(key_src, Config::node_json_parse()).is_ok());

        // Negative controls, one below and one above the FDD0..=FDEF band:
        // both must be accepted even by strict mode, or the rule above could
        // be "reject anything near that range" and the tests would not
        // notice.
        for esc in ["\\ufdcf", "\\ufdf0"] {
            let src = format!("{{\"a\":\"{esc}\"}}");
            assert!(parse_strict(&src).is_ok(), "expected accept for {src:?}");
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

        // A fractional or exponential *spelling* of the same out-of-range
        // integer must not slip past strict mode just because it carries an
        // extra `.0` or `e15` — that would let one extra character defeat
        // the reference decoder this paper relies on.
        for spelling in ["9007199254740993.0", "9.007199254740993e15"] {
            let src = format!(r#"{{"n":{spelling}}}"#);
            assert!(
                matches!(
                    parse(&src, Config::strict()).unwrap_err(),
                    JsonError::NumberOutOfRange { .. }
                ),
                "expected NumberOutOfRange for {src:?}"
            );
        }
    }

    #[test]
    fn go_rejects_a_literal_that_overflows_a_double_but_node_does_not() {
        // Task 4 correction: measured against the real `go` and `node`
        // binaries. `strconv.ParseFloat` inside `encoding/json` treats an
        // overflow to infinity as `ErrRange` and `encoding/json.Unmarshal`
        // surfaces that as an error — `json: cannot unmarshal number 1e400
        // into Go value of type float64` — while `JSON.parse("1e400")` in
        // Node (and `json.loads` in Python, and `JSON.parse` in Ruby) all
        // silently return `Infinity`. Before this fix, `Config::go_encoding_json`
        // shared `NumberPolicy::Ieee754Double` with Node and so wrongly
        // predicted `Infinity` for Go here too.
        for src in [r#"{"n":1e400}"#, r#"{"n":-1e400}"#] {
            assert!(
                matches!(
                    parse(src, Config::go_encoding_json()).unwrap_err(),
                    JsonError::NumberOverflowsFloat64 { .. }
                ),
                "go must reject {src:?}"
            );
            assert!(
                parse(src, Config::node_json_parse())
                    .unwrap()
                    .get("n")
                    .is_some(),
                "node must accept {src:?}"
            );
        }

        // Right at the boundary: f64::MAX itself must still parse under
        // Go's stricter policy, or the rule above could be "reject any
        // large number" and this test would not notice.
        let max = format!(r#"{{"n":{}}}"#, f64::MAX);
        assert_eq!(
            parse(&max, Config::go_encoding_json()).unwrap().get("n"),
            Some(&Json::Number(Num::Float(f64::MAX))),
            "f64::MAX itself is finite and must still parse"
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
        let arr = format!("{}{}", "[".repeat(100_000), "]".repeat(100_000));
        assert!(matches!(
            parse_strict(&arr).unwrap_err(),
            JsonError::TooDeep { .. }
        ));
        // Arrays and objects each have their own `enter`/`depth -= 1`
        // bookkeeping; covering only one form leaves the other free to
        // recurse straight into a stack overflow (SIGABRT, not a `Result`)
        // on hostile input, which is exactly the failure this crate exists
        // to turn into a diagnosable error.
        let obj = r#"{"a":"#.repeat(100_000);
        assert!(matches!(
            parse_strict(&obj).unwrap_err(),
            JsonError::TooDeep { .. }
        ));
    }

    #[test]
    fn max_depth_boundary_is_exactly_128() {
        // Nothing else pins the *value* of `MAX_DEPTH`; a document one level
        // under the limit must parse, and one level over must not, for both
        // container kinds.
        assert_eq!(MAX_DEPTH, 128);

        let arr_at_limit = format!("{}{}", "[".repeat(128), "]".repeat(128));
        assert!(
            parse_strict(&arr_at_limit).is_ok(),
            "an array nested 128 deep must parse"
        );
        let arr_over_limit = format!("{}{}", "[".repeat(129), "]".repeat(129));
        assert!(matches!(
            parse_strict(&arr_over_limit).unwrap_err(),
            JsonError::TooDeep { .. }
        ));

        // 127 repeats of the opening wrapper plus one closed empty object
        // nests to exactly depth 128; 128 repeats nests to 129.
        let obj_at_limit = format!("{}{}{}", r#"{"a":"#.repeat(127), "{}", "}".repeat(127));
        assert!(
            parse_strict(&obj_at_limit).is_ok(),
            "an object nested 128 deep must parse"
        );
        let obj_over_limit = format!("{}{}{}", r#"{"a":"#.repeat(128), "{}", "}".repeat(128));
        assert!(matches!(
            parse_strict(&obj_over_limit).unwrap_err(),
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
            // RFC 8259 §7: `\u` takes exactly `4HEXDIG`, no sign and no
            // stray whitespace in place of a digit.
            r#"{"a":"\u+041"}"#,
            r#"{"a":"\u 041"}"#,
        ] {
            assert!(parse_strict(bad).is_err(), "expected an error for {bad:?}");
        }
    }
}
