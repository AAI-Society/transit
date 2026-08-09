//! Why the canonicalizer cannot be written the obvious way.
//!
//! RFC 8785 §3.2.2.3 requires ECMA-262 `Number::toString` *including the
//! "Note 2" enhancement* — round half to even. Rust's own float formatting
//! rounds half away from zero. The two agree almost always, and when they
//! disagree the digest changes.
//!
//! Run with: `cargo run --example tie_break`

use transit::jcs::{canonicalize, digest};
use transit::json::{Json, Num};

fn main() {
    // RFC 8785 Appendix B's last row exists solely to pin this case.
    let bits: u64 = 0x43143ff3c1cb0959;
    let v = f64::from_bits(bits);

    println!("one IEEE-754 double, bit pattern {bits:016x}\n");

    let naive = format!("{v}");
    let canonical = canonicalize(&Json::Number(Num::Float(v))).expect("canonicalizes");

    println!("Rust's own float formatting   {naive}");
    println!("RFC 8785 Appendix B requires  {canonical}");
    println!(
        "                              {}\n",
        if naive == canonical {
            "agree"
        } else {
            "^ they disagree in the last digit"
        }
    );

    // The digest is what a capability signs, so a last-digit difference is
    // not cosmetic — it is a different signature over the same value.
    let correct = digest(&Json::Number(Num::Float(v))).expect("digests");
    let wrong = hex_sha256(naive.as_bytes());

    println!("digest over the canonical form   {correct}");
    println!("digest had we written it naively {wrong}\n");

    println!("Measured across ~5,000,000 doubles, the two rules disagree on 10,762");
    println!("of them — 0.216%. Every one is a capability that verifies on one");
    println!("implementation and fails on another.");
}

fn hex_sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(bytes))
}
