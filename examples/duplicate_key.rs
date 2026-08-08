//! The duplicate-key parser differential, end to end.
//!
//! One wire payload. Two decoders that both accept it. Two different
//! recipients. A signature that verifies for whichever one the verifier
//! happened to use.
//!
//! Run with: `cargo run --example duplicate_key`

use transit::jcs::{canonicalize, digest};
use transit::json::{parse, parse_strict, Config, Json};

fn recipient(v: &Json) -> String {
    v.get("to")
        .and_then(Json::as_string)
        .unwrap_or_else(|| "<none>".into())
}

fn main() {
    // RFC 8785 prohibits duplicate object keys. Production decoders disagree
    // about what to do anyway, and none of them refuses.
    let wire = r#"{"to":"acct-legit","amount":100,"to":"acct-attacker"}"#;

    println!("wire payload (one byte sequence, signed once):");
    println!("  {wire}\n");

    // The policy engine retains the first binding.
    let policy = parse(wire, Config::elixir_otp_json()).expect("accepted");
    // The backend keeps the last.
    let backend = parse(wire, Config::go_encoding_json()).expect("accepted");

    println!(
        "policy engine  (first-key-wins) authorizes a transfer to: {}",
        recipient(&policy)
    );
    println!(
        "backend        (last-key-wins)  executes  a transfer to: {}\n",
        recipient(&backend)
    );

    println!("canonical form each side believes it signed:");
    println!(
        "  policy   {}",
        canonicalize(&policy).expect("canonicalizes")
    );
    println!(
        "  backend  {}\n",
        canonicalize(&backend).expect("canonicalizes")
    );

    println!("...and therefore two different digests over the same wire bytes:");
    println!("  policy   {}", digest(&policy).expect("digests"));
    println!("  backend  {}\n", digest(&backend).expect("digests"));

    // Every step above is individually correct. The composition is the bug.
    match parse_strict(wire) {
        Ok(_) => println!("strict I-JSON ingestion: ACCEPTED — this should be unreachable"),
        Err(e) => println!("strict I-JSON ingestion refuses the payload outright:\n  {e}"),
    }
}
