//! The five acceptance tests from the design. Each is written to fail if the
//! claim the paper makes stops being true, not merely if the code stops
//! compiling.

use transit::differential;

/// Acceptance test 1: `differential` detects the duplicate-key divergence
/// between two decoders present on the host.
///
/// The canonical pair in the literature is Go's last-key-wins against
/// Elixir's first-key-wins. **Elixir is not installed here**, so the pair
/// asserted is `strict-ijson` (which refuses the payload outright, as RFC
/// 8785 requires) against `serde_json` (which accepts it and keeps the last
/// key). Both are genuinely present and independently implemented. The
/// first-key-wins side of the canonical pair is additionally exercised
/// through the Elixir *model* (`model:elixir-otp-json`), which the report
/// labels `Unverified`: first-key-wins on OTP 27 has since been *measured*
/// directly (`results/elixir-measurement.txt`, run on GCP, elixir 1.17.3 /
/// OTP 27), but no Elixir runtime exists on this machine, so that measurement
/// is a fact about a different host, not about this run. The local decoder
/// stays a model regardless of what was measured elsewhere, and its
/// provenance says so.
#[test]
fn differential_detects_the_duplicate_key_divergence() {
    let r = differential::run_payload(r#"{"to":"acct-1","amount":100,"to":"acct-9"}"#);
    let d = r.divergence.expect("this payload must divide the decoders");

    let strict = d.class_of("strict-ijson").expect("strict-ijson took part");
    let serde = d.class_of("serde_json").expect("serde_json took part");
    assert_ne!(strict, serde, "two decoders present on every host disagree");

    // And the disagreement is about the recipient, not about some incidental
    // formatting difference.
    assert!(
        serde.contains(&hex_units("acct-9")),
        "serde_json resolved the duplicate to the last key: {serde}"
    );

    // The two facts above are both true of decoders written elsewhere, so
    // they would survive this crate's own duplicate policies being swapped or
    // deleted. Pin those directly: first-key-wins and last-key-wins must land
    // in different classes, and the first-key class must hold the *first*
    // recipient. (`model:elixir-otp-json` is a model, not a measurement — no
    // Elixir runtime exists here, and the report labels it `Unverified`.)
    let first = d
        .class_of("model:elixir-otp-json")
        .expect("the first-key model took part");
    let last = d
        .class_of("model:go-encoding-json")
        .expect("the last-key model took part");
    assert_ne!(first, last, "the two duplicate policies must disagree");
    assert!(
        first.contains(&hex_units("acct-1")),
        "first-key-wins authorizes the legitimate recipient: {first}"
    );
    assert!(
        last.contains(&hex_units("acct-9")),
        "last-key-wins pays the attacker: {last}"
    );

    // Confirm the Elixir model's own provenance still says what the doc
    // comment above claims: measured elsewhere, unverified here. A crate
    // edit that quietly promoted it (e.g. by hard-coding `RuntimeInstalled`)
    // would be exactly the false-provenance failure this tool exists to
    // catch, and it would not show up in any assertion above.
    let elixir_report = r
        .reports
        .iter()
        .find(|rep| rep.id == "model:elixir-otp-json")
        .expect("the elixir model reported");
    assert!(
        matches!(
            &elixir_report.provenance,
            transit::decoder::Provenance::Modelled {
                verification: transit::decoder::ModelVerification::Unverified { .. },
                ..
            }
        ),
        "the elixir model must stay Unverified on this host: {:?}",
        elixir_report.provenance
    );

    // Any language runtime that is installed joins in; none is required.
    for id in ["go", "node", "python", "ruby"] {
        if let Some(cls) = d.class_of(id) {
            assert!(!cls.is_empty(), "{id} reported an empty observation");
        }
    }
}

/// The observation format renders strings as UTF-16 code units, so an
/// expected value has to be spelled the same way.
fn hex_units(s: &str) -> String {
    let units: Vec<String> = s.encode_utf16().map(|c| format!("{c:04x}")).collect();
    units.join(",")
}
