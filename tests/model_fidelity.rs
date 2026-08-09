//! The modelled decoders in `decoder::in_crate` are claims about how other
//! people's parsers behave. This file falsifies each claim against the real
//! runtime whenever that runtime is installed.
//!
//! When a model and its runtime disagree, **the model is wrong** — fix
//! `Config::<runtime>()` in `src/json.rs`. Do not relax the test, and do not
//! add an exception: the whole value of the model is that it was checked.

use transit::corpus;
use transit::decoder::in_crate;
use transit::external::{discover, missing_runtimes};

fn model_for(runtime: &str) -> &'static str {
    match runtime {
        "go" => "model:go-encoding-json",
        "node" => "model:node-json-parse",
        "python" => "model:python-json",
        "ruby" => "model:ruby-json",
        other => panic!("no model declared for runtime {other}"),
    }
}

/// The four runtimes this crate models, named directly rather than derived
/// from `external::EXPECTED.len()`. `EXPECTED` and this list are meant to
/// agree, but deriving the expected count from `EXPECTED` itself makes the
/// check circular: if an edit ever drops an entry from `EXPECTED` (e.g. the
/// `ruby` `Expected` in `src/external.rs`), `discover()`'s result shrinks in
/// lockstep with the yardstick measuring it, and `checked ==
/// EXPECTED.len() * cases().len()` stays true at a smaller number without
/// ever naming what went missing. Fixing that list here, independent of
/// `EXPECTED`, is what actually catches that mutation instead of just
/// tightening `checked > 0`.
const RUNTIMES: [&str; 4] = ["go", "node", "python", "ruby"];

#[test]
fn every_model_agrees_with_its_runtime_on_the_whole_corpus() {
    let discovered = discover();

    // A test that silently checks fewer models than it claims to is worse
    // than no test: `checked > 0` alone only guards the *empty* set, so a
    // host (or a source edit) missing one runtime still reports "every
    // model agrees" while one model was never run against reality at all --
    // the same unbacked-claim shape `ModelVerification::RuntimeInstalled`'s
    // doc comment (`decoder.rs`) warns a hard-coded label would make. Name
    // exactly which of `RUNTIMES` did not show up in `discover()`'s result.
    let found: Vec<&str> = discovered.iter().map(|e| e.runtime.as_str()).collect();
    let absent: Vec<&str> = RUNTIMES
        .iter()
        .copied()
        .filter(|r| !found.contains(r))
        .collect();
    assert!(
        absent.is_empty(),
        "the following runtimes were expected but not available, so their models were \
         never checked against reality: {}",
        absent.join(", ")
    );
    // `missing_runtimes()` is `external`'s own account of the same fact,
    // read from `EXPECTED` rather than from `RUNTIMES` above. The two are
    // independent sources and should agree; if they don't, `EXPECTED` and
    // `RUNTIMES` have drifted apart from each other, which is itself worth
    // failing loudly on rather than silently trusting either one.
    let missing = missing_runtimes();
    assert!(
        missing.is_empty(),
        "missing_runtimes() reports runtimes EXPECTED could not prepare: {}",
        missing
            .iter()
            .map(|m| m.runtime)
            .collect::<Vec<_>>()
            .join(", ")
    );

    let models = in_crate();
    let mut checked = 0usize;

    for ext in &discovered {
        let model = models
            .iter()
            .find(|m| m.id == model_for(&ext.runtime))
            .expect("a declared model");

        for case in corpus::cases() {
            let got = ext.observe(&case.payload).expect("the runtime runs");
            let want = model.observe(&case.payload);
            assert_eq!(
                got.observation, want.observation,
                "case `{}`: {} observed {:?} ({:?}) but the model predicted {:?}",
                case.name, ext.id, got.observation, got.detail, want.observation
            );
            checked += 1;
        }
    }

    // Pin the exact count on top of the two presence checks above, so a
    // future change that makes `discover()` return duplicate or partial
    // entries some other way still gets caught here.
    assert_eq!(
        checked,
        RUNTIMES.len() * corpus::cases().len(),
        "expected every one of RUNTIMES to be checked against every corpus case"
    );
}
