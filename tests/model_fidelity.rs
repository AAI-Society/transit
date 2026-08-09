//! The modelled decoders in `decoder::in_crate` are claims about how other
//! people's parsers behave. This file falsifies each claim against the real
//! runtime whenever that runtime is installed.
//!
//! When a model and its runtime disagree, **the model is wrong** — fix
//! `Config::<runtime>()` in `src/json.rs`. Do not relax the test, and do not
//! add an exception: the whole value of the model is that it was checked.

use transit::corpus;
use transit::decoder::in_crate;
use transit::external::discover;

fn model_for(runtime: &str) -> &'static str {
    match runtime {
        "go" => "model:go-encoding-json",
        "node" => "model:node-json-parse",
        "python" => "model:python-json",
        "ruby" => "model:ruby-json",
        other => panic!("no model declared for runtime {other}"),
    }
}

#[test]
fn every_model_agrees_with_its_runtime_on_the_whole_corpus() {
    let models = in_crate();
    let mut checked = 0usize;

    for ext in discover() {
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

    // A test that silently checks nothing is worse than no test. If no
    // runtime is installed, say so out loud rather than passing.
    assert!(
        checked > 0,
        "no language runtime was found, so no model was verified; \
         install node, go, python or ruby to check them"
    );
}
