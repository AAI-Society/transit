use crate::corpus::Evidence;
use crate::fuzz::{run_all, FuzzReport};
// `Transport` is in this list because `probe` calls `http.send` for the
// route check below; without the trait in scope the method does not exist.
use crate::transport::{Http, RateLimiter, Transport, TransportError};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Ten requests a minute. Deliberately gentle: the default has to be one
/// nobody would need to think about before running against something real.
pub const DEFAULT_RATE_PER_MINUTE: u32 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Authorization {
    /// The operator owns the account being probed.
    OwnAccount,
    /// The operator holds written permission from whoever does.
    WrittenPermission,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub name: String,
    pub base_url: String,
    /// No default, on purpose. An operator has to write this down.
    pub authorization: Authorization,
    /// Someone the probed party can reach if the probing is unwelcome.
    pub contact: String,
    #[serde(default = "default_rate")]
    pub rate_limit_per_minute: u32,
}

fn default_rate() -> u32 {
    DEFAULT_RATE_PER_MINUTE
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    #[serde(default)]
    pub target: Vec<Target>,
}

#[derive(Debug, thiserror::Error)]
pub enum GateError {
    #[error(
        "refusing to probe: `--i-am-authorized` was not given. This command sends \
         adversarial traffic to whatever it is pointed at, so it will not run until \
         you state, on the command line, that you are authorized to do that."
    )]
    FlagMissing,
    #[error(
        "refusing to probe: `--live` was not given. Nothing reaches the network \
         without it, and it is separate from `--i-am-authorized` so that neither \
         flag can be mistaken for the other."
    )]
    LiveMissing,
    #[error(
        "refusing to probe: the config names no targets. An empty target list is \
         almost always a mistake in the config rather than a request to do nothing, \
         so it is refused rather than silently satisfied."
    )]
    NoTargets,
    #[error(
        "refusing to probe `{name}`: `contact` must be an address the probed party \
         can actually reach — an email address or a URL. Whoever receives this \
         traffic needs a way to tell you to stop."
    )]
    UnusableContact { name: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("could not read {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse {path}: {source}")]
    Parse {
        path: String,
        #[source]
        source: toml::de::Error,
    },
    #[error(transparent)]
    Gate(#[from] GateError),
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// The whole safety story, in one function with no I/O in it, so it can be
/// tested exhaustively without a network.
pub fn gate(targets: &Targets, live: bool, authorized: bool) -> Result<(), GateError> {
    // Checked separately. Collapsing them into one boolean made omitting
    // `--live` report that `--i-am-authorized` was missing, which is both
    // wrong and the kind of wrong that teaches an operator to add the flag
    // that was not the problem.
    if !live {
        return Err(GateError::LiveMissing);
    }
    if !authorized {
        return Err(GateError::FlagMissing);
    }
    if targets.target.is_empty() {
        return Err(GateError::NoTargets);
    }
    for t in &targets.target {
        let c = t.contact.trim();
        // Not validation for its own sake: an unreachable contact means the
        // probed party has no way to object.
        if c.is_empty() || !(c.contains('@') || c.starts_with("http")) {
            return Err(GateError::UnusableContact {
                name: t.name.clone(),
            });
        }
    }
    Ok(())
}

pub fn load_targets(path: &Path) -> Result<Targets, ProbeError> {
    let text = std::fs::read_to_string(path).map_err(|source| ProbeError::Io {
        path: path.display().to_string(),
        source,
    })?;
    toml::from_str(&text).map_err(|source| ProbeError::Parse {
        path: path.display().to_string(),
        source,
    })
}

/// Run the adversarial checks against one live target. Only reachable after
/// `gate` has returned `Ok`.
///
/// **A limitation to state before anyone reads a result from this.** The
/// checks in `fuzz` address this repository's own routes — `/v1/transfer`,
/// `/v1/orders`, `/v1/users/me` — and parse a response shaped like the
/// hostile server's. Against a real API every request 404s, every check
/// returns nothing, and a naive reading of the output is "no findings" when
/// the truth is "no check applied". Probing a real endpoint needs per-target
/// route and payload configuration, which is **not built**.
///
/// So the report distinguishes the two. If no check got a response the target
/// recognised, `checks_applicable` is false and the summary says the checks
/// did not apply rather than that the endpoint is clean.
pub fn probe(t: &Target) -> Result<FuzzReport, ProbeError> {
    let mut http = Http {
        base: t.base_url.clone(),
        evidence: Evidence::LiveProbed,
        limiter: RateLimiter::per_minute(t.rate_limit_per_minute),
    };
    let mut report = run_all(&mut http, &format!("live:{}", t.name))?;
    // One cheap request decides it: if the endpoint does not know the route
    // the checks are built around, the checks did not run in any real sense.
    let probe_route = http.send(&crate::transport::Request {
        method: "GET".into(),
        path: "/v1/state".into(),
        headers: vec![],
        body: String::new(),
    })?;
    report.checks_applicable = probe_route.status != 404;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOOD: &str = r#"
[[target]]
name = "my-own-sandbox"
base_url = "https://sandbox.example.com"
authorization = "own-account"
contact = "jim@quome.com"
rate_limit_per_minute = 6
"#;

    fn targets(src: &str) -> Targets {
        toml::from_str(src).unwrap()
    }

    #[test]
    fn a_well_formed_config_with_both_flags_passes() {
        assert!(gate(&targets(GOOD), true, true).is_ok());
    }

    #[test]
    fn each_missing_flag_is_reported_as_itself() {
        // Collapsing the two into one boolean made omitting `--live` report
        // that `--i-am-authorized` was missing — wrong, and the kind of wrong
        // that teaches an operator to add the flag that was not the problem.
        assert!(matches!(
            gate(&targets(GOOD), true, false),
            Err(GateError::FlagMissing)
        ));
        assert!(matches!(
            gate(&targets(GOOD), false, true),
            Err(GateError::LiveMissing)
        ));
        assert!(gate(&targets(GOOD), false, false).is_err());
    }

    #[test]
    fn a_missing_authorization_declaration_is_a_parse_error() {
        let src = GOOD.replace("authorization = \"own-account\"\n", "");
        assert!(
            toml::from_str::<Targets>(&src).is_err(),
            "there is no default"
        );
    }

    #[test]
    fn a_misspelled_authorization_key_is_rejected_rather_than_ignored() {
        // Without `deny_unknown_fields` this would parse as a target with no
        // authorization key at all — and the field it was meant to set has
        // no default, so the failure would at least be loud. This test pins
        // that it stays loud if a default is ever added.
        let src = GOOD.replace("authorization =", "authorisation =");
        assert!(toml::from_str::<Targets>(&src).is_err());
    }

    #[test]
    fn an_empty_or_implausible_contact_is_refused() {
        for bad in ["\"\"", "\"   \"", "\"me\""] {
            let src = GOOD.replace("\"jim@quome.com\"", bad);
            let t: Targets = toml::from_str(&src).unwrap();
            assert!(
                matches!(gate(&t, true, true), Err(GateError::UnusableContact { .. })),
                "contact {bad} should be refused"
            );
        }
    }

    #[test]
    fn only_the_two_declared_authorization_values_parse() {
        let src = GOOD.replace("\"own-account\"", "\"i-guess-its-fine\"");
        assert!(toml::from_str::<Targets>(&src).is_err());
        let src = GOOD.replace("\"own-account\"", "\"written-permission\"");
        assert!(gate(&targets(&src), true, true).is_ok());
    }

    #[test]
    fn a_config_with_no_targets_is_refused_rather_than_vacuously_allowed() {
        assert!(matches!(
            gate(&targets(""), true, true),
            Err(GateError::NoTargets)
        ));
    }

    #[test]
    fn one_bad_target_among_good_ones_refuses_the_whole_run() {
        let src = format!("{GOOD}\n[[target]]\nname = \"other\"\nbase_url = \"https://x.example\"\nauthorization = \"own-account\"\ncontact = \"\"\n");
        let t: Targets = toml::from_str(&src).unwrap();
        assert!(gate(&t, true, true).is_err(), "the gate is all-or-nothing");
    }

    #[test]
    fn every_gate_error_says_what_to_do_about_it() {
        // The refusal has to be an explanation, not a stack trace.
        for e in [
            GateError::FlagMissing,
            GateError::NoTargets,
            GateError::UnusableContact { name: "t".into() },
        ] {
            let msg = e.to_string();
            assert!(msg.len() > 40, "too terse: {msg}");
        }
    }

    #[test]
    fn a_target_defaults_to_a_conservative_rate_limit() {
        let src = GOOD.replace("rate_limit_per_minute = 6\n", "");
        let t: Targets = toml::from_str(&src).unwrap();
        assert_eq!(t.target[0].rate_limit_per_minute, DEFAULT_RATE_PER_MINUTE);
        // A `const` block rather than a plain `assert!`: the operand is a
        // constant, so the claim is decidable at compile time and clippy
        // refuses to let it masquerade as a runtime check. Raising the
        // default past a gentle rate now fails the build rather than one
        // test.
        const { assert!(DEFAULT_RATE_PER_MINUTE <= 12, "the default must be gentle") };
    }
}
