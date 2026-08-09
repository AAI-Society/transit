use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "transit",
    version,
    about = "Test whether an endpoint satisfies the effect-binding conditions"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run a payload through every available decoder and report disagreement.
    /// Touches no network.
    Differential {
        /// A file holding one JSON payload. Omit to run the built-in corpus.
        #[arg(long)]
        payload: Option<PathBuf>,
        #[arg(long, default_value = "text")]
        format: Format,
        /// Exit 1 when any decoder disagrees. Off by default, because a
        /// divergence is the expected finding rather than an error.
        #[arg(long)]
        fail_on_divergence: bool,
    },
    /// Run the deliberately hostile endpoint. Local only.
    ServeHostile {
        #[arg(long, default_value = "all-hostile")]
        scenario: String,
        #[arg(long, default_value = "127.0.0.1:8787")]
        addr: String,
    },
    /// Run the adversarial checks against a target. Defaults to the hostile
    /// endpoint in this process, which needs no server and no credentials.
    Fuzz {
        /// A base URL. Omit to use the in-process hostile endpoint.
        #[arg(long)]
        target: Option<String>,
        #[arg(long, default_value = "all-hostile")]
        scenario: String,
        #[arg(long, default_value = "text")]
        format: Format,
    },
    /// Probe live endpoints. Gated: see `examples/targets.example.toml`.
    Probe {
        /// Required. Present so that no accidental invocation reaches the
        /// network.
        #[arg(long)]
        live: bool,
        #[arg(long)]
        config: PathBuf,
        /// Required. The gate refuses without it and explains why.
        #[arg(long)]
        i_am_authorized: bool,
        #[arg(long, default_value = "text")]
        format: Format,
    },
    /// Classify an OpenAPI operation against C1-C4.
    Classify {
        #[arg(long)]
        spec: PathBuf,
        #[arg(long, default_value = "text")]
        format: Format,
    },
    /// Run the enforcing reverse proxy in front of an upstream API.
    Guard {
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Clone, Copy, PartialEq, clap::ValueEnum)]
enum Format {
    Text,
    Json,
    /// A `tabular` environment for the paper to `\input`. Only `survey` and
    /// `classify` emit it; every other subcommand treats it as `Text`.
    /// Declared here rather than in a second enum so that
    /// `scripts/regen-results.sh` cannot ask for a value clap rejects.
    Tex,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        // `{e:#}` here, not `{e}`: anyhow's alternate form prints the chain,
        // and the library errors do not interpolate their own source.
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Differential {
            payload,
            format,
            fail_on_divergence,
        } => {
            let diverged = match payload {
                Some(p) => {
                    let src = std::fs::read_to_string(&p)
                        .with_context(|| format!("reading {}", p.display()))?;
                    let r = transit::differential::run_payload(&src);
                    // Fix round 1, I6: `--payload` used to run a materially
                    // weaker differential on a host missing runtimes with
                    // nothing in either format saying so — `run_payload`
                    // returns a lone `CaseReport`, which has no field for
                    // it, so this is fetched separately rather than added
                    // there.
                    let missing = transit::differential::missing();
                    if format == Format::Json {
                        let mut value = serde_json::to_value(&r)?;
                        if let serde_json::Value::Object(map) = &mut value {
                            map.insert("missing".to_string(), serde_json::to_value(&missing)?);
                        }
                        println!("{}", serde_json::to_string_pretty(&value)?);
                    } else {
                        for m in &missing {
                            println!("not installed, so not measured: {m}");
                        }
                        print_case(&r, format)?;
                    }
                    r.divergence.is_some()
                }
                None => {
                    let r = transit::differential::run();
                    if format == Format::Json {
                        println!("{}", serde_json::to_string_pretty(&r)?);
                    } else {
                        for m in &r.missing {
                            println!("not installed, so not measured: {m}");
                        }
                        for c in &r.cases {
                            print_case(c, format)?;
                        }
                    }
                    r.cases.iter().any(|c| c.divergence.is_some())
                }
            };
            Ok(if diverged && fail_on_divergence {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        Cmd::ServeHostile { scenario, addr } => {
            let modes = transit::hostile::FailureModes::named(&scenario)?;
            transit::hostile::serve(&addr, modes)?;
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Fuzz {
            target,
            scenario,
            format,
        } => {
            let modes = transit::hostile::FailureModes::named(&scenario)?;
            let report = match target {
                None => {
                    let mut t = transit::transport::InProcess::new(modes);
                    transit::fuzz::run_all(&mut t, &scenario)?
                }
                Some(base) => {
                    // `fuzz` has no authorization gate, and `run_all`
                    // deliberately executes a non-idempotent operation twice.
                    // Pointing it at a stranger would be both ungated and
                    // mislabelled, since its findings are tagged
                    // `HostileServer`. Refuse anything but loopback.
                    if !transit::transport::is_loopback(&base) {
                        eprintln!(
                            "refusing: `fuzz --target` is ungated and sends adversarial \
                             traffic, including a deliberate double execution, so it may \
                             only point at a hostile endpoint you are running locally. \
                             `{base}` is not loopback.\n\nTo test something real, use \
                             `transit probe`, which requires a written authorization \
                             declaration, a contact address, and --i-am-authorized."
                        );
                        return Ok(ExitCode::from(2));
                    }
                    let mut t = transit::transport::Http {
                        base,
                        evidence: transit::corpus::Evidence::HostileServer,
                        limiter: transit::transport::RateLimiter::per_minute(600),
                    };
                    transit::fuzz::run_all(&mut t, &scenario)?
                }
            };
            if format == Format::Json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("target:   {}", report.target);
                println!(
                    "evidence: {:?} — {}",
                    report.evidence,
                    report.evidence.caveat()
                );
                println!("checks:   {}", report.checks_run.join(", "));
                for f in &report.findings {
                    println!("\n{} [{}]", f.title, f.condition.title());
                    println!("  policy saw:   {}", f.policy_saw);
                    println!("  endpoint did: {}", f.endpoint_did);
                }
                if report.findings.is_empty() {
                    println!("\nno findings");
                }
                // The residual is the whole reason `FuzzReport` carries a
                // second list. Printing findings alone would let a conforming
                // endpoint render as "no findings" over the structural half
                // of C3, which is the claim this tool exists to support, not
                // one it may quietly drop in its default output format.
                for f in &report.residual {
                    println!("\nresidual — no endpoint change closes this");
                    println!("{} [{}]", f.title, f.condition.title());
                    println!("  policy saw:   {}", f.policy_saw);
                    println!("  endpoint did: {}", f.endpoint_did);
                }
            }
            Ok(if report.findings.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        Cmd::Probe {
            live,
            config,
            i_am_authorized,
            format,
        } => {
            let targets = transit::probe::load_targets(&config)?;
            if let Err(e) = transit::probe::gate(&targets, live, i_am_authorized) {
                eprintln!("{e}");
                // Exit code 3 is reserved for this and nothing else, so a
                // caller can distinguish "refused" from "found something".
                return Ok(ExitCode::from(3));
            }
            let mut any = false;
            for t in &targets.target {
                let report = transit::probe::probe(t)?;
                any |= !report.findings.is_empty();
                if format == Format::Json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!("\n{} ({})", t.name, t.base_url);
                    println!("  evidence: {}", report.evidence.caveat());
                    // Without this line an empty `findings` reads as "clean"
                    // when the truth is that none of the checks addressed a
                    // route this target recognised — the exact confusion
                    // `checks_applicable` exists to prevent, and the reason
                    // `probe` spends a request establishing it.
                    if !report.checks_applicable {
                        println!(
                            "  the checks did not apply: this target did not recognise the \
                             routes they are built around, so anything below is the absence \
                             of a measurement rather than a clean result"
                        );
                    }
                    for f in &report.findings {
                        println!("  {} [{}]", f.title, f.condition.title());
                    }
                }
            }
            Ok(if any {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        Cmd::Classify { spec, format } => {
            let src = std::fs::read_to_string(&spec)
                .with_context(|| format!("reading {}", spec.display()))?;
            let cs = transit::classify::classify_spec(&src)?;
            if format == Format::Json {
                println!("{}", serde_json::to_string_pretty(&cs)?);
            } else {
                for c in &cs {
                    println!("\n{} {} — {:?}", c.method, c.path, c.verdict);
                    println!("  evidence: {}", c.evidence.caveat());
                    for (cond, v) in &c.conditions {
                        println!("    {:<32} {v:?}", cond.title());
                    }
                }
            }
            Ok(
                if cs
                    .iter()
                    .any(|c| c.verdict == transit::classify::Verdict::NonQualifying)
                {
                    ExitCode::from(1)
                } else {
                    ExitCode::SUCCESS
                },
            )
        }
        Cmd::Guard { config } => {
            let cfg = transit::guard::load_config(&config)?;
            transit::guard::serve(&cfg)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn print_case(c: &transit::differential::CaseReport, format: Format) -> Result<()> {
    if format == Format::Json {
        println!("{}", serde_json::to_string_pretty(c)?);
        return Ok(());
    }
    println!("\n{}", c.case);
    if !c.why.is_empty() {
        println!("  {}", c.why);
    }
    match &c.divergence {
        None => {
            // Fix round 1, I8: "every decoder agreed" is what a genuine
            // agreement on a value looks like, but `divergence` is also
            // `None` when every decoder rejected the payload outright — in
            // which case they agreed about nothing, and the previous
            // wording claimed the opposite of what happened. Unavailable
            // (crashed) decoders take no part in either reading, the same
            // way `classify` excludes them from every comparison.
            let considered: Vec<&transit::decoder::Observation> = c
                .reports
                .iter()
                .map(|r| &r.observation)
                .filter(|o| !matches!(o, transit::decoder::Observation::Unavailable))
                .collect();
            let all_rejected = !considered.is_empty()
                && considered
                    .iter()
                    .all(|o| matches!(o, transit::decoder::Observation::Rejected));
            if all_rejected {
                println!("  every decoder agreed: REJECTED");
            } else {
                println!("  every decoder agreed");
            }
        }
        Some(d) => {
            println!("  {} distinct observations:", d.classes.len());
            for (obs, ids) in &d.classes {
                // Fix round 1, I7: a 72-character prefix truncated the
                // flagship duplicate-key finding — the two value classes for
                // `duplicate-key-recipient` are 83 characters and first
                // differ at index 81, so both printed an identical prefix
                // with no ellipsis, and the demo (first-key-wins authorizes
                // `acct-1`, last-key-wins pays `acct-9`) rendered as two
                // indistinguishable lines. Print the observation in full.
                println!("    {:<40} {}", ids.join(", "), obs);
            }
        }
    }
    Ok(())
}
