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
