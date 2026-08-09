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
                    print_case(&r, format)?;
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
        None => println!("  every decoder agreed"),
        Some(d) => {
            println!("  {} distinct observations:", d.classes.len());
            for (obs, ids) in &d.classes {
                let short: String = obs.chars().take(72).collect();
                println!("    {:<40} {}", ids.join(", "), short);
            }
        }
    }
    Ok(())
}
