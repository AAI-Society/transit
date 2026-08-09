//! Discovery and execution of the language runtimes installed on this host,
//! run as JSON decoders whose output is directly comparable to the in-crate
//! models in `decoder::in_crate`.
//!
//! Each runtime runs a script that parses a payload from stdin and prints one
//! line: `OK <observation>` or `ERR <detail>`. The scripts emit exactly the
//! format `decoder::render_exact` emits, so an external runtime and an
//! in-crate decoder are directly comparable once Rust re-derives the
//! material key with `decoder::materialize`.

use crate::decoder::{DecoderReport, Observation, Provenance};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

/// A temp-file suffix unique within this process, combined with the process
/// ID for uniqueness across processes too. Fix round 1, I2: an earlier draft
/// used only `std::process::id()`, which is unique *per process* but not
/// *per thread* — `cargo test`'s default parallel test execution runs many
/// `#[test]` functions as threads inside one process, all sharing that one
/// PID, so concurrent calls to `write_helper`/`build_go` collided on the
/// identical temp path and one thread's `rename` failed with "not found"
/// after another thread's `rename` had already moved it. Measured directly:
/// this crate's own test suite intermittently failed
/// `a_runtime_that_is_absent_is_reported_rather_than_dropped` under the
/// default parallel test runner until this counter was added.
fn unique_suffix() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    format!(
        "{}.{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

const NODE_SCRIPT: &str = r#"
const src = require('fs').readFileSync(0, 'utf8');
function render(v) {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'boolean') return String(v);
  if (t === 'number') { const b = Buffer.alloc(8); b.writeDoubleBE(v); return 'F:' + b.toString('hex'); }
  if (t === 'string') {
    const u = [];
    for (let i = 0; i < v.length; i++) u.push(v.charCodeAt(i).toString(16).padStart(4, '0'));
    return 'S:' + u.join(',');
  }
  if (Array.isArray(v)) return '[' + v.map(render).join(',') + ']';
  // Sorted by key, never by the joined pair — Rust re-derives the material
  // key from this output, and a value-dependent sort would reorder members
  // between the two paths.
  const keys = Object.keys(v).map(k => [render(k), k]);
  keys.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return '{' + keys.map(([rk, k]) => rk + '=' + render(v[k])).join(',') + '}';
}
try { process.stdout.write('OK ' + render(JSON.parse(src)) + '\n'); }
catch (e) { process.stdout.write('ERR ' + String(e.message).replace(/\n/g, ' ') + '\n'); }
"#;

const PYTHON_SCRIPT: &str = r#"
import sys, json, struct
def render(v):
    if v is None: return 'null'
    if v is True: return 'true'
    if v is False: return 'false'
    if isinstance(v, int): return 'I:%d' % v
    if isinstance(v, float): return 'F:' + struct.pack('>d', v).hex()
    if isinstance(v, str):
        u = []
        for ch in v:
            c = ord(ch)
            if c > 0xFFFF:
                c -= 0x10000
                u.append('%04x' % (0xD800 + (c >> 10)))
                u.append('%04x' % (0xDC00 + (c & 0x3FF)))
            else:
                u.append('%04x' % c)
        return 'S:' + ','.join(u)
    if isinstance(v, list): return '[' + ','.join(render(x) for x in v) + ']'
    # Sorted by key, never by the joined pair: Rust re-derives the material
    # key from this output and a value-dependent sort would reorder members.
    ks = sorted(((render(k), k) for k in v), key=lambda p: p[0])
    return '{' + ','.join(rk + '=' + render(v[k]) for rk, k in ks) + '}'
try:
    sys.stdout.write('OK ' + render(json.loads(sys.stdin.read())) + '\n')
except Exception as e:
    sys.stdout.write('ERR ' + str(e).replace('\n', ' ') + '\n')
"#;

const RUBY_SCRIPT: &str = r#"
require 'json'
def render(v)
  return 'null' if v.nil?
  return v.to_s if v == true || v == false
  return "I:#{v}" if v.is_a?(Integer)
  return 'F:' + [v].pack('G').unpack1('H*') if v.is_a?(Float)
  if v.is_a?(String)
    # Not `.encode('UTF-16BE', invalid: :replace)`: Ruby's JSON.parse can
    # produce a string that is not valid UTF-8 at all -- a lone low
    # surrogate (unpaired \udc00..\udfff) parses to the raw 3-byte
    # sequence ED Ax/Bx xx, which is exactly how CESU-8/WTF-8 spells that
    # surrogate. `.encode(invalid: :replace)` cannot decode that sequence
    # (it is invalid UTF-8 by construction) and replaces it with U+FFFD,
    # which reports a value Ruby never produced -- a fix-round-1 finding
    # (C2): the harness itself was manufacturing a divergence out of
    # nothing. Decode the raw bytes as WTF-8 by hand instead, the same way
    # PYTHON_SCRIPT splits an astral code point into a surrogate pair by
    # hand rather than delegating to something that assumes strict UTF-8.
    bytes = v.bytes
    units = []
    i = 0
    n = bytes.length
    while i < n
      b0 = bytes[i]
      if b0 < 0x80
        units << b0
        i += 1
      elsif b0 & 0xE0 == 0xC0
        units << (((b0 & 0x1F) << 6) | (bytes[i + 1] & 0x3F))
        i += 2
      elsif b0 & 0xF0 == 0xE0
        # A 3-byte sequence can legitimately encode a lone surrogate here
        # (0xD800..0xDFFF) -- forbidden in strict UTF-8, but exactly what
        # Ruby produces for the unpaired-low-surrogate case above.
        cp = ((b0 & 0x0F) << 12) | ((bytes[i + 1] & 0x3F) << 6) | (bytes[i + 2] & 0x3F)
        units << cp
        i += 3
      else
        cp = ((b0 & 0x07) << 18) | ((bytes[i + 1] & 0x3F) << 12) |
             ((bytes[i + 2] & 0x3F) << 6) | (bytes[i + 3] & 0x3F)
        units << (0xD800 + ((cp - 0x10000) >> 10))
        units << (0xDC00 + ((cp - 0x10000) & 0x3FF))
        i += 4
      end
    end
    return 'S:' + units.map { |c| format('%04x', c) }.join(',')
  end
  return '[' + v.map { |x| render(x) }.join(',') + ']' if v.is_a?(Array)
  # Sorted by key, never by the joined pair: Rust re-derives the material key
  # from this output and a value-dependent sort would reorder members.
  ks = v.map { |k, x| [render(k), x] }.sort_by { |rk, _| rk }
  '{' + ks.map { |rk, x| rk + '=' + render(x) }.join(',') + '}'
end
begin
  STDOUT.write('OK ' + render(JSON.parse(STDIN.read)) + "\n")
rescue => e
  STDOUT.write('ERR ' + e.message.gsub("\n", ' ') + "\n")
end
"#;

const GO_SCRIPT: &str = r#"
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"sort"
	"strings"
	"unicode/utf16"
)

func render(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return fmt.Sprintf("F:%016x", math.Float64bits(t))
	case string:
		u := utf16.Encode([]rune(t))
		parts := make([]string, len(u))
		for i, c := range u {
			parts[i] = fmt.Sprintf("%04x", c)
		}
		return "S:" + strings.Join(parts, ",")
	case []interface{}:
		parts := make([]string, len(t))
		for i, x := range t {
			parts[i] = render(x)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case map[string]interface{}:
		// Sorted by key, never by the joined pair: Rust re-derives the
		// material key from this output and a value-dependent sort would
		// reorder members.
		keys := make([]string, 0, len(t))
		byKey := make(map[string]interface{}, len(t))
		for k, x := range t {
			rk := render(k)
			keys = append(keys, rk)
			byKey[rk] = x
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, rk := range keys {
			parts[i] = rk + "=" + render(byKey[rk])
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	return "?"
}

func main() {
	b, _ := io.ReadAll(os.Stdin)
	var v interface{}
	if err := json.Unmarshal(b, &v); err != nil {
		fmt.Printf("ERR %s\n", strings.ReplaceAll(err.Error(), "\n", " "))
		return
	}
	fmt.Printf("OK %s\n", render(v))
}
"#;

#[derive(Debug, thiserror::Error)]
pub enum ExternalError {
    #[error("could not run {id}: {source}")]
    Spawn {
        id: String,
        #[source]
        source: std::io::Error,
    },
    #[error("{id} produced no parsable line; stdout was {stdout:?}, stderr was {stderr:?}")]
    BadOutput {
        id: String,
        stdout: String,
        stderr: String,
    },
    #[error("could not prepare the {id} helper: {source}")]
    Cache {
        id: String,
        #[source]
        source: std::io::Error,
    },
}

/// A runtime this crate looks for, and what to do if it is there.
pub struct Expected {
    pub id: &'static str,
    pub runtime: &'static str,
    /// Tried in order. `python3` is a shell alias rather than a binary on
    /// some hosts, so `python` has to be a candidate too.
    pub candidates: &'static [&'static str],
    pub version_arg: &'static str,
    pub compiled: bool,
}

pub const EXPECTED: &[Expected] = &[
    Expected {
        id: "node",
        runtime: "node",
        candidates: &["node"],
        version_arg: "--version",
        compiled: false,
    },
    Expected {
        id: "python",
        runtime: "python",
        // Fix round 1, M2: `python` first, not last. `python3` really is a
        // zsh alias on this host, same as the original brief said, but the
        // rebuttal in the first pass was the misleading half: bypassing the
        // shell (as `Command::new` always does) does not fall through to
        // the alias's target -- it finds `/usr/bin/python3`, macOS's own
        // bundled 3.9.6, which is not the CPython this host actually
        // develops against. `python` resolves (also bypassing the alias,
        // there is no alias for the bare name) to the Homebrew-linked
        // interpreter, measured at 3.14.6. Trying `python` first gets the
        // interpreter a developer on this host means when they say
        // "python"; the trailing candidates remain as a fallback for a host
        // where only a versioned binary is on `PATH` at all.
        candidates: &[
            "python",
            "python3",
            "python3.14",
            "python3.13",
            "python3.12",
        ],
        version_arg: "--version",
        compiled: false,
    },
    Expected {
        id: "ruby",
        runtime: "ruby",
        candidates: &["ruby"],
        version_arg: "--version",
        compiled: false,
    },
    Expected {
        id: "go",
        runtime: "go",
        candidates: &["go"],
        version_arg: "version",
        compiled: true,
    },
];

pub struct External {
    pub id: String,
    pub runtime: String,
    pub version: String,
    /// The program to run, and the arguments before the payload arrives on
    /// stdin. For Go this is the compiled helper with no arguments.
    program: String,
    args: Vec<String>,
}

/// A runtime this crate looked for but could not use, and why.
///
/// Fix round 1, C1: `discover()` and `missing_runtimes()` used to resolve
/// each `Expected` independently, and only `discover()` knew about
/// preparation failures (a script write or `go build` erroring). A runtime
/// whose *binary* resolved but whose helper failed to prepare therefore
/// vanished from both — neither found nor missing, and the preparation
/// error (including "go build failed: …") was silently dropped rather than
/// surfaced through the `ExternalError::Cache` variant that exists
/// specifically for it. `prepare_all` is now the single source both
/// `discover()` and `missing_runtimes()` read from, so a runtime can no
/// longer fall through the gap between them, and `reason` carries the
/// preparation error instead of discarding it.
pub struct Missing {
    pub id: &'static str,
    pub runtime: &'static str,
    /// `None` when no candidate binary could even be resolved — the
    /// runtime is simply not installed. `Some` when a candidate resolved
    /// but this crate could not prepare it to run.
    pub reason: Option<ExternalError>,
}

/// Runtimes that were looked for and not found. Never silently empty: a
/// missing runtime is a fact the report has to carry, because a differential
/// with fewer decoders is a weaker result and must not look like a stronger
/// one.
pub fn missing_runtimes() -> Vec<Missing> {
    prepare_all().1
}

pub fn discover() -> Vec<External> {
    prepare_all().0
}

fn prepare_all() -> (Vec<External>, Vec<Missing>) {
    prepare(EXPECTED)
}

/// The one place that resolves and prepares a list of `Expected` entries.
/// `discover()` and `missing_runtimes()` both read from `prepare_all`'s
/// result over the real `EXPECTED`, rather than each re-implementing (and,
/// as fix round 1 found, disagreeing about) what counts as available. Takes
/// the list as a parameter, rather than reading `EXPECTED` directly, so
/// `prepare`'s categorization can be tested against a synthetic `Expected`
/// without depending on which real runtimes happen to be installed on the
/// host running the tests — see
/// `a_runtime_whose_binary_resolves_but_fails_to_prepare_is_missing_with_a_reason`.
fn prepare(expected: &[Expected]) -> (Vec<External>, Vec<Missing>) {
    let mut found = Vec::new();
    let mut missing = Vec::new();
    for e in expected {
        let Some((program, version)) = resolve(e) else {
            missing.push(Missing {
                id: e.id,
                runtime: e.runtime,
                reason: None,
            });
            continue;
        };
        let built = if e.compiled {
            build_go(&program)
        } else {
            script_args(e.id, &program)
        };
        match built {
            Ok((program, args)) => found.push(External {
                id: e.id.to_string(),
                runtime: e.runtime.to_string(),
                version,
                program,
                args,
            }),
            Err(source) => missing.push(Missing {
                id: e.id,
                runtime: e.runtime,
                reason: Some(ExternalError::Cache {
                    id: e.id.to_string(),
                    source,
                }),
            }),
        }
    }
    (found, missing)
}

fn resolve(e: &Expected) -> Option<(String, String)> {
    for c in e.candidates {
        // `.ok()?` here would return from `resolve`, not from the loop — so
        // the first candidate that is not a binary would abandon the rest of
        // the list. On this host `python3` is a shell alias and spawning it
        // errors, so `python` would never be tried and Python would be
        // reported missing: exactly the silent weakening the Host facts
        // section says must not happen.
        let Ok(out) = Command::new(c).arg(e.version_arg).output() else {
            continue;
        };
        if !out.status.success() {
            continue;
        }
        let v = String::from_utf8_lossy(&out.stdout);
        let v = if v.trim().is_empty() {
            String::from_utf8_lossy(&out.stderr).trim().to_string()
        } else {
            v.trim().to_string()
        };
        if !v.is_empty() {
            return Some(((*c).to_string(), v));
        }
    }
    None
}

/// Fix round 1, M1: anchored on the crate's own directory, not the process's
/// current working directory. `.transit-cache` relative to an arbitrary CWD
/// meant a binary invoked from elsewhere littered a fresh cache directory
/// there and rebuilt Go every time instead of reusing the one this crate
/// already prepared.
fn cache_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(".transit-cache")
}

/// Write a script into the cache directory, returning its path.
///
/// Fix round 1, I2: writes to a process-unique temp path and `rename`s into
/// place rather than truncating the final path directly. `cargo test --lib`
/// and `cargo test --test model_fidelity` run as separate *processes*
/// against the same cache directory once Task 5 lands; a direct write that
/// another process's spawn reads mid-write would be a torn file. POSIX
/// `rename` onto an existing path is atomic, so a reader always sees either
/// the complete old file or the complete new one.
fn write_helper(name: &str, body: &str) -> Result<PathBuf, std::io::Error> {
    let dir = cache_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(name);
    let tmp = dir.join(format!("{name}.{}.tmp", unique_suffix()));
    std::fs::write(&tmp, body)?;
    std::fs::rename(&tmp, &path)?;
    Ok(path)
}

fn script_args(id: &str, program: &str) -> Result<(String, Vec<String>), std::io::Error> {
    let (file, body) = match id {
        "node" => ("obs.js", NODE_SCRIPT),
        "python" => ("obs.py", PYTHON_SCRIPT),
        "ruby" => ("obs.rb", RUBY_SCRIPT),
        _ => return Err(std::io::Error::other(format!("no script for {id}"))),
    };
    let path = write_helper(file, body)?;
    Ok((program.to_string(), vec![path.display().to_string()]))
}

/// Compile the Go helper once and reuse the binary. `GOPROXY=off` and
/// `GOFLAGS=-mod=mod` are not decoration: `differential` promises to touch no
/// network, and a toolchain that can fetch modules would quietly break that
/// promise on a host with a stray `go.mod`.
///
/// Fix round 1, I2: builds to a process-unique temp path and `rename`s into
/// place, the same reasoning as `write_helper`. The `exists()` check below
/// is still a plain check-then-act — two processes can both see the binary
/// missing and both build — but the build is deterministic (identical
/// `GO_SCRIPT` every time), so a duplicate build wastes CPU rather than
/// producing a torn or inconsistent binary; only the final `rename` needs to
/// be atomic, and it is.
fn build_go(program: &str) -> Result<(String, Vec<String>), std::io::Error> {
    let src = write_helper("obs.go", GO_SCRIPT)?;
    let bin = cache_dir().join("obs-go");
    if !bin.exists() {
        let tmp_bin = cache_dir().join(format!("obs-go.{}.tmp", unique_suffix()));
        let out = Command::new(program)
            .args(["build", "-o"])
            .arg(&tmp_bin)
            .arg(&src)
            .env("GOPROXY", "off")
            .env("GOFLAGS", "-mod=mod")
            .env("GOTOOLCHAIN", "local")
            .output()?;
        if !out.status.success() {
            let _ = std::fs::remove_file(&tmp_bin);
            return Err(std::io::Error::other(format!(
                "go build failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        std::fs::rename(&tmp_bin, &bin)?;
    }
    Ok((bin.display().to_string(), Vec::new()))
}

impl External {
    pub fn provenance(&self) -> Provenance {
        Provenance::External {
            runtime: self.runtime.clone(),
            version: self.version.clone(),
        }
    }

    pub fn observe(&self, payload: &str) -> Result<DecoderReport, ExternalError> {
        let mut child = Command::new(&self.program)
            .args(&self.args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|source| ExternalError::Spawn {
                id: self.id.clone(),
                source,
            })?;

        if let Some(mut si) = child.stdin.take() {
            // A helper that exits before reading everything closes the pipe;
            // that is its answer, not our failure.
            let _ = si.write_all(payload.as_bytes());
        }
        let out = child
            .wait_with_output()
            .map_err(|source| ExternalError::Spawn {
                id: self.id.clone(),
                source,
            })?;

        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        let line = stdout.lines().next().unwrap_or("").to_string();

        // The helpers emit the *exact* key. Rust derives the material key
        // from it with `decoder::materialize`, so both identities come from
        // one implementation and an external runtime is directly comparable
        // with an in-crate model on either.
        let (observation, representation, detail) = if let Some(rest) = line.strip_prefix("OK ") {
            let exact = rest.to_string();
            (
                Observation::Value {
                    rendered: crate::decoder::materialize(&exact),
                },
                Some(exact),
                None,
            )
        } else if let Some(rest) = line.strip_prefix("ERR ") {
            (Observation::Rejected, None, Some(rest.to_string()))
        } else {
            return Err(ExternalError::BadOutput {
                id: self.id.clone(),
                stdout,
                stderr,
            });
        };

        Ok(DecoderReport {
            id: self.id.clone(),
            provenance: self.provenance(),
            observation,
            representation,
            detail,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoder::Observation;

    /// Every discovered runtime must agree with itself on a trivial payload,
    /// which is really a test that the scripts and the transport work at all.
    #[test]
    fn discovered_runtimes_parse_a_trivial_payload() {
        for e in discover() {
            let r = e
                .observe(r#"{"a":1}"#)
                .unwrap_or_else(|err| panic!("{}: {err}", e.id));
            assert!(
                matches!(r.observation, Observation::Value { .. }),
                "{} rejected a trivial object: {:?}",
                e.id,
                r.detail
            );
        }
    }

    #[test]
    fn an_external_report_carries_its_runtime_version() {
        for e in discover() {
            let r = e.observe("{}").unwrap();
            let crate::decoder::Provenance::External { runtime, version } = &r.provenance else {
                panic!("{} should be External", e.id);
            };
            assert!(
                !runtime.is_empty() && !version.is_empty(),
                "{} has no version",
                e.id
            );
        }
    }

    #[test]
    fn a_runtime_that_is_absent_is_reported_rather_than_dropped() {
        // Nothing here asserts which runtimes exist — that is a property of
        // the host. It asserts that every runtime this crate looks for is
        // accounted for either as discovered or as missing, so a silently
        // absent runtime cannot quietly weaken the headline result.
        let found: Vec<String> = discover().into_iter().map(|e| e.id).collect();
        // `missing_runtimes` yields `Missing`, whose `id` is `&'static str`.
        let missing: Vec<String> = missing_runtimes()
            .into_iter()
            .map(|m| m.id.to_string())
            .collect();
        assert_eq!(found.len() + missing.len(), EXPECTED.len());
        for e in EXPECTED {
            assert!(
                found.iter().any(|f| f == e.id) || missing.iter().any(|m| m == e.id),
                "{} is neither discovered nor missing",
                e.id
            );
        }
    }

    #[test]
    fn a_runtime_whose_binary_resolves_but_fails_to_prepare_is_missing_with_a_reason() {
        // Fix round 1, C1: the exact scenario that used to make a runtime
        // vanish from both `discover()` and `missing_runtimes()` -- the
        // version-check candidate resolves (so it is not simply "absent"),
        // but the preparation step after that fails. `echo` resolves under
        // `resolve()` (any argument makes it print something and exit 0,
        // satisfying the version check), and `script_args` then fails
        // deterministically because `"unknown-script-id"` matches none of
        // the three known script kinds. Hermetic: no dependency on which
        // real runtimes happen to be installed, and no risk of colliding
        // with the `.transit-cache` state the other tests in this module
        // share (unlike routing this through `compiled: true`, which would
        // collide with the real Go entry's cached `obs-go` binary).
        let fake = Expected {
            id: "unknown-script-id",
            runtime: "fake",
            candidates: &["echo"],
            version_arg: "version",
            compiled: false,
        };
        let (found, missing) = prepare(std::slice::from_ref(&fake));
        assert!(
            found.is_empty(),
            "must not silently succeed: {} entries found",
            found.len()
        );
        assert_eq!(missing.len(), 1, "must not silently vanish");
        assert_eq!(missing[0].id, "unknown-script-id");
        assert!(
            matches!(&missing[0].reason, Some(ExternalError::Cache { .. })),
            "the preparation failure must be carried, not discarded: {:?}",
            missing[0].reason
        );
    }

    #[test]
    fn a_malformed_payload_is_an_observation_not_an_error() {
        // A runtime rejecting a payload is data. Only a failure to *run* the
        // runtime is an error.
        for e in discover() {
            let r = e
                .observe("{")
                .unwrap_or_else(|err| panic!("{}: {err}", e.id));
            assert_eq!(r.observation, Observation::Rejected, "{}", e.id);
            assert!(r.detail.is_some(), "{} gave no reason", e.id);
        }
    }
}
