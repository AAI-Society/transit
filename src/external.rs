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
use std::path::PathBuf;
use std::process::{Command, Stdio};

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
    u = v.encode('UTF-16BE', invalid: :replace, undef: :replace).unpack('n*')
    return 'S:' + u.map { |c| format('%04x', c) }.join(',')
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
        candidates: &[
            "python3",
            "python3.14",
            "python3.13",
            "python3.12",
            "python",
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

/// Runtimes that were looked for and not found. Never silently empty: a
/// missing runtime is a fact the report has to carry, because a differential
/// with fewer decoders is a weaker result and must not look like a stronger
/// one.
pub fn missing_runtimes() -> Vec<&'static Expected> {
    EXPECTED.iter().filter(|e| resolve(e).is_none()).collect()
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

fn cache_dir() -> PathBuf {
    PathBuf::from(".transit-cache")
}

/// Write a script into the cache directory, returning its path.
fn write_helper(name: &str, body: &str) -> Result<PathBuf, std::io::Error> {
    let dir = cache_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(name);
    std::fs::write(&path, body)?;
    Ok(path)
}

pub fn discover() -> Vec<External> {
    let mut out = Vec::new();
    for e in EXPECTED {
        let Some((program, version)) = resolve(e) else {
            continue;
        };
        let built = if e.compiled {
            build_go(&program)
        } else {
            script_args(e.id, &program)
        };
        let Ok((program, args)) = built else { continue };
        out.push(External {
            id: e.id.to_string(),
            runtime: e.runtime.to_string(),
            version,
            program,
            args,
        });
    }
    out
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
fn build_go(program: &str) -> Result<(String, Vec<String>), std::io::Error> {
    let src = write_helper("obs.go", GO_SCRIPT)?;
    let bin = cache_dir().join("obs-go");
    if !bin.exists() {
        let out = Command::new(program)
            .args(["build", "-o"])
            .arg(&bin)
            .arg(&src)
            .env("GOPROXY", "off")
            .env("GOFLAGS", "-mod=mod")
            .env("GOTOOLCHAIN", "local")
            .output()?;
        if !out.status.success() {
            return Err(std::io::Error::other(format!(
                "go build failed: {}",
                String::from_utf8_lossy(&out.stderr)
            )));
        }
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
        // `missing_runtimes` yields `&'static Expected`, so `id` is a `&str`.
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
