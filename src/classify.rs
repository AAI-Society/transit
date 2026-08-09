use crate::corpus::{Condition, Evidence};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum ClassifyError {
    #[error("could not parse the specification: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("this does not look like an OpenAPI document: {why}")]
    NotOpenApi { why: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Verdict {
    /// C1–C4 all satisfied as specified.
    Qualified,
    /// Nothing failed, but something is unknown or depends on the client
    /// volunteering more than the specification requires.
    Conditional,
    /// At least one condition cannot be met at all.
    NonQualifying,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ConditionVerdict {
    Satisfied,
    /// A specification cannot answer this question. Caps the result at
    /// `Conditional` rather than asserting a failure the document does not
    /// support.
    Unknown {
        why: String,
    },
    /// Achievable, but only if the client sends more than it is obliged to.
    ClientDependent {
        how: String,
    },
    /// There is nothing a well-behaved client could do about this.
    Failed {
        why: String,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct Classification {
    pub operation: String,
    pub method: String,
    pub path: String,
    pub conditions: Vec<(Condition, ConditionVerdict)>,
    pub verdict: Verdict,
    /// The specific conditions that failed, named so a reader knows which
    /// one is load-bearing for a given deployment.
    pub failing: Vec<Condition>,
    pub evidence: Evidence,
}

impl Classification {
    pub fn verdict_for(&self, c: Condition) -> Option<&ConditionVerdict> {
        self.conditions
            .iter()
            .find(|(k, _)| *k == c)
            .map(|(_, v)| v)
    }
}

/// Phrases that betray server-side defaulting in prose. Crude on purpose:
/// this is a documentation heuristic and is labelled as one. It fires on
/// evidence *for* a failure and never on its absence.
const SERVER_DEFAULT_PHRASES: &[&str] = &[
    "user profile",
    "account default",
    "workspace default",
    "inherited from",
    "server-side default",
    "derived from the account",
];

const ALIAS_PHRASES: &[&str] = &[
    "id or name",
    "name or id",
    "channel name",
    "or alias",
    "alias for",
    "may be an alias",
];

const IDEMPOTENCY_NAMES: &[&str] = &[
    "idempotency-key",
    "idempotency_key",
    "x-idempotency-key",
    "idempotencytoken",
    "client-token",
    "clienttoken",
    "request-id",
    "request_id",
    "requestid",
];

const PINNING_NAMES: &[&str] = &[
    "if-match",
    "if-unmodified-since",
    "etag",
    "version",
    "resource_version",
    "cas",
    "sha",
    "parent_sha",
    "base_commit",
];

/// Methods RFC 9110 defines as idempotent.
const IDEMPOTENT_METHODS: &[&str] = &["GET", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE"];

/// Maximum `$ref` hops. Bounded rather than cycle-detected: a self-referential
/// schema is legal OpenAPI, and this classifier only needs the top two levels
/// of any schema, so stopping is both safe and sufficient.
const MAX_REF_DEPTH: usize = 16;

/// Inline local `$ref`s before classifying.
///
/// Not optional polish: **every** real OpenAPI document — the actual ISO
/// 20022, S3 and Stripe specifications included — puts its schemas behind
/// `$ref`. A classifier that does not resolve them sees an object whose only
/// key is `$ref`, finds no properties, and returns `Unknown` for C1 and C2 on
/// every operation, collapsing silently to `Conditional`. The four examples
/// shipped here are hand-inlined, so without this the gap would be invisible
/// in testing and universal in practice.
///
/// Remote and file `$ref`s are deliberately not followed — resolving those
/// would mean fetching, and `classify` touches no network.
fn inline_refs(doc: &Value, node: &Value, depth: usize) -> Value {
    if depth >= MAX_REF_DEPTH {
        return node.clone();
    }
    match node {
        Value::Object(m) => {
            if let Some(Value::String(r)) = m.get("$ref") {
                let Some(rest) = r.strip_prefix("#/") else {
                    // A remote or file reference. Left as-is, and the verdict
                    // it produces is `Unknown` rather than a guess.
                    return node.clone();
                };
                let mut cur = doc;
                for seg in rest.split('/') {
                    // RFC 6901 escaping, the only two that matter here.
                    let seg = seg.replace("~1", "/").replace("~0", "~");
                    match cur.get(&seg) {
                        Some(next) => cur = next,
                        None => return node.clone(),
                    }
                }
                return inline_refs(doc, &cur.clone(), depth + 1);
            }
            Value::Object(
                m.iter()
                    .map(|(k, v)| (k.clone(), inline_refs(doc, v, depth + 1)))
                    .collect(),
            )
        }
        Value::Array(a) => Value::Array(a.iter().map(|v| inline_refs(doc, v, depth + 1)).collect()),
        other => other.clone(),
    }
}

pub fn classify_spec(spec_json: &str) -> Result<Vec<Classification>, ClassifyError> {
    let raw: Value = serde_json::from_str(spec_json)?;
    if raw.get("swagger").is_some() && raw.get("openapi").is_none() {
        return Err(ClassifyError::NotOpenApi {
            why: "this is a Swagger 2.0 document; only OpenAPI 3.x is understood".into(),
        });
    }
    let doc = inline_refs(&raw, &raw, 0);
    let paths =
        doc.get("paths")
            .and_then(Value::as_object)
            .ok_or_else(|| ClassifyError::NotOpenApi {
                why: "no `paths` object".into(),
            })?;

    let mut out = Vec::new();
    for (path, item) in paths {
        let Some(item) = item.as_object() else {
            continue;
        };
        for method in ["get", "post", "put", "patch", "delete"] {
            let Some(op) = item.get(method).and_then(Value::as_object) else {
                continue;
            };
            check_shape(path, method, op, item)?;
            out.push(classify_operation(path, method, op, item));
        }
    }
    if out.is_empty() {
        return Err(ClassifyError::NotOpenApi {
            why: "no operations found".into(),
        });
    }
    Ok(out)
}

/// Refuse an operation whose shape this classifier would otherwise read past
/// in silence.
///
/// `parameters()` and `body_schema()` are both written to skip anything of
/// the wrong type, which is right for an *absent* field and wrong for a
/// malformed one: a `"parameters"` that is a string, or a `"schema"` that is
/// a number, would classify as an operation with no parameters and no body
/// and quietly earn C1 `Unknown` rather than an error. Since the whole point
/// of `Unknown` is that it is an honest reading of a document, a reading
/// taken from a document this tool failed to understand cannot be allowed to
/// wear the same label.
fn check_shape(
    path: &str,
    method: &str,
    op: &serde_json::Map<String, Value>,
    item: &serde_json::Map<String, Value>,
) -> Result<(), ClassifyError> {
    let where_ = || format!("{} {path}", method.to_ascii_uppercase());
    for (src, whose) in [
        (item.get("parameters"), "path item"),
        (op.get("parameters"), "operation"),
    ] {
        if let Some(v) = src {
            if !v.is_array() {
                return Err(ClassifyError::NotOpenApi {
                    why: format!("{}: the {whose} `parameters` is not an array", where_()),
                });
            }
        }
    }
    if let Some(body) = op.get("requestBody") {
        if let Some(content) = body.get("content") {
            for (media, entry) in content.as_object().into_iter().flatten() {
                if let Some(schema) = entry.get("schema") {
                    if !schema.is_object() {
                        return Err(ClassifyError::NotOpenApi {
                            why: format!("{}: the `{media}` schema is not an object", where_()),
                        });
                    }
                }
            }
        }
    }
    Ok(())
}

struct Param<'a> {
    name: String,
    /// `path`, `query`, `header` or `cookie`. Load-bearing for C1: an
    /// optional *query* parameter is un-signed server-side input, while a
    /// path parameter is structurally required by the template.
    location: String,
    required: bool,
    description: String,
    schema: Option<&'a Value>,
}

fn parameters<'a>(
    op: &'a serde_json::Map<String, Value>,
    item: &'a serde_json::Map<String, Value>,
) -> Vec<Param<'a>> {
    let mut out = Vec::new();
    for src in [item.get("parameters"), op.get("parameters")]
        .into_iter()
        .flatten()
    {
        let Some(list) = src.as_array() else { continue };
        for p in list {
            let Some(name) = p.get("name").and_then(Value::as_str) else {
                continue;
            };
            out.push(Param {
                name: name.to_ascii_lowercase(),
                location: p
                    .get("in")
                    .and_then(Value::as_str)
                    .unwrap_or("query")
                    .to_ascii_lowercase(),
                required: p.get("required").and_then(Value::as_bool).unwrap_or(false),
                description: p
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_ascii_lowercase(),
                schema: p.get("schema"),
            });
        }
    }
    out
}

fn body_schema(op: &serde_json::Map<String, Value>) -> Option<&Value> {
    op.get("requestBody")?
        .get("content")?
        .get("application/json")?
        .get("schema")
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| haystack.contains(n))
}

fn classify_operation(
    path: &str,
    method: &str,
    op: &serde_json::Map<String, Value>,
    item: &serde_json::Map<String, Value>,
) -> Classification {
    let params = parameters(op, item);
    let schema = body_schema(op);
    let method_upper = method.to_ascii_uppercase();

    let conditions = vec![
        (Condition::C1, judge_c1(schema, &params)),
        (Condition::C2, judge_c2(path, schema, &params)),
        (Condition::C3, judge_c3(&method_upper, schema, &params)),
        (Condition::C4, judge_c4(schema, &params)),
    ];

    let failing: Vec<Condition> = conditions
        .iter()
        .filter(|(_, v)| matches!(v, ConditionVerdict::Failed { .. }))
        .map(|(c, _)| *c)
        .collect();

    let verdict = if !failing.is_empty() {
        Verdict::NonQualifying
    } else if conditions
        .iter()
        .all(|(_, v)| matches!(v, ConditionVerdict::Satisfied))
    {
        Verdict::Qualified
    } else {
        Verdict::Conditional
    };

    Classification {
        operation: op
            .get("operationId")
            .and_then(Value::as_str)
            .unwrap_or("(unnamed)")
            .to_string(),
        method: method_upper,
        path: path.to_string(),
        conditions,
        verdict,
        failing,
        evidence: Evidence::SpecDerived,
    }
}

/// Every property of the body schema, as `(name, schema)`.
fn properties(schema: Option<&Value>) -> Vec<(String, &Value)> {
    let Some(props) = schema
        .and_then(|s| s.get("properties"))
        .and_then(Value::as_object)
    else {
        return Vec::new();
    };
    props
        .iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .collect()
}

fn required_names(schema: Option<&Value>) -> Vec<String> {
    schema
        .and_then(|s| s.get("required"))
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_ascii_lowercase)
                .collect()
        })
        .unwrap_or_default()
}

fn description_of(v: &Value) -> String {
    v.get("description")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn judge_c1(schema: Option<&Value>, params: &[Param]) -> ConditionVerdict {
    // A documented server-side default is a positive signal of failure: the
    // client cannot override state it never sees.
    for (name, prop) in properties(schema) {
        if prop
            .get("x-transit-server-default")
            .and_then(Value::as_bool)
            == Some(true)
            || contains_any(&description_of(prop), SERVER_DEFAULT_PHRASES)
        {
            return ConditionVerdict::Failed {
                why: format!("`{name}` is documented as filled from server-side state"),
            };
        }
    }
    for p in params {
        if contains_any(&p.description, SERVER_DEFAULT_PHRASES) {
            return ConditionVerdict::Failed {
                why: format!(
                    "`{}` is documented as filled from server-side state",
                    p.name
                ),
            };
        }
    }

    let Some(schema) = schema else {
        return ConditionVerdict::Unknown {
            why: "no JSON request body is described, so the parameter space is unknown".into(),
        };
    };
    let props = properties(Some(schema));
    if props.is_empty() {
        return ConditionVerdict::Unknown {
            why: "the request body schema declares no properties".into(),
        };
    }
    let required = required_names(Some(schema));
    let closed = schema.get("additionalProperties").and_then(Value::as_bool) == Some(false);

    let mut volunteer: Vec<String> = props
        .iter()
        .filter(|(n, p)| !required.contains(n) || p.get("default").is_some())
        .map(|(n, _)| n.clone())
        .collect();
    // Optional parameters outside the body count too. P02's worked example is
    // `POST /v1/transfer?to=acct-9&fee_tier=priority` — a *query* parameter —
    // so a rule that reads only the request body would return `Satisfied` on
    // the paper's own headline case. Path parameters are excluded: they are
    // structurally required by the template.
    for p in params
        .iter()
        .filter(|p| !p.required && p.location != "path")
    {
        volunteer.push(format!("{} ({})", p.name, p.location));
    }
    if !closed {
        volunteer.push("(additionalProperties is not `false`)".into());
    }
    if volunteer.is_empty() {
        ConditionVerdict::Satisfied
    } else {
        volunteer.sort();
        ConditionVerdict::ClientDependent {
            how: format!(
                "send every optional parameter explicitly: {}",
                volunteer.join(", ")
            ),
        }
    }
}

fn judge_c2(path: &str, schema: Option<&Value>, params: &[Param]) -> ConditionVerdict {
    for seg in path.split('/') {
        if seg.eq_ignore_ascii_case("me") || seg.eq_ignore_ascii_case("self") {
            return ConditionVerdict::Failed {
                why: format!("`{seg}` is an alias for a concrete identifier, so two canonical forms name one resource"),
            };
        }
    }
    for (name, prop) in properties(schema) {
        if prop.get("x-transit-alias").and_then(Value::as_bool) == Some(true)
            || contains_any(&description_of(prop), ALIAS_PHRASES)
        {
            return ConditionVerdict::Failed {
                why: format!("`{name}` accepts more than one spelling of the same resource"),
            };
        }
    }
    for p in params {
        if contains_any(&p.description, ALIAS_PHRASES) {
            return ConditionVerdict::Failed {
                why: format!(
                    "`{}` accepts more than one spelling of the same resource",
                    p.name
                ),
            };
        }
    }

    // Injectivity needs the identifier space pinned as well as the body
    // closed: an unconstrained path template can spell one resource many
    // ways just as an alias can.
    let closed = schema
        .and_then(|s| s.get("additionalProperties"))
        .and_then(Value::as_bool)
        == Some(false);
    let templated: Vec<&str> = path
        .split('/')
        .filter(|s| s.starts_with('{') && s.ends_with('}'))
        .collect();
    let all_constrained = templated.iter().all(|t| {
        let name = t
            .trim_matches(|c| c == '{' || c == '}')
            .to_ascii_lowercase();
        params.iter().any(|p| {
            p.name == name
                && p.schema
                    .map(|s| s.get("pattern").is_some() || s.get("format").is_some())
                    .unwrap_or(false)
        })
    });

    if closed && all_constrained {
        ConditionVerdict::Satisfied
    } else if !closed {
        ConditionVerdict::Unknown {
            why: "the body schema admits additional properties, so two wire forms may parse to one document".into(),
        }
    } else {
        ConditionVerdict::Unknown {
            why: "a path parameter is unconstrained, so the identifier space is not pinned".into(),
        }
    }
}

fn judge_c3(method: &str, schema: Option<&Value>, params: &[Param]) -> ConditionVerdict {
    if IDEMPOTENT_METHODS.contains(&method) {
        return ConditionVerdict::Satisfied;
    }
    let required = required_names(schema);
    let in_body = properties(schema)
        .into_iter()
        .find(|(n, _)| IDEMPOTENCY_NAMES.contains(&n.as_str()));
    if let Some((name, _)) = in_body {
        return if required.contains(&name) {
            ConditionVerdict::Satisfied
        } else {
            ConditionVerdict::ClientDependent {
                how: format!("send the optional `{name}` on every request"),
            }
        };
    }
    match params
        .iter()
        .find(|p| IDEMPOTENCY_NAMES.contains(&p.name.as_str()))
    {
        Some(p) if p.required => ConditionVerdict::Satisfied,
        Some(p) => ConditionVerdict::ClientDependent {
            how: format!("send the optional `{}` on every request", p.name),
        },
        None => ConditionVerdict::Failed {
            why: format!("{method} is not idempotent and the interface offers no idempotency key the client could supply"),
        },
    }
}

fn judge_c4(schema: Option<&Value>, params: &[Param]) -> ConditionVerdict {
    let required = required_names(schema);
    if let Some((name, _)) = properties(schema)
        .into_iter()
        .find(|(n, _)| PINNING_NAMES.contains(&n.as_str()))
    {
        return if required.contains(&name) {
            ConditionVerdict::Satisfied
        } else {
            ConditionVerdict::ClientDependent {
                how: format!("send the optional `{name}` precondition on every request"),
            }
        };
    }
    match params
        .iter()
        .find(|p| PINNING_NAMES.contains(&p.name.as_str()))
    {
        Some(p) if p.required => ConditionVerdict::Satisfied,
        Some(p) => ConditionVerdict::ClientDependent {
            how: format!("send the optional `{}` precondition on every request", p.name),
        },
        // Not `Failed`: a specification cannot say whether the effect depends
        // on server state. Only a probe can, which is the methodological
        // crux of the whole empirical half of this paper.
        None => ConditionVerdict::Unknown {
            why: "no precondition mechanism is described, and a specification cannot say whether the effect depends on server state".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(spec: &str) -> Classification {
        classify_spec(spec).unwrap().into_iter().next().unwrap()
    }

    fn spec_with(op: &str) -> String {
        format!(
            r#"{{"openapi":"3.0.3","info":{{"title":"t","version":"1"}},"paths":{{"/x":{{{op}}}}}}}"#
        )
    }

    const FULLY_PINNED: &str = r#""post":{
      "operationId":"op",
      "parameters":[
        {"name":"Idempotency-Key","in":"header","required":true,"schema":{"type":"string"}},
        {"name":"If-Match","in":"header","required":true,"schema":{"type":"string"}}],
      "requestBody":{"required":true,"content":{"application/json":{"schema":{
        "type":"object","additionalProperties":false,
        "required":["a"],"properties":{"a":{"type":"string"}}}}}}}"#;

    #[test]
    fn a_fully_pinned_operation_qualifies() {
        let c = one(&spec_with(FULLY_PINNED));
        assert_eq!(c.verdict, Verdict::Qualified);
        assert!(c.failing.is_empty());
        assert_eq!(c.evidence, Evidence::SpecDerived);
    }

    #[test]
    fn an_optional_idempotency_key_is_client_dependent_not_a_failure() {
        let op = FULLY_PINNED.replace(
            r#"{"name":"Idempotency-Key","in":"header","required":true"#,
            r#"{"name":"Idempotency-Key","in":"header","required":false"#,
        );
        let c = one(&spec_with(&op));
        assert_eq!(c.verdict, Verdict::Conditional);
        assert!(c.failing.is_empty(), "the client can still volunteer one");
    }

    #[test]
    fn a_post_with_no_idempotency_key_at_all_fails_c3() {
        let op = FULLY_PINNED.replace(
            r#"{"name":"Idempotency-Key","in":"header","required":true,"schema":{"type":"string"}},"#,
            "",
        );
        let c = one(&spec_with(&op));
        assert_eq!(c.verdict, Verdict::NonQualifying);
        assert!(
            c.failing.contains(&Condition::C3),
            "nothing the client can supply"
        );
    }

    #[test]
    fn a_put_is_idempotent_by_method_without_a_key() {
        let op = FULLY_PINNED.replace(r#""post":"#, r#""put":"#).replace(
            r#"{"name":"Idempotency-Key","in":"header","required":true,"schema":{"type":"string"}},"#,
            "",
        );
        let c = one(&spec_with(&op));
        assert_eq!(
            c.verdict,
            Verdict::Qualified,
            "RFC 9110 makes PUT idempotent"
        );
    }

    #[test]
    fn a_missing_state_pin_is_unknown_rather_than_failed() {
        // A specification cannot say whether the effect depends on server
        // state. Calling that a failure would assert more than the document
        // supports; calling it Unknown caps the result at Conditional.
        let op = FULLY_PINNED.replace(
            r#"{"name":"If-Match","in":"header","required":true,"schema":{"type":"string"}}"#,
            r#"{"name":"X-Trace","in":"header","required":false,"schema":{"type":"string"}}"#,
        );
        let c = one(&spec_with(&op));
        assert_eq!(c.verdict, Verdict::Conditional);
        assert!(matches!(
            c.verdict_for(Condition::C4),
            Some(ConditionVerdict::Unknown { .. })
        ));
    }

    #[test]
    fn a_documented_profile_default_fails_c1() {
        let op = FULLY_PINNED.replace(
            r#""a":{"type":"string"}"#,
            r#""a":{"type":"string","description":"When omitted, inherited from the user profile."}"#,
        );
        let c = one(&spec_with(&op));
        assert_eq!(c.verdict, Verdict::NonQualifying);
        assert!(c.failing.contains(&Condition::C1));
    }

    #[test]
    fn an_alias_segment_in_the_path_fails_c2() {
        let spec = format!(
            r#"{{"openapi":"3.0.3","info":{{"title":"t","version":"1"}},"paths":{{"/v1/users/me/send":{{{FULLY_PINNED}}}}}}}"#
        );
        let c = one(&spec);
        assert!(c.failing.contains(&Condition::C2));
        assert_eq!(c.verdict, Verdict::NonQualifying);
    }

    #[test]
    fn an_optional_property_with_a_default_is_client_dependent() {
        let op = FULLY_PINNED.replace(
            r#""required":["a"],"properties":{"a":{"type":"string"}}"#,
            r#""required":["a"],"properties":{"a":{"type":"string"},"b":{"type":"string","default":"x"}}"#,
        );
        let c = one(&spec_with(&op));
        assert_eq!(
            c.verdict,
            Verdict::Conditional,
            "the client can send `b` explicitly"
        );
        assert!(c.failing.is_empty());
    }

    #[test]
    fn a_verdict_names_every_condition_that_failed() {
        let c = one(&spec_with(r#""post":{"operationId":"bare"}"#));
        assert_eq!(c.verdict, Verdict::NonQualifying);
        assert!(!c.failing.is_empty());
        for cond in &c.failing {
            assert!(matches!(
                c.verdict_for(*cond),
                Some(ConditionVerdict::Failed { .. })
            ));
        }
    }

    #[test]
    fn an_optional_query_parameter_is_client_dependent_not_satisfied() {
        // P02's worked example is `POST /v1/transfer?to=…&fee_tier=priority`.
        // A C1 rule that read only the request body would call this operation
        // Satisfied — on the paper's own headline case.
        let op = FULLY_PINNED.replace(
            r#""parameters":[
        {"name":"Idempotency-Key""#,
            r#""parameters":[
        {"name":"fee_tier","in":"query","required":false,"schema":{"type":"string"}},
        {"name":"Idempotency-Key""#,
        );
        let c = one(&spec_with(&op));
        assert_eq!(c.verdict, Verdict::Conditional);
        let Some(ConditionVerdict::ClientDependent { how }) = c.verdict_for(Condition::C1) else {
            panic!(
                "C1 should be client-dependent, got {:?}",
                c.verdict_for(Condition::C1)
            );
        };
        assert!(
            how.contains("fee_tier"),
            "the parameter must be named: {how}"
        );
    }

    #[test]
    fn a_schema_behind_a_ref_is_resolved_and_not_silently_empty() {
        // Every real OpenAPI document does this. Unresolved, the classifier
        // sees no properties and collapses to Conditional without a word.
        // `r##"…"##`, not `r#"…"#`: a JSON pointer starts `"#/`, and that
        // `"#` would close an `r#` raw string in the middle of the document.
        let spec = r##"{"openapi":"3.0.3","info":{"title":"t","version":"1"},
          "paths":{"/x":{"post":{"operationId":"op",
            "parameters":[
              {"name":"Idempotency-Key","in":"header","required":true,"schema":{"type":"string"}},
              {"name":"If-Match","in":"header","required":true,"schema":{"type":"string"}}],
            "requestBody":{"required":true,"content":{"application/json":{
              "schema":{"$ref":"#/components/schemas/Body"}}}}}}},
          "components":{"schemas":{"Body":{"type":"object","additionalProperties":false,
            "required":["a"],"properties":{"a":{"type":"string"}}}}}}"##;
        assert_eq!(one(spec).verdict, Verdict::Qualified);
    }

    #[test]
    fn a_self_referential_ref_terminates() {
        let spec = r##"{"openapi":"3.0.3","info":{"title":"t","version":"1"},
          "paths":{"/x":{"post":{"operationId":"op",
            "requestBody":{"content":{"application/json":{
              "schema":{"$ref":"#/components/schemas/Node"}}}}}}},
          "components":{"schemas":{"Node":{"type":"object",
            "properties":{"child":{"$ref":"#/components/schemas/Node"}}}}}}"##;
        assert!(
            classify_spec(spec).is_ok(),
            "a legal recursive schema must not hang"
        );
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        for bad in [
            "",
            "{",
            "null",
            "[]",
            r#"{"paths":5}"#,
            r#"{"openapi":"3.0.3"}"#,
            // Swagger 2.0 is refused explicitly rather than misread as an
            // OpenAPI 3 document with no operations.
            r#"{"swagger":"2.0","paths":{}}"#,
            r#"{"paths":{"/x":{"post":{"parameters":"not an array"}}}}"#,
            r#"{"paths":{"/x":{"post":{"requestBody":{"content":{"application/json":{"schema":5}}}}}}}"#,
        ] {
            assert!(classify_spec(bad).is_err(), "expected an error for {bad:?}");
        }
    }
}
