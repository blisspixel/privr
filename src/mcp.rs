//! Model Context Protocol (stdio) server implementation.
//!
//! Provides a direct, synchronous JSON-RPC 2.0 stdio server conforming to the
//! Model Context Protocol (MCP) and the Agent Plugins specification.
//! Adheres to decisions 2, 4, 7, and 8 in `docs/DECISIONS.md`:
//! - Direct implementation over `serde_json` without an asynchronous runtime.
//! - Standard output carries protocol traffic only; diagnostics go to stderr.
//! - Read-only tools are always present. Mutating tools are absent from tool
//!   discovery unless `--allow-apply` is explicitly passed.

use serde_json::{Value, json};
use std::io::{BufRead, Write};

use crate::cli::Profile;

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "privr";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Run the stdio MCP server loop until stdin closes or an unrecoverable IO error occurs.
pub fn run_stdio(
    allow_apply: bool,
    input: impl BufRead,
    mut out: impl Write,
    mut err: impl Write,
) -> i32 {
    let _ = writeln!(
        err,
        "privr: starting stdio MCP server (version {SERVER_VERSION}, allow_apply={allow_apply})"
    );

    for line in input.lines() {
        let line = match line {
            Ok(l) => l,
            Err(e) => {
                let _ = writeln!(err, "privr: error reading stdin: {e}");
                return 1;
            }
        };

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(err, "privr: malformed json-rpc input: {e}");
                let error_response = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": {
                        "code": -32700,
                        "message": format!("Parse error: {e}")
                    }
                });
                let _ = writeln!(out, "{error_response}");
                let _ = out.flush();
                continue;
            }
        };

        if let Some(response) = handle_message(&request, allow_apply, &mut err) {
            if let Err(e) = writeln!(out, "{response}") {
                let _ = writeln!(err, "privr: failed to write to stdout: {e}");
                return 2;
            }
            let _ = out.flush();
        }
    }

    0
}

fn handle_message(req: &Value, allow_apply: bool, err: &mut impl Write) -> Option<Value> {
    let id = req.get("id");
    let method = match req.get("method").and_then(Value::as_str) {
        Some(m) => m,
        None => {
            // Notification or invalid format
            return None;
        }
    };

    // If there is no id, it is a notification (e.g. notifications/initialized)
    let req_id = id?.clone();

    let response_result = match method {
        "initialize" => handle_initialize(req.get("params")),
        "ping" => Ok(json!({})),
        "tools/list" => Ok(handle_tools_list(allow_apply)),
        "tools/call" => handle_tools_call(req.get("params"), allow_apply, err),
        "resources/list" => Ok(json!({ "resources": [] })),
        "prompts/list" => Ok(json!({ "prompts": [] })),
        other => Err((
            -32601,
            format!("The method {other} does not exist / is not implemented"),
        )),
    };

    match response_result {
        Ok(result) => Some(json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "result": result
        })),
        Err((code, message)) => Some(json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": code,
                "message": message
            }
        })),
    }
}

fn handle_initialize(_params: Option<&Value>) -> Result<Value, (i64, String)> {
    Ok(json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {
            "tools": {}
        },
        "serverInfo": {
            "name": SERVER_NAME,
            "version": SERVER_VERSION
        }
    }))
}

fn handle_tools_list(allow_apply: bool) -> Value {
    let mut tools = vec![
        json!({
            "name": "privr_status",
            "description": "Inspect host operating system facts, architecture, platform capability, and catalogue status.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        json!({
            "name": "privr_doctor",
            "description": "Run diagnostic capability, health, and storage integrity checks on the host environment.",
            "inputSchema": {
                "type": "object",
                "properties": {}
            }
        }),
        json!({
            "name": "privr_catalog",
            "description": "Search and inspect compiled privacy controls in the catalogue. Returns candidate control IDs, titles, sections, and summaries without modifying state.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Optional search term to filter controls by ID, title, section, or summary"
                    },
                    "platform": {
                        "type": "string",
                        "description": "Platform to list: auto, windows, macos, or linux (defaults to auto)"
                    }
                }
            }
        }),
        json!({
            "name": "privr_check",
            "description": "Evaluate host privacy settings against a profile (baseline, standard, strict). Returns structured findings and drift state.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "profile": {
                        "type": "string",
                        "description": "Policy profile to evaluate (baseline, standard, strict; default is baseline)",
                        "default": "baseline"
                    },
                    "all": {
                        "type": "boolean",
                        "description": "Include compliant controls alongside drifted controls (default is false)",
                        "default": false
                    },
                    "control": {
                        "type": "string",
                        "description": "Optional exact control ID or prefix filter"
                    }
                }
            }
        }),
        json!({
            "name": "privr_explain",
            "description": "Retrieve detailed privacy rationale, evidence, risk, tradeoff, mitigation, and primary vendor documentation for a control.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id": {
                        "type": "string",
                        "description": "Exact control ID (e.g. windows.browser.edge.telemetry, windows.storage.thumbnail-cache)"
                    }
                },
                "required": ["id"]
            }
        }),
        json!({
            "name": "privr_plan",
            "description": "Show exact proposed changes for drifted controls without modifying machine state.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "profile": {
                        "type": "string",
                        "description": "Policy profile to plan (baseline, standard, strict; default is baseline)",
                        "default": "baseline"
                    },
                    "control": {
                        "type": "string",
                        "description": "Optional exact control ID or prefix filter"
                    }
                }
            }
        }),
    ];

    if allow_apply {
        tools.push(json!({
            "name": "privr_apply",
            "description": "Apply and verify supported changes for drifted controls, recording prior values in the transaction journal.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "profile": {
                        "type": "string",
                        "description": "Policy profile to apply (default is baseline)",
                        "default": "baseline"
                    },
                    "yes": {
                        "type": "boolean",
                        "description": "Explicit confirmation to apply changes"
                    },
                    "control": {
                        "type": "string",
                        "description": "Optional exact control ID or prefix filter"
                    }
                },
                "required": ["yes"]
            }
        }));

        tools.push(json!({
            "name": "privr_rollback",
            "description": "Restore prior settings recorded in a transaction journal.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "transaction_id": {
                        "type": "string",
                        "description": "Transaction identifier recorded in history"
                    },
                    "yes": {
                        "type": "boolean",
                        "description": "Explicit confirmation to rollback"
                    }
                },
                "required": ["transaction_id", "yes"]
            }
        }));
    }

    json!({ "tools": tools })
}

fn handle_tools_call(
    params: Option<&Value>,
    allow_apply: bool,
    _err: &mut impl Write,
) -> Result<Value, (i64, String)> {
    let params = params.ok_or((-32602, "Missing params".to_owned()))?;
    let name = params
        .get("name")
        .and_then(Value::as_str)
        .ok_or((-32602, "Missing tool name".to_owned()))?;
    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or_else(|| json!({}));

    match name {
        "privr_status" => {
            let host = crate::platform::discover();
            let all_controls = crate::catalog::all();
            let arch_str = match host.architecture.known() {
                Some(crate::model::host::Architecture::X86) => "x86",
                Some(crate::model::host::Architecture::X86_64) => "x86_64",
                Some(crate::model::host::Architecture::Aarch64) => "aarch64",
                Some(crate::model::host::Architecture::Other) => "other",
                None => "unknown",
            };
            let status = json!({
                "platform": host.platform.as_str(),
                "architecture": arch_str,
                "version": host.version.known().map(|v| v.display.as_str()).unwrap_or("unknown"),
                "edition": host.edition.known().map(|e| e.as_str()).unwrap_or("unknown"),
                "catalogue_controls_count": all_controls.len(),
                "offline_guarantee": true
            });
            tool_success(serde_json::to_string_pretty(&status).unwrap_or_default())
        }
        "privr_doctor" => {
            let host = crate::platform::discover();
            let report = crate::doctor::diagnose(&host);
            tool_success(serde_json::to_string_pretty(&report).unwrap_or_default())
        }
        "privr_catalog" => {
            let query = arguments.get("query").and_then(Value::as_str);
            let manifest = crate::manifest::Manifest::build(query);
            tool_success(serde_json::to_string_pretty(&manifest).unwrap_or_default())
        }
        "privr_check" => {
            let profile_str = arguments
                .get("profile")
                .and_then(Value::as_str)
                .unwrap_or("baseline");
            let profile = parse_profile(profile_str)?;
            let host = crate::platform::discover();
            let mut report = crate::report::Report::build(&host, profile.as_str());

            if let Some(filter) = arguments.get("control").and_then(Value::as_str) {
                report
                    .results
                    .retain(|r| r.id == filter || r.id.starts_with(filter));
            }
            if !arguments
                .get("all")
                .and_then(Value::as_bool)
                .unwrap_or(false)
            {
                report
                    .results
                    .retain(|r| r.outcome != crate::model::outcome::Outcome::Pass);
            }

            tool_success(serde_json::to_string_pretty(&report).unwrap_or_default())
        }
        "privr_explain" => {
            let id = arguments
                .get("id")
                .and_then(Value::as_str)
                .ok_or((-32602, "Missing required argument 'id'".to_owned()))?;

            match crate::explain::find(id) {
                Ok(control) => {
                    let host = crate::platform::discover();
                    let resolution = control.observe(&crate::catalog::Context::live(&host));
                    let explanation = json!({
                        "id": control.spec.id,
                        "title": control.title,
                        "section": control.spec.section,
                        "summary": control.summary,
                        "rationale": control.rationale,
                        "tradeoff": control.tradeoff,
                        "mitigation": control.mitigation,
                        "state": resolution.state.map(|s| s.0),
                        "sources": control.sources.iter().map(|s| json!({
                            "url": s.url,
                            "claim": s.claim,
                            "reviewed": s.reviewed
                        })).collect::<Vec<_>>()
                    });
                    tool_success(serde_json::to_string_pretty(&explanation).unwrap_or_default())
                }
                Err(_) => {
                    let suggestions = crate::explain::suggestions(id);
                    let err_msg = if suggestions.is_empty() {
                        format!("Control '{id}' not found.")
                    } else {
                        format!(
                            "Control '{id}' not found. Did you mean: {}?",
                            suggestions.join(", ")
                        )
                    };
                    tool_error(err_msg)
                }
            }
        }
        "privr_plan" => {
            let profile_str = arguments
                .get("profile")
                .and_then(Value::as_str)
                .unwrap_or("baseline");
            let profile = parse_profile(profile_str)?;
            let host = crate::platform::discover();
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();
            let filter = arguments.get("control").and_then(Value::as_str);

            let mut planned = Vec::new();
            let mut unautomated_drift = 0;
            for c in &all_controls {
                if let Some(f) = filter
                    && c.spec.id != f
                    && !c.spec.id.starts_with(f)
                {
                    continue;
                }
                let resolution = c.observe(&context);
                let eval = crate::engine::evaluate::evaluate(
                    &c.spec,
                    crate::engine::evaluate::Mode::Enforce,
                    &resolution,
                    &host,
                    crate::model::outcome::Exception::None,
                );
                if eval.outcome == crate::model::outcome::Outcome::Drift {
                    if eval.remediation == crate::model::outcome::Remediation::Automatic
                        && c.apply.is_some()
                    {
                        let current_str = resolution
                            .state
                            .map(|s| s.0)
                            .unwrap_or_else(|| "drift".to_owned());
                        planned.push(json!({
                            "id": c.spec.id,
                            "title": c.title,
                            "section": c.spec.section,
                            "current": current_str,
                            "desired": c.spec.desired.0
                        }));
                    } else {
                        unautomated_drift += 1;
                    }
                }
            }

            let report = json!({
                "schema": 1,
                "profile": profile.as_str(),
                "platform": host.platform.as_str(),
                "planned_changes": planned.len(),
                "unautomated_drift": unautomated_drift,
                "changes": planned
            });
            tool_success(serde_json::to_string_pretty(&report).unwrap_or_default())
        }
        "privr_apply" => {
            if !allow_apply {
                return tool_error(
                    "Tool 'privr_apply' is not available. The server must be launched with --allow-apply.".to_owned(),
                );
            }
            let confirmed = arguments
                .get("yes")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !confirmed {
                return tool_error(
                    "Confirmation required: 'yes': true must be provided to apply changes."
                        .to_owned(),
                );
            }
            let profile_str = arguments
                .get("profile")
                .and_then(Value::as_str)
                .unwrap_or("baseline");
            let profile = parse_profile(profile_str)?;
            let host = crate::platform::discover();
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();
            let filter = arguments.get("control").and_then(Value::as_str);

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let timestamp = format!("{}.{:03}", now.as_secs(), now.subsec_millis());
            let tx_id = format!("tx-{}-{}", now.as_secs(), now.subsec_millis());
            let mut journal = crate::journal::TransactionJournal {
                schema: crate::journal::JOURNAL_SCHEMA,
                transaction_id: tx_id.clone(),
                timestamp: timestamp.clone(),
                platform: host.platform.as_str().to_owned(),
                profile: profile.as_str().to_owned(),
                operations: Vec::new(),
            };

            if let Err(e) = crate::journal::save_transaction(&journal) {
                return tool_error(format!("Failed to initialize transaction journal: {e}"));
            }

            for c in &all_controls {
                if let Some(f) = filter
                    && c.spec.id != f
                    && !c.spec.id.starts_with(f)
                {
                    continue;
                }
                let resolution = c.observe(&context);
                let eval = crate::engine::evaluate::evaluate(
                    &c.spec,
                    crate::engine::evaluate::Mode::Enforce,
                    &resolution,
                    &host,
                    crate::model::outcome::Exception::None,
                );
                if eval.outcome == crate::model::outcome::Outcome::Drift
                    && eval.remediation == crate::model::outcome::Remediation::Automatic
                    && c.apply.is_some()
                {
                    match c.apply(&context) {
                        Some(Ok(op)) => {
                            journal.operations.push(crate::journal::OperationJournal {
                                control_id: c.spec.id.clone(),
                                target_key: op.target_key,
                                preimage: op.preimage,
                                postimage: op.postimage,
                                verified: true,
                            });
                            if let Err(e) = crate::journal::save_transaction(&journal) {
                                return tool_error(format!(
                                    "Fatal error writing transaction journal: {e}. Applied {} change(s). Halting apply.",
                                    journal.operations.len()
                                ));
                            }
                        }
                        Some(Err(e)) => {
                            return tool_error(format!(
                                "Failed to apply {}: {e}. Applied {} prior changes (tx: {}).",
                                c.spec.id,
                                journal.operations.len(),
                                tx_id
                            ));
                        }
                        None => {}
                    }
                }
            }

            if journal.operations.is_empty() {
                let initial_path = crate::journal::transactions_dir().join(format!("{tx_id}.json"));
                let _ = std::fs::remove_file(initial_path);
            }

            let report = json!({
                "schema": 1,
                "profile": profile.as_str(),
                "platform": host.platform.as_str(),
                "transaction_id": tx_id,
                "applied_changes": journal.operations.len()
            });
            tool_success(serde_json::to_string_pretty(&report).unwrap_or_default())
        }
        "privr_rollback" => {
            if !allow_apply {
                return tool_error(
                    "Tool 'privr_rollback' is not available. The server must be launched with --allow-apply.".to_owned(),
                );
            }
            let confirmed = arguments
                .get("yes")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !confirmed {
                return tool_error(
                    "Confirmation required: 'yes': true must be provided to rollback transaction."
                        .to_owned(),
                );
            }
            let tx_id = arguments
                .get("transaction_id")
                .and_then(Value::as_str)
                .ok_or((-32602, "Missing transaction_id".to_owned()))?;

            if !crate::journal::is_valid_transaction_id(tx_id) {
                return tool_error(format!("Invalid transaction identifier '{tx_id}'."));
            }

            let journal = match crate::journal::load_transaction(tx_id) {
                Ok(j) => j,
                Err(e) => {
                    return tool_error(format!("Transaction '{tx_id}' not found: {e}"));
                }
            };

            let host = crate::platform::discover();
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();
            let mut restored = 0;

            for op in journal.operations.iter().rev() {
                if let Some(c) = all_controls
                    .iter()
                    .find(|item| item.spec.id == op.control_id)
                {
                    match c.rollback(&context, &op.preimage, &op.postimage) {
                        Some(Ok(())) => {
                            restored += 1;
                        }
                        Some(Err(e)) => {
                            return tool_error(format!(
                                "Conflict during rollback of {}: {e}. Restored {} operations.",
                                c.spec.id, restored
                            ));
                        }
                        None => {}
                    }
                }
            }

            let report = json!({
                "schema": 1,
                "transaction_id": tx_id,
                "restored_changes": restored
            });
            tool_success(serde_json::to_string_pretty(&report).unwrap_or_default())
        }
        unknown => Err((-32601, format!("Unknown tool '{unknown}'"))),
    }
}

fn tool_success(text: String) -> Result<Value, (i64, String)> {
    Ok(json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "isError": false
    }))
}

fn tool_error(text: String) -> Result<Value, (i64, String)> {
    Ok(json!({
        "content": [
            {
                "type": "text",
                "text": text
            }
        ],
        "isError": true
    }))
}

fn parse_profile(p: &str) -> Result<Profile, (i64, String)> {
    match p.to_ascii_lowercase().as_str() {
        "baseline" => Ok(Profile::Baseline),
        "strict" => Ok(Profile::Strict),
        "restrictive" => Ok(Profile::Restrictive),
        other => Err((
            -32602,
            format!("Invalid profile '{other}'; must be baseline, strict, or restrictive"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_returns_protocol_version_and_tools_capability() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05"
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&req, false, &mut err).expect("response");
        assert_eq!(resp["id"], 1);
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
        assert_eq!(resp["result"]["serverInfo"]["name"], SERVER_NAME);
    }

    #[test]
    fn tools_list_hides_mutating_tools_when_disallowed() {
        let tools = handle_tools_list(false);
        let list = tools["tools"].as_array().expect("tools array");
        let names: Vec<&str> = list
            .iter()
            .map(|t| t["name"].as_str().expect("name"))
            .collect();
        assert!(names.contains(&"privr_status"));
        assert!(names.contains(&"privr_doctor"));
        assert!(names.contains(&"privr_catalog"));
        assert!(names.contains(&"privr_check"));
        assert!(names.contains(&"privr_explain"));
        assert!(names.contains(&"privr_plan"));
        assert!(!names.contains(&"privr_apply"));
        assert!(!names.contains(&"privr_rollback"));
    }

    #[test]
    fn tools_list_exposes_mutating_tools_when_allowed() {
        let tools = handle_tools_list(true);
        let list = tools["tools"].as_array().expect("tools array");
        let names: Vec<&str> = list
            .iter()
            .map(|t| t["name"].as_str().expect("name"))
            .collect();
        assert!(names.contains(&"privr_apply"));
        assert!(names.contains(&"privr_rollback"));
    }

    #[test]
    fn explain_tool_returns_structured_sources_and_rationale() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "privr_catalog",
                "arguments": {
                    "query": "thumbnail"
                }
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&req, false, &mut err).expect("response");
        assert_eq!(resp["id"], 42);
        let content_text = resp["result"]["content"][0]["text"].as_str().expect("text");
        assert!(content_text.contains("thumbnail"));
    }

    #[test]
    fn privr_status_returns_facts() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "privr_status"
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&req, false, &mut err).expect("response");
        assert_eq!(resp["id"], 2);
        let text = resp["result"]["content"][0]["text"].as_str().expect("text");
        assert!(text.contains("platform"));
    }

    #[test]
    fn privr_doctor_returns_health_report() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "privr_doctor"
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&req, false, &mut err).expect("response");
        assert_eq!(resp["id"], 10);
        let text = resp["result"]["content"][0]["text"].as_str().expect("text");
        assert!(text.contains("\"healthy\": true"));
        assert!(text.contains("\"storage\""));
    }

    #[test]
    fn privr_check_evaluates_profiles() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "privr_check",
                "arguments": {
                    "profile": "baseline",
                    "all": true
                }
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&req, false, &mut err).expect("response");
        assert_eq!(resp["id"], 3);
        let text = resp["result"]["content"][0]["text"].as_str().expect("text");
        assert!(text.contains("results"));
    }

    #[test]
    fn privr_explain_handles_unknown_id() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "privr_explain",
                "arguments": {
                    "id": "completely.unknown.control"
                }
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&req, false, &mut err).expect("response");
        assert_eq!(resp["id"], 4);
        assert_eq!(resp["result"]["isError"], true);
    }

    #[test]
    fn privr_plan_returns_change_set() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "privr_plan",
                "arguments": {
                    "profile": "strict"
                }
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&req, false, &mut err).expect("response");
        assert_eq!(resp["id"], 5);
        let text = resp["result"]["content"][0]["text"].as_str().expect("text");
        assert!(text.contains("planned_changes"));
    }

    #[test]
    fn privr_apply_requires_allow_apply_and_confirmation() {
        // Disallowed
        let req = json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "privr_apply",
                "arguments": { "yes": true }
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&req, false, &mut err).expect("response");
        assert_eq!(resp["result"]["isError"], true);

        // Allowed but unconfirmed
        let req_unconfirmed = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "privr_apply",
                "arguments": { "yes": false }
            }
        });
        let resp2 = handle_message(&req_unconfirmed, true, &mut err).expect("response");
        assert_eq!(resp2["result"]["isError"], true);
    }

    #[test]
    fn privr_rollback_requires_allow_apply_and_confirmation() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "privr_rollback",
                "arguments": { "transaction_id": "tx-fake", "yes": true }
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&req, false, &mut err).expect("response");
        assert_eq!(resp["result"]["isError"], true);

        // Unconfirmed
        let req_unconfirmed = json!({
            "jsonrpc": "2.0",
            "id": 9,
            "method": "tools/call",
            "params": {
                "name": "privr_rollback",
                "arguments": { "transaction_id": "tx-fake", "yes": false }
            }
        });
        let resp2 = handle_message(&req_unconfirmed, true, &mut err).expect("response");
        assert_eq!(resp2["result"]["isError"], true);

        // Confirmed but nonexistent transaction
        let resp3 = handle_message(&req, true, &mut err).expect("response");
        assert_eq!(resp3["result"]["isError"], true);
    }

    #[test]
    fn unknown_tool_returns_error() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "unknown_tool_name"
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&req, false, &mut err).expect("response");
        assert!(resp["error"].is_object());
    }

    #[test]
    fn protocol_notifications_and_methods() {
        let mut err = Vec::new();
        // ping
        let ping_req = json!({ "jsonrpc": "2.0", "id": 11, "method": "ping" });
        let resp = handle_message(&ping_req, false, &mut err).expect("response");
        assert_eq!(resp["result"], json!({}));

        // resources & prompts
        let res_req = json!({ "jsonrpc": "2.0", "id": 12, "method": "resources/list" });
        let resp_res = handle_message(&res_req, false, &mut err).expect("response");
        assert!(resp_res["result"]["resources"].is_array());

        let prompt_req = json!({ "jsonrpc": "2.0", "id": 13, "method": "prompts/list" });
        let resp_prompt = handle_message(&prompt_req, false, &mut err).expect("response");
        assert!(resp_prompt["result"]["prompts"].is_array());

        // notification without id
        let notif = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(handle_message(&notif, false, &mut err).is_none());

        // unknown method
        let unk_req = json!({ "jsonrpc": "2.0", "id": 14, "method": "nonexistent" });
        let resp_unk = handle_message(&unk_req, false, &mut err).expect("response");
        assert!(resp_unk["error"].is_object());
    }

    #[test]
    fn parse_profile_validation() {
        assert_eq!(parse_profile("baseline").unwrap(), Profile::Baseline);
        assert_eq!(parse_profile("strict").unwrap(), Profile::Strict);
        assert_eq!(parse_profile("restrictive").unwrap(), Profile::Restrictive);
        assert!(parse_profile("invalid").is_err());
    }

    #[test]
    fn run_stdio_processes_lines() {
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\n\n{\"invalid json\n";
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = run_stdio(false, input.as_bytes(), &mut out, &mut err);
        assert_eq!(code, 0);
        let out_str = String::from_utf8(out).expect("utf8 stdout");
        assert!(out_str.contains("\"id\":1"));
        assert!(out_str.contains("Parse error"));
    }
}
