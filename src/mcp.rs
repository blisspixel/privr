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
use crate::model::posture::{FrictionTier, WorkloadPersona};

const PROTOCOL_VERSION: &str = "2024-11-05";
const SERVER_NAME: &str = "privr";
const SERVER_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Eq, PartialEq)]
enum ElevationDecision {
    NotRequired,
    Defer,
    Refuse,
}

fn automatic_elevation_decision(
    control: &crate::catalog::Control,
    result: &crate::model::outcome::ControlResult,
    elevated: bool,
    explicit: bool,
) -> ElevationDecision {
    use crate::model::outcome::{Outcome, Remediation};
    if elevated
        || !control.requires_elevation()
        || control.apply.is_none()
        || result.outcome != Outcome::Drift
        || result.remediation != Remediation::Automatic
    {
        ElevationDecision::NotRequired
    } else if explicit {
        ElevationDecision::Refuse
    } else {
        ElevationDecision::Defer
    }
}

/// Run the stdio MCP server loop until stdin closes or an unrecoverable IO error occurs.
pub fn run_stdio(allow_apply: bool, input: impl BufRead, out: impl Write, err: impl Write) -> i32 {
    run_stdio_with_check_context(allow_apply, input, out, err, None)
}

fn run_stdio_with_check_context(
    allow_apply: bool,
    input: impl BufRead,
    mut out: impl Write,
    mut err: impl Write,
    check_context: Option<&crate::catalog::Context>,
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

        let response = if check_context.is_some() {
            handle_message_with_check_context(&request, allow_apply, &mut err, check_context)
        } else {
            handle_message(&request, allow_apply, &mut err)
        };
        if let Some(response) = response {
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
    handle_message_with_check_context(req, allow_apply, err, None)
}

fn handle_message_with_check_context(
    req: &Value,
    allow_apply: bool,
    err: &mut impl Write,
    check_context: Option<&crate::catalog::Context>,
) -> Option<Value> {
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
        "tools/call" => {
            handle_tools_call_with_check_context(req.get("params"), allow_apply, err, check_context)
        }
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
            "description": "Report host facts, compiled adapters, and transaction storage checks. Compiled interfaces and successful storage checks do not attest live host capabilities.",
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
                    },
                    "section": {
                        "type": "string",
                        "description": "Optional section filter"
                    },
                    "policy": {
                        "type": "string",
                        "description": "Optional file path or TOML/JSON string of a custom policy"
                    },
                    "compare": {
                        "type": "string",
                        "description": "Optional file path or JSON string of a saved prior report to compare against and detect update regressions"
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
                    "workload": {
                        "type": "string",
                        "description": "Optional workload persona to plan recommendations for: general, developer, creative, mobile, or high-assurance",
                        "enum": ["general", "developer", "creative", "mobile", "high-assurance"]
                    },
                    "max_friction": {
                        "type": "string",
                        "description": "Optional maximum tolerable friction tier: tier0-transparent, tier1-cosmetic, tier2-workflow-altering, or tier3-incompatible-or-tradeoff",
                        "enum": ["tier0-transparent", "tier1-cosmetic", "tier2-workflow-altering", "tier3-incompatible-or-tradeoff"]
                    },
                    "control": {
                        "type": "string",
                        "description": "Optional exact control ID or prefix filter"
                    },
                    "section": {
                        "type": "string",
                        "description": "Optional section filter"
                    },
                    "policy": {
                        "type": "string",
                        "description": "Optional file path or TOML/JSON string of a custom policy"
                    }
                }
            }
        }),
        json!({
            "name": "privr_recommend",
            "description": "Recommend confirmed drift across the full eligible compiled catalogue and all profiles, filtered by workload, optional friction ceiling, and dimension. An empty list does not establish compliance; unknown, unchecked, and filtered controls remain unverified.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "workload": {
                        "type": "string",
                        "description": "Workload persona: general, developer, creative, mobile, or high-assurance (default: general)",
                        "enum": ["general", "developer", "creative", "mobile", "high-assurance"],
                        "default": "general"
                    },
                    "max_friction": {
                        "type": "string",
                        "description": "Optional maximum tolerable friction tier: tier0-transparent, tier1-cosmetic, tier2-workflow-altering, or tier3-incompatible-or-tradeoff",
                        "enum": ["tier0-transparent", "tier1-cosmetic", "tier2-workflow-altering", "tier3-incompatible-or-tradeoff"]
                    },
                    "dimension": {
                        "type": "string",
                        "description": "Optional posture dimension to restrict recommendations to: behavioral-commercial, forensic-residue, network-exposure, diagnostic-crash, or ambient-sensor",
                        "enum": ["behavioral-commercial", "forensic-residue", "network-exposure", "diagnostic-crash", "ambient-sensor"]
                    }
                }
            }
        }),
        json!({
            "name": "privr_simulate",
            "description": "Counterfactually simulate applying a profile or controls without modifying machine state. Returns projected posture vector, friction breakdown, and reboot/signout requirements.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "profile": {
                        "type": "string",
                        "description": "Policy profile to simulate (baseline, standard, strict; default is baseline)",
                        "default": "baseline"
                    },
                    "policy": {
                        "type": "string",
                        "description": "Optional file path or TOML/JSON string of a custom policy"
                    },
                    "control": {
                        "type": "string",
                        "description": "Optional exact control ID or prefix filter"
                    },
                    "section": {
                        "type": "string",
                        "description": "Optional section name filter"
                    }
                }
            }
        }),
        json!({
            "name": "privr_history",
            "description": "Show chronological transaction history of applied changes, or purge transaction records.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "purge": {
                        "type": "boolean",
                        "description": "Purge and destroy all saved transaction history files (requires --allow-apply and 'yes': true)",
                        "default": false
                    },
                    "yes": {
                        "type": "boolean",
                        "description": "Explicit confirmation to purge transaction history"
                    }
                }
            }
        }),
        json!({
            "name": "privr_clean",
            "description": "Preview or clean disposable caches, temporary files, activity residue, and issue hardware SSD TRIM.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "dry_run": {
                        "type": "boolean",
                        "description": "Preview targets, file counts, and byte sizes without mutating (default is true)",
                        "default": true
                    },
                    "polite": {
                        "type": "boolean",
                        "description": "Retain disruptive or costly-to-rebuild caches such as thumbnail cache and recent items",
                        "default": false
                    },
                    "category": {
                        "type": "string",
                        "description": "Filter by residue category: system, browsers, ai, dev, recent, all"
                    },
                    "control": {
                        "type": "string",
                        "description": "Optional exact residue target ID or prefix filter"
                    },
                    "trim": {
                        "type": "boolean",
                        "description": "Check TRIM support or execute hardware TRIM/Deallocate on solid-state drives",
                        "default": false
                    },
                    "yes": {
                        "type": "boolean",
                        "description": "Explicit confirmation to purge residue (required when dry_run is false)"
                    },
                    "accept_risk": {
                        "type": "string",
                        "description": "Optional comma-separated list of residue target IDs to accept risk"
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
                    "workload": {
                        "type": "string",
                        "description": "Optional workload persona to apply recommendations for: general, developer, creative, mobile, or high-assurance",
                        "enum": ["general", "developer", "creative", "mobile", "high-assurance"]
                    },
                    "max_friction": {
                        "type": "string",
                        "description": "Optional maximum tolerable friction tier: tier0-transparent, tier1-cosmetic, tier2-workflow-altering, or tier3-incompatible-or-tradeoff",
                        "enum": ["tier0-transparent", "tier1-cosmetic", "tier2-workflow-altering", "tier3-incompatible-or-tradeoff"]
                    },
                    "policy": {
                        "type": "string",
                        "description": "Optional file path or TOML/JSON string of a custom policy"
                    },
                    "accept_risk": {
                        "type": "string",
                        "description": "Optional comma-separated list of control IDs or 'all' to accept risk for high-friction controls"
                    },
                    "yes": {
                        "type": "boolean",
                        "description": "Explicit confirmation to apply changes"
                    },
                    "control": {
                        "type": "string",
                        "description": "Optional exact control ID or prefix filter"
                    },
                    "section": {
                        "type": "string",
                        "description": "Optional section filter"
                    },
                    "elevate": {
                        "type": "boolean",
                        "description": "Request elevation (UAC on Windows, sudo on Unix) to apply machine-scope changes in-place"
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
                    "section": {
                        "type": "string",
                        "description": "Optional section name or prefix to filter rollback operations"
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

fn handle_tools_call_with_check_context(
    params: Option<&Value>,
    allow_apply: bool,
    _err: &mut impl Write,
    check_context: Option<&crate::catalog::Context>,
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
            let controls: Vec<String> = arguments
                .get("control")
                .and_then(Value::as_str)
                .map(|s| vec![s.to_owned()])
                .unwrap_or_default();
            let sections: Vec<String> = arguments
                .get("section")
                .and_then(Value::as_str)
                .map(|s| vec![s.to_owned()])
                .unwrap_or_default();
            let loaded_policy = if let Some(pol_arg) =
                arguments.get("policy").and_then(Value::as_str)
            {
                let pol = if pol_arg.trim_start().starts_with('{') || pol_arg.contains("schema =") {
                    pol_arg
                        .parse::<crate::policy::CustomPolicy>()
                        .map_err(|e| (-32602, e))?
                } else {
                    let path = std::path::Path::new(pol_arg);
                    crate::policy::CustomPolicy::from_file(path).map_err(|e| (-32602, e))?
                };
                Some(pol)
            } else {
                None
            };
            let mut report = if let Some(pol) = &loaded_policy {
                let host = crate::platform::discover();
                let context = crate::catalog::Context::live(&host);
                crate::report::Report::build_with_policy(&context, pol, &controls, &sections)
            } else if let Some(context) = check_context {
                crate::report::Report::build_with_context(
                    context,
                    Some(profile.as_str()),
                    None,
                    &controls,
                    &sections,
                )
            } else {
                let host = crate::platform::discover();
                crate::report::Report::build_filtered(&host, profile.as_str(), &controls, &sections)
            };
            if let Some(compare_val) = arguments.get("compare").and_then(Value::as_str) {
                let prior_report: crate::report::Report =
                    if compare_val.trim_start().starts_with('{') {
                        serde_json::from_str(compare_val).map_err(|e| {
                            (-32602, format!("Malformed comparison report JSON: {e}"))
                        })?
                    } else {
                        let path = std::path::PathBuf::from(compare_val);
                        let content = std::fs::read_to_string(&path).map_err(|e| {
                            (
                                -32602,
                                format!("Cannot read comparison report file '{compare_val}': {e}"),
                            )
                        })?;
                        serde_json::from_str(&content).map_err(|e| {
                            (
                                -32602,
                                format!("Malformed comparison report JSON in '{compare_val}': {e}"),
                            )
                        })?
                    };
                let comparison = crate::report::compare_reports(&prior_report, &report);
                return tool_success(serde_json::to_string_pretty(&comparison).unwrap_or_default());
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
                        "profile": control.spec.min_profile.as_str(),
                        "summary": control.summary,
                        "rationale": control.rationale,
                        "tradeoff": control.tradeoff,
                        "mitigation": control.mitigation,
                        "state": resolution.state.map(|s| s.0),
                        "evidence": "fresh",
                        "reconstructed_check": false,
                        "note": "This is a fresh reading of the machine. It does not reconstruct an earlier check.",
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
            let host = crate::platform::discover();
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();
            let filter = arguments.get("control").and_then(Value::as_str);
            let section_filter = arguments.get("section").and_then(Value::as_str);

            let workload = match arguments.get("workload").and_then(Value::as_str) {
                Some(w) => Some(parse_workload(w)?),
                None => None,
            };
            let max_friction = match arguments.get("max_friction").and_then(Value::as_str) {
                Some(f) => Some(parse_max_friction(f)?),
                None => None,
            };

            let profile_str = arguments
                .get("profile")
                .and_then(Value::as_str)
                .unwrap_or("baseline");
            let profile = parse_profile(profile_str)?;

            let recommended_ids: Option<std::collections::BTreeSet<String>> = workload.map(|w| {
                crate::engine::recommend::generate_recommendations(
                    &all_controls,
                    &context,
                    &host,
                    w,
                    max_friction,
                    None,
                )
                .into_iter()
                .map(|r| r.control_id)
                .collect()
            });

            let loaded_policy = if let Some(pol_arg) =
                arguments.get("policy").and_then(Value::as_str)
            {
                let pol = if pol_arg.trim_start().starts_with('{') || pol_arg.contains("schema =") {
                    pol_arg
                        .parse::<crate::policy::CustomPolicy>()
                        .map_err(|e| (-32602, e))?
                } else {
                    let path = std::path::Path::new(pol_arg);
                    crate::policy::CustomPolicy::from_file(path).map_err(|e| (-32602, e))?
                };
                Some(pol)
            } else {
                None
            };
            let plan_profile = if let Some(pol) = &loaded_policy {
                pol.extends
            } else {
                profile
            };
            let today = crate::policy::today_iso();

            let mut planned = Vec::new();
            let mut unautomated_drift = 0;
            let mut requires_elevation_drift = 0;
            for c in &all_controls {
                if let Some(f) = filter
                    && c.spec.id != f
                    && !c.spec.id.starts_with(f)
                {
                    continue;
                }
                if let Some(s) = section_filter
                    && !c.spec.section.eq_ignore_ascii_case(s)
                    && !c
                        .spec
                        .section
                        .to_ascii_lowercase()
                        .starts_with(&s.to_ascii_lowercase())
                {
                    continue;
                }
                if let Some(recs) = &recommended_ids
                    && !recs.contains(&c.spec.id)
                {
                    continue;
                }
                let mut spec_clone = c.spec.clone();
                let override_opt = loaded_policy
                    .as_ref()
                    .and_then(|pol| pol.controls.get(&c.spec.id));
                if let Some(ov) = override_opt
                    && let Some(desired_val) = &ov.desired
                {
                    spec_clone.desired = crate::engine::evaluate::SemanticState::new(desired_val);
                }
                let resolution = c.observe(&context);
                let mode = if let Some(ov) = override_opt
                    && let Some(m) = ov.mode
                {
                    m
                } else if filter.is_some()
                    || recommended_ids.is_some()
                    || c.spec.min_profile <= plan_profile
                {
                    crate::engine::evaluate::Mode::Enforce
                } else {
                    crate::engine::evaluate::Mode::Ignore
                };

                let exception = if let Some(pol) = &loaded_policy {
                    if let Some(ex) = pol.exceptions.iter().find(|e| e.control == c.spec.id) {
                        if resolution.state.as_ref().map(|s| s.0.as_str()) == Some(&ex.accepted) {
                            ex.status(&today)
                        } else {
                            crate::model::outcome::Exception::None
                        }
                    } else {
                        crate::model::outcome::Exception::None
                    }
                } else {
                    crate::model::outcome::Exception::None
                };

                let eval = crate::engine::evaluate::evaluate(
                    &spec_clone,
                    mode,
                    &resolution,
                    &host,
                    exception,
                );
                if eval.outcome == crate::model::outcome::Outcome::Drift {
                    if eval.exception == crate::model::outcome::Exception::Active {
                        continue;
                    }
                    if eval.remediation == crate::model::outcome::Remediation::Automatic
                        && c.apply.is_some()
                    {
                        if c.spec.requires_elevation
                            && host.elevated == crate::model::host::Fact::Known(false)
                        {
                            requires_elevation_drift += 1;
                        }
                        let current_str = resolution
                            .state
                            .map(|s| s.0)
                            .unwrap_or_else(|| "drift".to_owned());
                        planned.push(json!({
                            "id": c.spec.id,
                            "title": c.title,
                            "section": c.spec.section,
                            "current": current_str,
                            "desired": spec_clone.desired.0,
                            "requires_elevation": c.spec.requires_elevation
                        }));
                    } else {
                        unautomated_drift += 1;
                    }
                }
            }

            let profile_name = if let Some(pol) = &loaded_policy {
                format!("custom (extends {})", pol.extends)
            } else if let Some(w) = workload {
                format!("workload:{}", w.as_str())
            } else {
                profile.as_str().to_owned()
            };

            let report = json!({
                "schema": 1,
                "profile": profile_name,
                "workload": workload.map(|w| w.as_str()),
                "platform": host.platform.as_str(),
                "planned_changes": planned.len(),
                "unautomated_drift": unautomated_drift,
                "requires_elevation_drift": requires_elevation_drift,
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
            let host = crate::platform::discover();
            let is_elevated = host.elevated == crate::model::host::Fact::Known(true);
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();
            let filter = arguments.get("control").and_then(Value::as_str);
            let section_filter = arguments.get("section").and_then(Value::as_str);
            let elevate = arguments
                .get("elevate")
                .and_then(Value::as_bool)
                .unwrap_or(false);

            let loaded_policy = if let Some(pol_arg) =
                arguments.get("policy").and_then(Value::as_str)
            {
                let pol = if pol_arg.trim_start().starts_with('{') || pol_arg.contains("schema =") {
                    pol_arg
                        .parse::<crate::policy::CustomPolicy>()
                        .map_err(|e| (-32602, e))?
                } else {
                    let path = std::path::Path::new(pol_arg);
                    crate::policy::CustomPolicy::from_file(path).map_err(|e| (-32602, e))?
                };
                Some(pol)
            } else {
                None
            };

            let accept_risk: Vec<String> = arguments
                .get("accept_risk")
                .and_then(Value::as_str)
                .map(|s| s.split(',').map(|r| r.trim().to_owned()).collect())
                .unwrap_or_default();

            let has_profile_arg = arguments.get("profile").is_some();
            let has_workload_arg = arguments.get("workload").is_some();

            let workload = match arguments.get("workload").and_then(Value::as_str) {
                Some(w) => Some(parse_workload(w)?),
                None => None,
            };
            let max_friction = match arguments.get("max_friction").and_then(Value::as_str) {
                Some(f) => Some(parse_max_friction(f)?),
                None => None,
            };

            let (workload, max_friction) =
                if !has_profile_arg && !has_workload_arg && loaded_policy.is_none() {
                    (
                        Some(WorkloadPersona::General),
                        Some(FrictionTier::Tier1Cosmetic),
                    )
                } else {
                    (workload, max_friction)
                };

            let profile_val = if let Some(pol) = &loaded_policy {
                pol.extends
            } else {
                let profile_str = arguments
                    .get("profile")
                    .and_then(Value::as_str)
                    .unwrap_or("baseline");
                parse_profile(profile_str)?
            };

            let profile_name = if let Some(pol) = &loaded_policy {
                format!("custom (extends {})", pol.extends)
            } else if let Some(w) = workload {
                format!("workload:{}", w.as_str())
            } else {
                profile_val.as_str().to_owned()
            };

            let today = crate::policy::today_iso();

            let recommended_ids: Option<std::collections::BTreeSet<String>> = workload.map(|w| {
                crate::engine::recommend::generate_recommendations(
                    &all_controls,
                    &context,
                    &host,
                    w,
                    max_friction,
                    None,
                )
                .into_iter()
                .map(|r| r.control_id)
                .collect()
            });

            let requires_elevation = all_controls.iter().any(|c| {
                if let Some(f) = filter
                    && c.spec.id != f
                    && !c.spec.id.starts_with(f)
                {
                    return false;
                }
                if let Some(s) = section_filter
                    && !c.spec.section.eq_ignore_ascii_case(s)
                    && !c
                        .spec
                        .section
                        .to_ascii_lowercase()
                        .starts_with(&s.to_ascii_lowercase())
                {
                    return false;
                }
                if let Some(recs) = &recommended_ids
                    && !recs.contains(&c.spec.id)
                {
                    return false;
                }
                if !c.spec.requires_elevation || c.apply.is_none() {
                    return false;
                }
                let override_opt = loaded_policy
                    .as_ref()
                    .and_then(|pol| pol.controls.get(&c.spec.id));
                let mut spec_clone = c.spec.clone();
                if let Some(ov) = override_opt
                    && let Some(desired_val) = &ov.desired
                {
                    spec_clone.desired = crate::engine::evaluate::SemanticState::new(desired_val);
                }
                let resolution = c.observe(&context);
                let mode = if let Some(ov) = override_opt
                    && let Some(m) = ov.mode
                {
                    m
                } else if filter.is_some()
                    || recommended_ids.is_some()
                    || c.spec.min_profile <= profile_val
                {
                    crate::engine::evaluate::Mode::Enforce
                } else {
                    crate::engine::evaluate::Mode::Ignore
                };
                let exception = if let Some(pol) = &loaded_policy {
                    if let Some(ex) = pol.exceptions.iter().find(|e| e.control == c.spec.id) {
                        if resolution.state.as_ref().map(|s| s.0.as_str()) == Some(&ex.accepted) {
                            ex.status(&today)
                        } else {
                            crate::model::outcome::Exception::None
                        }
                    } else {
                        crate::model::outcome::Exception::None
                    }
                } else {
                    crate::model::outcome::Exception::None
                };
                let eval = crate::engine::evaluate::evaluate(
                    &spec_clone,
                    mode,
                    &resolution,
                    &host,
                    exception,
                );
                eval.outcome == crate::model::outcome::Outcome::Drift
                    && eval.exception != crate::model::outcome::Exception::Active
                    && eval.remediation == crate::model::outcome::Remediation::Automatic
            });

            if elevate && !is_elevated && requires_elevation {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default();
                let temp_file = std::env::temp_dir().join(format!(
                    "privr-mcp-elev-{}-{}.tmp",
                    std::process::id(),
                    now.as_millis()
                ));

                let mut child_args = vec!["apply", "--yes", "--format", "json"];
                let workload_str;
                if let Some(w) = workload {
                    child_args.push("--workload");
                    workload_str = w.as_str().to_owned();
                    child_args.push(&workload_str);
                }
                let friction_str;
                if let Some(f) = max_friction {
                    child_args.push("--max-friction");
                    friction_str = f.as_str().to_owned();
                    child_args.push(&friction_str);
                }
                if let Some(p_arg) = arguments.get("policy").and_then(Value::as_str) {
                    child_args.push("--policy");
                    child_args.push(p_arg);
                } else if has_profile_arg {
                    child_args.push("--profile");
                    child_args.push(profile_val.as_str());
                }
                for r in &accept_risk {
                    child_args.push("--accept-risk");
                    child_args.push(r);
                }
                if let Some(f) = filter {
                    child_args.push("--control");
                    child_args.push(f);
                }
                if let Some(s) = section_filter {
                    child_args.push("--section");
                    child_args.push(s);
                }

                let res = crate::platform::elevation::run_elevated(&child_args, Some(&temp_file));
                let _ = std::fs::remove_file(&temp_file);

                match res {
                    crate::platform::elevation::ElevationResult::Success { exit_code, output } => {
                        if exit_code == 0 {
                            return tool_success(output);
                        }
                        return tool_error(format!(
                            "Elevated apply exited with code {exit_code}: {output}"
                        ));
                    }
                    crate::platform::elevation::ElevationResult::Cancelled => {
                        return tool_error("Elevation request was cancelled by user.".to_owned());
                    }
                    crate::platform::elevation::ElevationResult::Failed(e) => {
                        return tool_error(format!("Elevation failed: {e}"));
                    }
                }
            }

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let timestamp = format!("{}.{:03}", now.as_secs(), now.subsec_millis());
            let tx_id = format!("tx-{}-{}", now.as_secs(), now.subsec_millis());
            let mut journal = crate::journal::TransactionJournal {
                schema: crate::journal::JOURNAL_SCHEMA,
                cleanup: None,
                transaction_id: tx_id.clone(),
                timestamp: timestamp.clone(),
                platform: host.platform.as_str().to_owned(),
                profile: profile_name.clone(),
                operations: Vec::new(),
            };

            // Verify journal storage is writable before mutating system state.
            if let Err(e) = crate::journal::save_transaction(&journal) {
                return tool_error(format!("Failed to initialize transaction journal: {e}"));
            }

            let mut unautomated_drift = 0;
            let mut requires_elevation_drift = 0;

            for c in &all_controls {
                if let Some(f) = filter
                    && c.spec.id != f
                    && !c.spec.id.starts_with(f)
                {
                    continue;
                }
                if let Some(s) = section_filter
                    && !c.spec.section.eq_ignore_ascii_case(s)
                    && !c
                        .spec
                        .section
                        .to_ascii_lowercase()
                        .starts_with(&s.to_ascii_lowercase())
                {
                    continue;
                }
                if let Some(recs) = &recommended_ids
                    && !recs.contains(&c.spec.id)
                {
                    continue;
                }
                let override_opt = loaded_policy
                    .as_ref()
                    .and_then(|pol| pol.controls.get(&c.spec.id));
                let mut spec_clone = c.spec.clone();
                if let Some(ov) = override_opt
                    && let Some(desired_val) = &ov.desired
                {
                    spec_clone.desired = crate::engine::evaluate::SemanticState::new(desired_val);
                }
                let resolution = c.observe(&context);
                let mode = if let Some(ov) = override_opt
                    && let Some(m) = ov.mode
                {
                    m
                } else if filter.is_some()
                    || recommended_ids.is_some()
                    || c.spec.min_profile <= profile_val
                {
                    crate::engine::evaluate::Mode::Enforce
                } else {
                    crate::engine::evaluate::Mode::Ignore
                };
                let exception = if let Some(pol) = &loaded_policy {
                    if let Some(ex) = pol.exceptions.iter().find(|e| e.control == c.spec.id) {
                        if resolution.state.as_ref().map(|s| s.0.as_str()) == Some(&ex.accepted) {
                            ex.status(&today)
                        } else {
                            crate::model::outcome::Exception::None
                        }
                    } else {
                        crate::model::outcome::Exception::None
                    }
                } else {
                    crate::model::outcome::Exception::None
                };
                let eval = crate::engine::evaluate::evaluate(
                    &spec_clone,
                    mode,
                    &resolution,
                    &host,
                    exception,
                );
                if eval.outcome == crate::model::outcome::Outcome::Drift {
                    if eval.exception == crate::model::outcome::Exception::Active {
                        continue;
                    }
                    let is_risk_accepted =
                        accept_risk.iter().any(|r| r == "all" || r == &c.spec.id);
                    if c.spec.friction >= FrictionTier::Tier2WorkflowAltering && !is_risk_accepted {
                        unautomated_drift += 1;
                        continue;
                    }
                    if eval.remediation == crate::model::outcome::Remediation::Automatic
                        && c.apply.is_some()
                    {
                        match automatic_elevation_decision(c, &eval, is_elevated, filter.is_some())
                        {
                            ElevationDecision::Refuse => {
                                if let Ok(root) = crate::journal::transactions_dir() {
                                    let _ =
                                        std::fs::remove_file(root.join(format!("{tx_id}.json")));
                                }
                                return tool_error(format!(
                                    "Control '{}' requires administrative privileges (run privr as Administrator).",
                                    c.spec.id
                                ));
                            }
                            ElevationDecision::Defer => {
                                requires_elevation_drift += 1;
                                continue;
                            }
                            ElevationDecision::NotRequired => {}
                        }

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
                    } else {
                        unautomated_drift += 1;
                    }
                }
            }

            if journal.operations.is_empty()
                && let Ok(root) = crate::journal::transactions_dir()
            {
                let _ = std::fs::remove_file(root.join(format!("{tx_id}.json")));
            }

            let report = json!({
                "schema": 1,
                "profile": profile_name,
                "workload": workload.map(|w| w.as_str()),
                "platform": host.platform.as_str(),
                "transaction_id": if journal.operations.is_empty() { "" } else { &tx_id },
                "applied_changes": journal.operations.len(),
                "unautomated_drift": unautomated_drift,
                "requires_elevation_drift": requires_elevation_drift
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
            let section_filter = arguments.get("section").and_then(Value::as_str);

            if !crate::journal::is_valid_transaction_id(tx_id) {
                return tool_error(format!("Invalid transaction identifier '{tx_id}'."));
            }

            let journal = match crate::journal::load_transaction(tx_id) {
                Ok(j) => j,
                Err(e) => {
                    return tool_error(format!("Transaction '{tx_id}' not found: {e}"));
                }
            };

            if journal.operations.is_empty() {
                if journal.profile.starts_with("clean:") {
                    return tool_error(format!(
                        "Transaction '{tx_id}' is an irreversible residue clean and cannot be rolled back."
                    ));
                }
                return tool_error(format!(
                    "Transaction '{tx_id}' contains no operations to roll back."
                ));
            }

            let host = crate::platform::discover();
            if journal.platform != host.platform.as_str() {
                return tool_error(format!(
                    "Transaction '{tx_id}' was recorded on '{}' and cannot be rolled back on '{}'.",
                    journal.platform,
                    host.platform.as_str()
                ));
            }
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();

            let matching_ops: Vec<&crate::journal::OperationJournal> =
                if let Some(sec) = section_filter {
                    journal
                        .operations
                        .iter()
                        .filter(|op| {
                            all_controls
                                .iter()
                                .find(|c| c.spec.id == op.control_id)
                                .map(|c| {
                                    c.spec.section.eq_ignore_ascii_case(sec)
                                        || c.spec
                                            .section
                                            .to_ascii_lowercase()
                                            .starts_with(&sec.to_ascii_lowercase())
                                })
                                .unwrap_or(false)
                        })
                        .collect()
                } else {
                    journal.operations.iter().collect()
                };

            if matching_ops.is_empty()
                && let Some(sec) = section_filter
            {
                return tool_error(format!(
                    "No operations in transaction '{tx_id}' match section '{sec}'."
                ));
            }

            let mut restored = 0;

            for op in matching_ops.iter().rev() {
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

            let mut report = json!({
                "schema": 1,
                "transaction_id": tx_id,
                "restored_changes": restored
            });
            if let Some(sec) = section_filter {
                report["section"] = json!(sec);
            }
            tool_success(serde_json::to_string_pretty(&report).unwrap_or_default())
        }
        "privr_recommend" => {
            let workload_str = arguments
                .get("workload")
                .and_then(Value::as_str)
                .unwrap_or("general");
            let workload = match workload_str.to_ascii_lowercase().as_str() {
                "general" => crate::model::posture::WorkloadPersona::General,
                "developer" => crate::model::posture::WorkloadPersona::Developer,
                "creative" => crate::model::posture::WorkloadPersona::Creative,
                "mobile" => crate::model::posture::WorkloadPersona::Mobile,
                "high-assurance" | "high_assurance" => {
                    crate::model::posture::WorkloadPersona::HighAssurance
                }
                other => {
                    return tool_error(format!(
                        "Invalid workload '{other}'; must be general, developer, creative, mobile, or high-assurance"
                    ));
                }
            };

            let max_friction = match arguments.get("max_friction").and_then(Value::as_str) {
                Some(s) => match s.to_ascii_lowercase().as_str() {
                    "tier0-transparent" | "tier0" | "transparent" => {
                        Some(crate::model::posture::FrictionTier::Tier0Transparent)
                    }
                    "tier1-cosmetic" | "tier1" | "cosmetic" => {
                        Some(crate::model::posture::FrictionTier::Tier1Cosmetic)
                    }
                    "tier2-workflow-altering" | "tier2" | "workflow-altering" => {
                        Some(crate::model::posture::FrictionTier::Tier2WorkflowAltering)
                    }
                    "tier3-incompatible-or-tradeoff" | "tier3" | "incompatible" => {
                        Some(crate::model::posture::FrictionTier::Tier3IncompatibleOrTradeoff)
                    }
                    other => {
                        return tool_error(format!(
                            "Invalid max_friction '{other}'; must be tier0-transparent, tier1-cosmetic, tier2-workflow-altering, or tier3-incompatible-or-tradeoff"
                        ));
                    }
                },
                None => None,
            };

            let dimension = match arguments.get("dimension").and_then(Value::as_str) {
                Some(s) => match s.to_ascii_lowercase().as_str() {
                    "behavioral-commercial" | "behavioral" => {
                        Some(crate::model::posture::PostureDimension::BehavioralCommercial)
                    }
                    "forensic-residue" | "forensic" => {
                        Some(crate::model::posture::PostureDimension::ForensicResidue)
                    }
                    "network-exposure" | "network" => {
                        Some(crate::model::posture::PostureDimension::NetworkExposure)
                    }
                    "diagnostic-crash" | "diagnostic" => {
                        Some(crate::model::posture::PostureDimension::DiagnosticCrash)
                    }
                    "ambient-sensor" | "ambient" => {
                        Some(crate::model::posture::PostureDimension::AmbientSensor)
                    }
                    other => {
                        return tool_error(format!(
                            "Invalid dimension '{other}'; must be behavioral-commercial, forensic-residue, network-exposure, diagnostic-crash, or ambient-sensor"
                        ));
                    }
                },
                None => None,
            };

            let host = crate::platform::discover();
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();
            let recommendations = crate::engine::recommend::generate_recommendations(
                &all_controls,
                &context,
                &host,
                workload,
                max_friction,
                dimension,
            );

            let report = json!({
                "schema": 1,
                "platform": host.platform.as_str(),
                "workload": workload.as_str(),
                "max_friction": max_friction.map(|f| f.as_str()),
                "dimension": dimension.map(|d| d.as_str()),
                "recommendations_count": recommendations.len(),
                "recommendations": recommendations
            });
            tool_success(serde_json::to_string_pretty(&report).unwrap_or_default())
        }
        "privr_simulate" => {
            let profile_str = arguments
                .get("profile")
                .and_then(Value::as_str)
                .unwrap_or("baseline");
            let profile = parse_profile(profile_str)?;
            let control_filter = arguments
                .get("control")
                .and_then(Value::as_str)
                .map(|s| vec![s.to_owned()])
                .unwrap_or_default();
            let section_filter = arguments
                .get("section")
                .and_then(Value::as_str)
                .map(|s| vec![s.to_owned()])
                .unwrap_or_default();

            let loaded_policy = if let Some(pol_arg) =
                arguments.get("policy").and_then(Value::as_str)
            {
                let pol = if pol_arg.trim_start().starts_with('{') || pol_arg.contains("schema =") {
                    pol_arg
                        .parse::<crate::policy::CustomPolicy>()
                        .map_err(|e| (-32602, e))?
                } else {
                    let path = std::path::Path::new(pol_arg);
                    crate::policy::CustomPolicy::from_file(path).map_err(|e| (-32602, e))?
                };
                Some(pol)
            } else {
                None
            };

            let host = crate::platform::discover();
            let context = crate::catalog::Context::live(&host);
            let all_controls = crate::catalog::all();
            let simulation = if let Some(pol) = &loaded_policy {
                crate::engine::simulate::simulate_with_policy(
                    &all_controls,
                    &context,
                    &host,
                    pol,
                    &control_filter,
                    &section_filter,
                )
            } else {
                crate::engine::simulate::simulate_profile(
                    &all_controls,
                    &context,
                    &host,
                    profile,
                    &control_filter,
                    &section_filter,
                )
            };

            let report = json!({
                "schema": 1,
                "platform": host.platform.as_str(),
                "profile": simulation.profile,
                "simulated_changes": simulation.simulated_changes,
                "unautomated_drift": simulation.unautomated_drift,
                "current_posture": simulation.current_posture,
                "simulated_posture": simulation.simulated_posture,
                "friction_breakdown": simulation.friction_breakdown,
                "pending_restart_required": simulation.pending_restart_required,
                "pending_signout_required": simulation.pending_signout_required,
                "simulated_control_ids": simulation.simulated_control_ids
            });
            tool_success(serde_json::to_string_pretty(&report).unwrap_or_default())
        }
        "privr_history" => {
            let purge = arguments
                .get("purge")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if purge {
                if !allow_apply {
                    return Err((
                        -32600,
                        "privr_history purge requires server launched with --allow-apply"
                            .to_owned(),
                    ));
                }
                let yes = arguments
                    .get("yes")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !yes {
                    return Err((
                        -32602,
                        "Explicit confirmation 'yes': true required to purge transaction history"
                            .to_owned(),
                    ));
                }
                match crate::journal::purge_transactions() {
                    Ok(count) => {
                        let res = json!({
                            "purged": count
                        });
                        tool_success(serde_json::to_string_pretty(&res).unwrap_or_default())
                    }
                    Err(e) => Err((-32603, format!("Failed to purge transaction history: {e}"))),
                }
            } else {
                match crate::journal::list_transactions() {
                    Ok(txs) => tool_success(serde_json::to_string_pretty(&txs).unwrap_or_default()),
                    Err(error) => tool_error(error.to_string()),
                }
            }
        }
        "privr_clean" => {
            let dry_run = arguments
                .get("dry_run")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            let polite = arguments
                .get("polite")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let trim = arguments
                .get("trim")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let category_filter: Vec<String> = arguments
                .get("category")
                .and_then(Value::as_str)
                .map(|s| s.split(',').map(|c| c.trim().to_owned()).collect())
                .unwrap_or_default();
            let control_filter: Vec<String> = arguments
                .get("control")
                .and_then(Value::as_str)
                .map(|s| s.split(',').map(|c| c.trim().to_owned()).collect())
                .unwrap_or_default();
            let accept_risks: Vec<String> = arguments
                .get("accept_risk")
                .and_then(Value::as_str)
                .map(|s| s.split(',').map(|r| r.trim().to_owned()).collect())
                .unwrap_or_default();

            if !dry_run {
                if !allow_apply {
                    return Err((
                        -32600,
                        "privr_clean mutating purge requires server launched with --allow-apply"
                            .to_owned(),
                    ));
                }
                let yes = arguments
                    .get("yes")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if !yes {
                    return Err((
                        -32602,
                        "Explicit confirmation 'yes': true required to execute residue clean"
                            .to_owned(),
                    ));
                }
            }

            let mode = if polite {
                crate::model::residue::PurgeMode::Polite
            } else {
                crate::model::residue::PurgeMode::Aggressive
            };

            let target_specs = crate::catalog::residue::select_residue_targets(
                mode,
                &control_filter,
                &category_filter,
            );

            if let Err(reason) = crate::platform::validate_residue_roots(&target_specs) {
                return tool_error(reason);
            }

            let trim_status = if trim && dry_run {
                Some(crate::platform::check_volume_trim_support())
            } else {
                None
            };

            if dry_run {
                let mut preview_items = Vec::new();
                for (spec, selected, reason) in &target_specs {
                    let item =
                        crate::platform::inspect_residue_target(spec, *selected, reason.clone());
                    preview_items.push(item);
                }
                let report = crate::model::residue::PurgeReport {
                    schema: 1,
                    mode,
                    dry_run: true,
                    status: None,
                    transaction_id: None,
                    journal_error: None,
                    total_files_affected: preview_items
                        .iter()
                        .filter(|i| i.selected)
                        .map(|i| i.file_count)
                        .sum(),
                    total_bytes_affected: preview_items
                        .iter()
                        .filter(|i| i.selected)
                        .map(|i| i.size_bytes)
                        .sum(),
                    items: preview_items
                        .into_iter()
                        .filter(|i| i.selected)
                        .map(|i| crate::model::residue::ResiduePurgeItem {
                            id: i.id,
                            title: i.title,
                            category: i.category,
                            trade_off: i.trade_off.clone(),
                            files_removed: i.file_count,
                            bytes_reclaimed: i.size_bytes,
                            files_retained: 0,
                            error: None,
                        })
                        .collect(),
                    trim: trim_status,
                };
                tool_success(serde_json::to_string_pretty(&report).unwrap_or_default())
            } else {
                for (spec, selected, _) in &target_specs {
                    if *selected && spec.requires_risk_ack && !accept_risks.contains(&spec.id) {
                        return tool_error(format!(
                            "Target '{}' requires explicit acknowledgement via 'accept_risk'",
                            spec.id
                        ));
                    }
                }

                let selected: Vec<_> = target_specs
                    .into_iter()
                    .filter_map(|(spec, selected, _)| selected.then_some(spec))
                    .collect();
                let root = match crate::journal::transactions_dir() {
                    Ok(root) => root,
                    Err(error) => return tool_error(error.to_string()),
                };
                match crate::cleanup::execute(mode, &selected, trim, &root) {
                    Ok(report) => {
                        let json = serde_json::to_string_pretty(&report).unwrap_or_default();
                        if report.status == Some(crate::model::residue::CleanupStatus::Completed) {
                            tool_success(json)
                        } else {
                            tool_error(json)
                        }
                    }
                    Err(reason) => tool_error(reason),
                }
            }
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

fn parse_workload(s: &str) -> Result<crate::model::posture::WorkloadPersona, (i64, String)> {
    match s.to_ascii_lowercase().as_str() {
        "general" => Ok(crate::model::posture::WorkloadPersona::General),
        "developer" => Ok(crate::model::posture::WorkloadPersona::Developer),
        "creative" => Ok(crate::model::posture::WorkloadPersona::Creative),
        "mobile" => Ok(crate::model::posture::WorkloadPersona::Mobile),
        "high-assurance" | "high_assurance" => {
            Ok(crate::model::posture::WorkloadPersona::HighAssurance)
        }
        other => Err((
            -32602,
            format!(
                "Invalid workload '{other}'; must be general, developer, creative, mobile, or high-assurance"
            ),
        )),
    }
}

fn parse_max_friction(s: &str) -> Result<crate::model::posture::FrictionTier, (i64, String)> {
    match s.to_ascii_lowercase().as_str() {
        "tier0-transparent" | "tier0" | "transparent" => {
            Ok(crate::model::posture::FrictionTier::Tier0Transparent)
        }
        "tier1-cosmetic" | "tier1" | "cosmetic" => {
            Ok(crate::model::posture::FrictionTier::Tier1Cosmetic)
        }
        "tier2-workflow-altering" | "tier2" | "workflow-altering" => {
            Ok(crate::model::posture::FrictionTier::Tier2WorkflowAltering)
        }
        "tier3-incompatible-or-tradeoff" | "tier3" | "incompatible" => {
            Ok(crate::model::posture::FrictionTier::Tier3IncompatibleOrTradeoff)
        }
        other => Err((
            -32602,
            format!(
                "Invalid max_friction '{other}'; must be tier0-transparent, tier1-cosmetic, tier2-workflow-altering, or tier3-incompatible-or-tradeoff"
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle_message(req: &Value, allow_apply: bool, err: &mut impl Write) -> Option<Value> {
        let params = &req["params"];
        let confirmed_mutation = allow_apply
            && ((matches!(
                params["name"].as_str(),
                Some("privr_apply" | "privr_rollback")
            ) && params["arguments"]["yes"] == true)
                || (params["name"].as_str() == Some("privr_history")
                    && params["arguments"]["purge"] == true
                    && params["arguments"]["yes"] == true)
                || (params["name"].as_str() == Some("privr_clean")
                    && params["arguments"]["dry_run"] == false
                    && params["arguments"]["yes"] == true));
        assert!(
            !confirmed_mutation,
            "unit tests must not execute confirmed live mutations"
        );
        super::handle_message(req, allow_apply, err)
    }

    #[test]
    #[should_panic(expected = "unit tests must not execute confirmed live mutations")]
    fn test_dispatch_refuses_a_confirmed_live_mutation_before_host_access() {
        let request = json!({"method":"tools/call", "params":{"name":"privr_apply", "arguments":{"yes":true}}});
        let _ = handle_message(&request, true, &mut Vec::new());
    }

    #[test]
    #[should_panic(expected = "unit tests must not execute confirmed live mutations")]
    fn test_dispatch_refuses_a_confirmed_live_rollback_before_host_access() {
        let request = json!({"method":"tools/call", "params":{"name":"privr_rollback", "arguments":{"yes":true, "transaction_id":"tx-fake"}}});
        let _ = handle_message(&request, true, &mut Vec::new());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issue18_mcp_file_only_storage_is_successful_but_unknown() {
        use crate::platform::linux::systemd::ConfigurationFamily;
        for (family, selector, bytes) in [
            (
                ConfigurationFamily::Coredump,
                "systemd.coredump",
                b"[Coredump]\nStorage=none\n".as_slice(),
            ),
            (
                ConfigurationFamily::Journald,
                "systemd.journald",
                b"[Journal]\nStorage=volatile\n".as_slice(),
            ),
        ] {
            let host = crate::test_context::host("arch", "hyprland");
            let reader = crate::test_context::configuration_reader(family, bytes);
            let context = crate::test_context::context(&host, &reader);
            let (response, report) =
                recorded_check(json!({"control":selector,"all":true}), &context);
            assert_eq!(response["result"]["isError"], false);
            assert_eq!(report["complete"], false);
            assert_eq!(report["summary"]["unknown"], 1);
            assert_eq!(report["summary"]["pass"], 0);
            assert!(report["results"][0]["note"].as_str().unwrap().contains(
                if family == ConfigurationFamily::Coredump {
                    "temporary writes"
                } else {
                    "existing history"
                }
            ));
            assert!(
                report["results"][0]["note"]
                    .as_str()
                    .unwrap()
                    .contains("Loaded storage is unverified")
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn recorded_check(arguments: Value, context: &crate::catalog::Context) -> (Value, Value) {
        let request = json!({"jsonrpc":"2.0","id":42,"method":"tools/call", "params":{"name":"privr_check","arguments":arguments}});
        let input = format!("{request}\n");
        let mut out = Vec::new();
        let mut err = Vec::new();
        assert_eq!(
            run_stdio_with_check_context(
                false,
                input.as_bytes(),
                &mut out,
                &mut err,
                Some(context)
            ),
            0
        );
        let response: Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(response["id"], 42);
        assert!(response.get("error").is_none(), "{response}");
        assert_eq!(response["result"]["isError"], false);
        let report =
            serde_json::from_str(response["result"]["content"][0]["text"].as_str().unwrap())
                .unwrap();
        (response, report)
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_analytics_mcp_retains_unknown_and_incomplete_scope() {
        let host = crate::model::host::HostFacts::unknown(crate::model::host::Platform::Macos);
        let context = crate::catalog::Context { host: &host };
        let (_, report) = recorded_check(
            json!({"control":"macos.analytics.share-mac", "all":true}),
            &context,
        );
        assert_eq!(report["complete"], false);
        assert_eq!(report["summary"]["unknown"], 1);
        assert_eq!(report["summary"]["pass"], 0);
        assert_eq!(report["results"][0]["management_source"], "unknown");
        assert!(
            report["results"][0]["note"]
                .as_str()
                .unwrap()
                .contains("unverified")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issue19_mcp_selected_scope_is_aggregated_before_presentation() {
        let host = crate::test_context::host("debian", "hyprland");
        let reader = crate::test_context::reader(crate::test_context::fstrim_enabled());
        let context = crate::test_context::context(&host, &reader);
        let (_, report) = recorded_check(json!({"section":"SyStEmD","all":true}), &context);
        assert_eq!(report["results"].as_array().unwrap().len(), 5);
        assert_eq!(report["summary"]["pass"], 0);
        assert_eq!(report["summary"]["not_selected"], 3);
        assert_eq!(report["complete"], false);
        assert_eq!(report["carried"], 17);
        assert!(reader.requested().is_empty());

        let (_, shown) = recorded_check(json!({"control":"systemd.fstrim", "all":true}), &context);
        let (_, hidden) =
            recorded_check(json!({"control":"systemd.fstrim", "all":false}), &context);
        assert_eq!(shown["summary"]["pass"], 1);
        assert_eq!(shown["summary"], hidden["summary"]);
        assert_eq!(shown["complete"], true);
        assert_eq!(hidden["complete"], true);
        assert_eq!(shown["results"].as_array().unwrap().len(), 1);
        assert!(hidden["results"].as_array().unwrap().is_empty());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn issue19_mcp_explicit_control_enforces_and_empty_scopes_stay_incomplete() {
        use crate::platform::linux::systemd::ConfigurationFamily;
        let host = crate::test_context::host("arch", "hyprland");
        let reader = crate::test_context::configuration_reader(
            ConfigurationFamily::Coredump,
            b"[Coredump]\nStorage=none\n",
        );
        let context = crate::test_context::context(&host, &reader);
        for (arguments, rows, not_applicable, not_selected) in [
            (json!({"all":true}), 17, 7, 7),
            (json!({"control":"missing","all":true}), 0, 0, 0),
            (json!({"section":"UbU","all":true}), 2, 2, 0),
            (
                json!({"control":"systemd", "section":"ubuntu","all":true}),
                0,
                0,
                0,
            ),
            (json!({"control":"Systemd","all":true}), 0, 0, 0),
        ] {
            let (_, report) = recorded_check(arguments, &context);
            assert_eq!(report["results"].as_array().unwrap().len(), rows);
            assert_eq!(report["summary"]["not_applicable"], not_applicable);
            assert_eq!(report["summary"]["not_selected"], not_selected);
            assert_eq!(report["complete"], false);
            assert_eq!(report["carried"], 17);
        }
        assert!(reader.requested().is_empty());
        assert!(reader.requested_configurations().is_empty());
        let (_, report) =
            recorded_check(json!({"control":"systemd.coredump","all":true}), &context);
        assert_eq!(report["summary"]["pass"], 0);
        assert_eq!(report["summary"]["unknown"], 1);
        assert!(
            report["results"][0]["note"]
                .as_str()
                .unwrap()
                .contains("Storage=none")
        );
        assert_eq!(report["summary"]["not_selected"], 0);
        assert_eq!(report["complete"], false);
        assert!(reader.requested().is_empty());
        assert_eq!(
            reader.requested_configurations(),
            vec![ConfigurationFamily::Coredump]
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mcp_check_matches_the_shared_report_for_the_same_recording() {
        use crate::platform::linux::evidence::Target;
        let host = crate::test_context::host("fedora", "hyprland");
        let reader = crate::test_context::reader([(
            Target::FedoraAbrt,
            crate::test_context::text(b"AutoreportingEnabled = yes\n# /home/secret-user\n"),
        )]);
        let context = crate::test_context::context(&host, &reader);
        let report = crate::report::Report::build_with_context(
            &context,
            Some("baseline"),
            None,
            &["fedora".to_owned()],
            &[],
        );
        let (_, mcp) = recorded_check(json!({"control": "fedora", "all": true}), &context);
        let cli: Value = serde_json::from_str(&serde_json::to_string(&report).unwrap()).unwrap();
        let mut mcp_no_ts = mcp.clone();
        let mut cli_no_ts = cli.clone();
        mcp_no_ts["timestamp"] = Value::Null;
        cli_no_ts["timestamp"] = Value::Null;
        assert_eq!(mcp_no_ts, cli_no_ts);
        assert!(mcp["timestamp"].is_string());
        assert!(cli["timestamp"].is_string());
        assert_eq!(mcp["schema"], 2);
        assert_eq!(mcp["complete"], true);
        assert_eq!(mcp["results"][0]["observed"], "enabled");
        assert_eq!(mcp["results"][0]["policy_mode"], "enforce");
        assert!(mcp["results"][0]["confident"].as_bool().unwrap());
        let rendered = mcp.to_string();
        assert!(!rendered.contains("/home/secret-user"));
        assert!(!rendered.contains("PARTICIPATE"));
    }

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
        let apply_tool = list
            .iter()
            .find(|t| t["name"] == "privr_apply")
            .expect("apply tool");
        assert!(apply_tool["inputSchema"]["properties"]["elevate"].is_object());
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
    fn privr_explain_is_a_fresh_read() {
        let id = if cfg!(windows) {
            "windows.advertising.id"
        } else if cfg!(target_os = "macos") {
            "macos.analytics.share-mac"
        } else {
            "debian.popularity-contest.participation"
        };
        let req = json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "privr_explain",
                "arguments": { "id": id }
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&req, false, &mut err).expect("response");
        let text = resp["result"]["content"][0]["text"].as_str().expect("text");
        let value: Value = serde_json::from_str(text).expect("explain json");
        assert_eq!(value["evidence"], "fresh");
        assert_eq!(value["reconstructed_check"], false);
        assert!(
            value["note"]
                .as_str()
                .unwrap()
                .contains("does not reconstruct an earlier check")
        );
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

        let text = resp2["result"]["content"][0]["text"]
            .as_str()
            .expect("confirmation error");
        assert!(text.contains("Confirmation required"));
        // Missing transactions are covered by isolated journal tests.
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

    #[test]
    fn privr_recommend_evaluates_workloads_and_friction_budgets() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 20,
            "method": "tools/call",
            "params": {
                "name": "privr_recommend",
                "arguments": {
                    "workload": "developer",
                    "max_friction": "tier1-cosmetic"
                }
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&req, false, &mut err).expect("response");
        assert_eq!(resp["id"], 20);
        let text = resp["result"]["content"][0]["text"].as_str().expect("text");
        assert!(text.contains("recommendations"));
        assert!(text.contains("developer"));
    }

    #[test]
    fn privr_simulate_evaluates_counterfactual_posture() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "privr_simulate",
                "arguments": {
                    "profile": "baseline"
                }
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&req, false, &mut err).expect("response");
        assert_eq!(resp["id"], 21);
        let text = resp["result"]["content"][0]["text"].as_str().expect("text");
        assert!(text.contains("simulated_changes"));
        assert!(text.contains("current_posture"));
        assert!(text.contains("simulated_posture"));
    }

    #[test]
    fn privr_check_and_plan_support_section_filter() {
        let check_req = json!({
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": {
                "name": "privr_check",
                "arguments": {
                    "profile": "baseline",
                    "section": "advertising",
                    "all": true
                }
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&check_req, false, &mut err).expect("response");
        assert_eq!(resp["id"], 22);
        let text = resp["result"]["content"][0]["text"].as_str().expect("text");
        assert!(text.contains("results"));

        let plan_req = json!({
            "jsonrpc": "2.0",
            "id": 23,
            "method": "tools/call",
            "params": {
                "name": "privr_plan",
                "arguments": {
                    "profile": "baseline",
                    "section": "advertising"
                }
            }
        });
        let plan_resp = handle_message(&plan_req, false, &mut err).expect("response");
        assert_eq!(plan_resp["id"], 23);
        let plan_text = plan_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("text");
        assert!(plan_text.contains("planned_changes"));
    }

    #[test]
    fn privr_plan_supports_workload_and_max_friction() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 30,
            "method": "tools/call",
            "params": {
                "name": "privr_plan",
                "arguments": {
                    "workload": "developer",
                    "max_friction": "tier1-cosmetic"
                }
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&req, false, &mut err).expect("response");
        assert_eq!(resp["id"], 30);
        let text = resp["result"]["content"][0]["text"].as_str().expect("text");
        let val: Value = serde_json::from_str(text).expect("json");
        assert_eq!(val["workload"], "developer");
        assert!(val["planned_changes"].as_u64().is_some());
    }

    #[test]
    fn privr_plan_accepts_workload_and_max_friction_without_mutation() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "privr_plan",
                "arguments": {
                    "workload": "developer",
                    "max_friction": "tier0-transparent"
                }
            }
        });
        let mut err = Vec::new();
        let resp = handle_message(&req, false, &mut err).expect("response");
        assert_eq!(resp["id"], 31);
        let text = resp["result"]["content"][0]["text"].as_str().expect("text");
        let val: Value = serde_json::from_str(text).expect("json");
        assert_eq!(val["workload"], "developer");
        assert!(val["planned_changes"].as_u64().is_some());
    }

    #[test]
    fn automatic_elevation_decision_uses_synthetic_capability_and_effective_privilege() {
        use crate::engine::evaluate::{Mode, Resolution, SemanticState, evaluate};
        use crate::model::host::{HostFacts, ManagementSource, Platform};
        use crate::model::outcome::{Exception, Outcome, Remediation};
        let host = HostFacts::unknown(Platform::current());
        let mut control = crate::catalog::all()
            .into_iter()
            .find(|control| control.requires_elevation())
            .expect("machine control");
        control.spec.applicability = Default::default();
        control.spec.verified_through = None;
        control.spec.remediation = Remediation::Automatic;
        control.spec.remediation_reason = None;
        control.apply = Some(|_| panic!("synthetic mutation must never execute"));
        let resolution = Resolution::determined(
            SemanticState::new("synthetic-different-state"),
            ManagementSource::User,
        );
        let mut result = evaluate(
            &control.spec,
            Mode::Enforce,
            &resolution,
            &host,
            Exception::None,
        );
        assert_eq!(result.outcome, Outcome::Drift);
        assert_eq!(result.remediation, Remediation::Automatic);
        assert_eq!(
            automatic_elevation_decision(&control, &result, false, true),
            ElevationDecision::Refuse
        );
        assert_eq!(
            automatic_elevation_decision(&control, &result, false, false),
            ElevationDecision::Defer
        );
        assert_eq!(
            automatic_elevation_decision(&control, &result, true, true),
            ElevationDecision::NotRequired
        );
        // Unknown privilege is reduced to false by the real dispatcher.
        assert_ne!(host.elevated, crate::model::host::Fact::Known(true));
        control.apply = None;
        assert_eq!(
            automatic_elevation_decision(&control, &result, false, true),
            ElevationDecision::NotRequired
        );
        control.apply = Some(|_| panic!("synthetic mutation must never execute"));
        result.remediation = Remediation::AuditOnly;
        assert_eq!(
            automatic_elevation_decision(&control, &result, false, true),
            ElevationDecision::NotRequired
        );
        result.remediation = Remediation::Automatic;
        result.outcome = Outcome::Unknown;
        assert_eq!(
            automatic_elevation_decision(&control, &result, false, true),
            ElevationDecision::NotRequired
        );
        result.outcome = Outcome::Drift;
        control.spec.requires_elevation = false;
        assert_eq!(
            automatic_elevation_decision(&control, &result, false, true),
            ElevationDecision::NotRequired
        );
    }

    #[test]
    fn mutation_argument_parsers_reject_invalid_workload_and_friction_without_host_access() {
        assert_eq!(parse_workload("developer"), Ok(WorkloadPersona::Developer));
        assert_eq!(
            parse_workload("high-assurance"),
            Ok(WorkloadPersona::HighAssurance)
        );
        assert_eq!(
            parse_max_friction("tier3-incompatible-or-tradeoff"),
            Ok(FrictionTier::Tier3IncompatibleOrTradeoff)
        );
        for invalid in ["", "unrecognized", "developer --yes"] {
            assert_eq!(
                parse_workload(invalid).expect_err("invalid workload").0,
                -32602
            );
            assert_eq!(
                parse_max_friction(invalid).expect_err("invalid friction").0,
                -32602
            );
        }
    }

    #[test]
    fn test_privr_history_and_clean_tools_in_tool_list() {
        let tools_val = handle_tools_list(false);
        let tools_arr = tools_val["tools"].as_array().expect("tools array");
        assert!(tools_arr.iter().any(|t| t["name"] == "privr_history"));
        assert!(tools_arr.iter().any(|t| t["name"] == "privr_clean"));
        assert!(tools_arr.iter().any(|t| t["name"] == "privr_check"));
    }

    #[test]
    fn test_privr_history_read_only_call() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "privr_history",
                "arguments": {}
            }
        });
        let res = super::handle_message(&req, false, &mut Vec::new()).expect("response");
        if let Some(err) = res.get("error") {
            panic!("Got error: {err:?}");
        }
        assert_eq!(res["result"]["isError"], false);
    }

    #[test]
    fn test_privr_check_and_plan_with_custom_policy_via_mcp() {
        let toml_policy = r#"
schema = 1
extends = "baseline"

[controls."windows.advertising.id"]
mode = "enforce"
desired = "disabled"

[[exceptions]]
control = "windows.advertising.id"
accepted = "enabled"
reason = "Accepted risk for test"
expires = "2029-01-01"
"#;
        let req = json!({
            "jsonrpc": "2.0",
            "id": 100,
            "method": "tools/call",
            "params": {
                "name": "privr_check",
                "arguments": {
                    "policy": toml_policy
                }
            }
        });
        let res = super::handle_message(&req, false, &mut Vec::new()).expect("response");
        assert_eq!(res["result"]["isError"], false);
        let text = res["result"]["content"][0]["text"].as_str().expect("text");
        let parsed: serde_json::Value = serde_json::from_str(text).expect("valid json report");
        assert_eq!(parsed["profile"], "custom (extends baseline)");

        // Plan with policy
        let plan_req = json!({
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "privr_plan",
                "arguments": {
                    "policy": toml_policy
                }
            }
        });
        let plan_res =
            super::handle_message(&plan_req, false, &mut Vec::new()).expect("plan response");
        assert_eq!(plan_res["result"]["isError"], false);
        let plan_text = plan_res["result"]["content"][0]["text"]
            .as_str()
            .expect("plan text");
        let plan_parsed: serde_json::Value =
            serde_json::from_str(plan_text).expect("valid json plan");
        assert_eq!(plan_parsed["profile"], "custom (extends baseline)");
    }

    #[test]
    fn test_privr_history_purge_refuses_without_allow_apply() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "privr_history",
                "arguments": {
                    "purge": true,
                    "yes": true
                }
            }
        });
        let res = super::handle_message(&req, false, &mut Vec::new()).expect("response");
        assert_eq!(res["error"]["code"], -32600);
    }

    #[test]
    fn test_privr_clean_preview_call() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "privr_clean",
                "arguments": {
                    "dry_run": true,
                    "polite": true
                }
            }
        });
        let res = super::handle_message(&req, false, &mut Vec::new()).expect("response");
        if let Some(err) = res.get("error") {
            panic!("Got error: {err:?}");
        }
        assert_eq!(res["result"]["isError"], false);
        let text = res["result"]["content"][0]["text"].as_str().expect("text");
        let parsed: Value = serde_json::from_str(text).expect("valid json report");
        assert_eq!(parsed["dry_run"], true);
    }

    #[test]
    fn test_privr_clean_mutating_refuses_without_allow_apply() {
        let req = json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "privr_clean",
                "arguments": {
                    "dry_run": false,
                    "yes": true
                }
            }
        });
        let res = super::handle_message(&req, false, &mut Vec::new()).expect("response");
        assert_eq!(res["error"]["code"], -32600);
    }

    #[test]
    fn test_privr_check_compare_returns_structured_delta() {
        let host = crate::platform::discover();
        let mut prior = crate::report::Report::build_filtered(
            &host,
            "baseline",
            &["windows.delivery-optimization.mode".to_string()],
            &[],
        );
        prior.os_version = Some("10.0.22631".to_owned());
        let prior_str = serde_json::to_string(&prior).unwrap();

        let req = json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "privr_check",
                "arguments": {
                    "control": "windows.delivery-optimization.mode",
                    "compare": prior_str
                }
            }
        });
        let res = super::handle_message(&req, false, &mut Vec::new()).expect("response");
        if let Some(err) = res.get("error") {
            panic!("Got error: {err:?}");
        }
        assert_eq!(res["result"]["isError"], false);
        let text = res["result"]["content"][0]["text"].as_str().expect("text");
        let parsed: Value = serde_json::from_str(text).expect("valid comparison json");
        assert!(parsed.get("regressions").is_some());
        assert_eq!(parsed["platform_upgraded"], true);
    }

    #[test]
    fn test_privr_apply_and_rollback_schemas_have_parity_options() {
        let tools_val = handle_tools_list(true);
        let tools_arr = tools_val["tools"].as_array().expect("tools array");

        let apply_tool = tools_arr
            .iter()
            .find(|t| t["name"] == "privr_apply")
            .expect("privr_apply tool");
        let apply_props = &apply_tool["inputSchema"]["properties"];
        assert!(apply_props.get("policy").is_some());
        assert!(apply_props.get("accept_risk").is_some());

        let rollback_tool = tools_arr
            .iter()
            .find(|t| t["name"] == "privr_rollback")
            .expect("privr_rollback tool");
        let rollback_props = &rollback_tool["inputSchema"]["properties"];
        assert!(rollback_props.get("section").is_some());

        let clean_tool = tools_arr
            .iter()
            .find(|t| t["name"] == "privr_clean")
            .expect("privr_clean tool");
        let clean_props = &clean_tool["inputSchema"]["properties"];
        assert!(clean_props.get("accept_risk").is_some());
    }
}
