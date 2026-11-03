//! Custom privacy policy schema, parser, and validator.
//!
//! A policy states privacy intent. It does not describe operating-system
//! mutation mechanics.
//!
//! A custom policy file:
//! - selects a base profile to extend (baseline, strict, or restrictive);
//! - optionally overrides modes (enforce, review, ignore) and desired states per control;
//! - declares exceptions with an accepted semantic state, a mandatory reason, and an expiry date.
//!
//! Invariant: An exception accepts a specific named state for a specific control.
//! It does not suppress the finding in `check`: drift remains drift, but carries
//! an active exception status that prevents remediation in `plan` and `apply`.
//! When the expiry date passes, the exception becomes expired and drift is remediated.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::model::outcome::{Exception, Mode};
use crate::model::profile::Profile;

/// Schema version for custom policy files.
pub const POLICY_SCHEMA: u32 = 1;

/// A parsed and validated custom policy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomPolicy {
    pub schema: u32,
    pub extends: Profile,
    #[serde(default)]
    pub controls: BTreeMap<String, ControlOverride>,
    #[serde(default)]
    pub exceptions: Vec<PolicyException>,
}

/// A per-control override in a custom policy.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ControlOverride {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired: Option<String>,
}

/// A policy exception accepting a specific state with justification and expiry.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PolicyException {
    pub control: String,
    pub accepted: String,
    pub reason: String,
    pub expires: String,
}

impl PolicyException {
    /// Whether this exception's expiry date is strictly in the past relative to `today`.
    pub fn is_expired(&self, today: &str) -> bool {
        self.expires.as_str() < today
    }

    /// Resolve exception state against `today` (ISO 8601 YYYY-MM-DD).
    pub fn status(&self, today: &str) -> Exception {
        if self.is_expired(today) {
            Exception::Expired
        } else {
            Exception::Active
        }
    }
}

/// Validate that a date string is formatted strictly as YYYY-MM-DD.
pub fn validate_date(date: &str) -> bool {
    if date.len() != 10 {
        return false;
    }
    let bytes = date.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let y: u32 = match date[0..4].parse() {
        Ok(val) => val,
        Err(_) => return false,
    };
    let m: u32 = match date[5..7].parse() {
        Ok(val) => val,
        Err(_) => return false,
    };
    let d: u32 = match date[8..10].parse() {
        Ok(val) => val,
        Err(_) => return false,
    };
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return false;
    }
    true
}

/// Return the current UTC date as `(year, month, day)`.
pub fn current_date_utc() -> (i32, u32, u32) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (secs / 86400) as i64;
    // Euclidean affine transform for civil date from days since 1970-01-01
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m, d)
}

/// Return today's UTC date in `YYYY-MM-DD` ISO format.
pub fn today_iso() -> String {
    let (y, m, d) = current_date_utc();
    format!("{y:04}-{m:02}-{d:02}")
}

/// Parse an inheritance profile target from string.
pub fn parse_extends(extends: &str) -> Result<Profile, String> {
    let trimmed = extends.trim().trim_matches('"');
    let lower = trimmed.to_ascii_lowercase();
    if lower == "baseline" || lower.starts_with("builtin:baseline") {
        Ok(Profile::Baseline)
    } else if lower == "strict" || lower.starts_with("builtin:strict") {
        Ok(Profile::Strict)
    } else if lower == "restrictive" || lower.starts_with("builtin:restrictive") {
        Ok(Profile::Restrictive)
    } else {
        Err(format!(
            "unknown or unsupported profile inheritance '{trimmed}', expected 'baseline', 'strict', or 'restrictive'"
        ))
    }
}

/// Parse a control policy mode from string.
pub fn parse_mode(mode: &str) -> Result<Mode, String> {
    let trimmed = mode.trim().trim_matches('"');
    match trimmed.to_ascii_lowercase().as_str() {
        "enforce" => Ok(Mode::Enforce),
        "review" => Ok(Mode::Review),
        "ignore" => Ok(Mode::Ignore),
        other => Err(format!(
            "unknown mode '{other}', expected 'enforce', 'review', or 'ignore'"
        )),
    }
}

#[derive(Debug, Deserialize)]
struct PolicyJson {
    schema: u32,
    extends: String,
    #[serde(default)]
    controls: BTreeMap<String, ControlOverrideJson>,
    #[serde(default)]
    exceptions: Vec<PolicyExceptionJson>,
}

#[derive(Debug, Deserialize)]
struct ControlOverrideJson {
    mode: Option<String>,
    desired: Option<String>,
}

#[derive(Debug, Deserialize)]
struct PolicyExceptionJson {
    control: String,
    accepted: String,
    reason: String,
    expires: String,
}

impl CustomPolicy {
    /// Load, parse, and validate a custom policy from a file path.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path).map_err(|e| {
            format!(
                "privr: failed to read policy file '{}': {e}",
                path.display()
            )
        })?;
        content.parse()
    }
}

impl std::str::FromStr for CustomPolicy {
    type Err = String;

    /// Parse and validate a custom policy string (JSON or TOML).
    fn from_str(content: &str) -> Result<Self, Self::Err> {
        let trimmed = content.trim();
        if trimmed.starts_with('{') {
            Self::from_json_str(trimmed)
        } else {
            Self::from_toml_str(trimmed)
        }
    }
}

fn parse_toml_value(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if let Some(rest) = trimmed.strip_prefix('"') {
        if let Some(end_idx) = rest.find('"') {
            let val = &rest[..end_idx];
            let after = rest[end_idx + 1..].trim();
            if !after.is_empty() && !after.starts_with('#') {
                return Err(format!("unexpected characters after string: '{after}'"));
            }
            Ok(val.to_string())
        } else {
            Err("unterminated double-quoted string".to_string())
        }
    } else if let Some(rest) = trimmed.strip_prefix('\'') {
        if let Some(end_idx) = rest.find('\'') {
            let val = &rest[..end_idx];
            let after = rest[end_idx + 1..].trim();
            if !after.is_empty() && !after.starts_with('#') {
                return Err(format!("unexpected characters after string: '{after}'"));
            }
            Ok(val.to_string())
        } else {
            Err("unterminated single-quoted string".to_string())
        }
    } else {
        let clean = match trimmed.split_once('#') {
            Some((before, _comment)) => before.trim(),
            None => trimmed,
        };
        Ok(clean.to_string())
    }
}

impl CustomPolicy {
    fn from_json_str(content: &str) -> Result<Self, String> {
        let raw: PolicyJson = serde_json::from_str(content)
            .map_err(|e| format!("privr: invalid policy JSON: {e}"))?;

        if raw.schema != POLICY_SCHEMA {
            return Err(format!(
                "privr: unsupported policy schema version {}, expected {POLICY_SCHEMA}",
                raw.schema
            ));
        }

        let extends = parse_extends(&raw.extends)?;

        let mut controls = BTreeMap::new();
        for (id, ov) in raw.controls {
            let mode = if let Some(m) = ov.mode {
                Some(parse_mode(&m)?)
            } else {
                None
            };
            controls.insert(
                id,
                ControlOverride {
                    mode,
                    desired: ov.desired,
                },
            );
        }

        let mut exceptions = Vec::new();
        for ex in raw.exceptions {
            exceptions.push(PolicyException {
                control: ex.control,
                accepted: ex.accepted,
                reason: ex.reason,
                expires: ex.expires,
            });
        }

        let policy = Self {
            schema: raw.schema,
            extends,
            controls,
            exceptions,
        };
        policy.validate()?;
        Ok(policy)
    }

    fn from_toml_str(content: &str) -> Result<Self, String> {
        enum Section {
            TopLevel,
            Control(String),
            Exception,
        }

        let mut schema: Option<u32> = None;
        let mut extends: Option<String> = None;
        let mut controls: BTreeMap<String, ControlOverride> = BTreeMap::new();
        let mut exceptions: Vec<PolicyException> = Vec::new();

        let mut current_section = Section::TopLevel;
        let mut current_override = ControlOverride {
            mode: None,
            desired: None,
        };
        let mut current_ex = PolicyException {
            control: String::new(),
            accepted: String::new(),
            reason: String::new(),
            expires: String::new(),
        };

        let flush_control =
            |id: &str, ov: &ControlOverride, controls: &mut BTreeMap<String, ControlOverride>| {
                if !id.is_empty() {
                    controls.insert(id.to_string(), ov.clone());
                }
            };

        let flush_exception = |ex: &PolicyException, exceptions: &mut Vec<PolicyException>| {
            if !ex.control.is_empty() {
                exceptions.push(ex.clone());
            }
        };

        for (line_no, raw_line) in content.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let (line_clean, is_header) = if line.starts_with('[') {
                if let Some(end_bracket) = line.rfind(']') {
                    let header_content = &line[..=end_bracket];
                    let after = line[end_bracket + 1..].trim();
                    if !after.is_empty() && !after.starts_with('#') {
                        return Err(format!(
                            "privr: line {}: unexpected characters after header: '{after}'",
                            line_no + 1
                        ));
                    }
                    (header_content, true)
                } else {
                    (line, false)
                }
            } else {
                (line, false)
            };

            if is_header && line_clean == "[[exceptions]]" {
                match current_section {
                    Section::Control(ref id) => {
                        flush_control(id, &current_override, &mut controls);
                    }
                    Section::Exception => {
                        flush_exception(&current_ex, &mut exceptions);
                    }
                    Section::TopLevel => {}
                }
                current_section = Section::Exception;
                current_ex = PolicyException {
                    control: String::new(),
                    accepted: String::new(),
                    reason: String::new(),
                    expires: String::new(),
                };
                continue;
            }

            if is_header && line_clean.starts_with('[') && line_clean.ends_with(']') {
                match current_section {
                    Section::Control(ref id) => {
                        flush_control(id, &current_override, &mut controls);
                    }
                    Section::Exception => {
                        flush_exception(&current_ex, &mut exceptions);
                    }
                    Section::TopLevel => {}
                }

                let inner = line_clean[1..line_clean.len() - 1].trim();
                if let Some(rest) = inner.strip_prefix("controls.") {
                    let id = rest.trim().trim_matches('"').to_string();
                    if id.is_empty() {
                        return Err(format!(
                            "privr: line {}: empty control identifier in [controls.X]",
                            line_no + 1
                        ));
                    }
                    current_override = ControlOverride {
                        mode: None,
                        desired: None,
                    };
                    current_section = Section::Control(id);
                } else {
                    return Err(format!(
                        "privr: line {}: unknown table header '[{inner}]'",
                        line_no + 1
                    ));
                }
                continue;
            }

            // Key-value pair
            let Some((key_raw, val_raw)) = line.split_once('=') else {
                return Err(format!(
                    "privr: line {}: expected 'key = value'",
                    line_no + 1
                ));
            };
            let key = key_raw.trim();
            let val = parse_toml_value(val_raw)
                .map_err(|e| format!("privr: line {}: {e}", line_no + 1))?;

            match current_section {
                Section::TopLevel => {
                    if key == "schema" {
                        let parsed: u32 = val.parse().map_err(|_| {
                            format!(
                                "privr: line {}: invalid schema integer '{val}'",
                                line_no + 1
                            )
                        })?;
                        schema = Some(parsed);
                    } else if key == "extends" {
                        extends = Some(val);
                    } else {
                        return Err(format!(
                            "privr: line {}: unknown top-level field '{key}'",
                            line_no + 1
                        ));
                    }
                }
                Section::Control(_) => {
                    if key == "mode" {
                        current_override.mode = Some(parse_mode(&val)?);
                    } else if key == "desired" {
                        current_override.desired = Some(val);
                    } else {
                        return Err(format!(
                            "privr: line {}: unknown control field '{key}'",
                            line_no + 1
                        ));
                    }
                }
                Section::Exception => {
                    if key == "control" {
                        current_ex.control = val;
                    } else if key == "accepted" {
                        current_ex.accepted = val;
                    } else if key == "reason" {
                        current_ex.reason = val;
                    } else if key == "expires" {
                        current_ex.expires = val;
                    } else {
                        return Err(format!(
                            "privr: line {}: unknown exception field '{key}'",
                            line_no + 1
                        ));
                    }
                }
            }
        }

        // Final flush
        match current_section {
            Section::Control(ref id) => {
                flush_control(id, &current_override, &mut controls);
            }
            Section::Exception => {
                flush_exception(&current_ex, &mut exceptions);
            }
            Section::TopLevel => {}
        }

        let schema_val =
            schema.ok_or_else(|| "privr: policy missing 'schema' field".to_string())?;
        if schema_val != POLICY_SCHEMA {
            return Err(format!(
                "privr: unsupported policy schema version {schema_val}, expected {POLICY_SCHEMA}"
            ));
        }

        let extends_str =
            extends.ok_or_else(|| "privr: policy missing 'extends' field".to_string())?;
        let extends_profile = parse_extends(&extends_str)?;

        let policy = Self {
            schema: schema_val,
            extends: extends_profile,
            controls,
            exceptions,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validate the policy against compiled catalogue rules.
    pub fn validate(&self) -> Result<(), String> {
        // Control overrides must reference existing controls
        for id in self.controls.keys() {
            if !crate::catalog::is_known_control_id(id) {
                return Err(format!(
                    "privr: unknown control identifier '{id}' in policy file"
                ));
            }
        }

        // Exceptions must reference existing controls, provide reasons, and valid expiry dates
        let mut seen_exceptions = BTreeSet::new();
        for ex in &self.exceptions {
            if !crate::catalog::is_known_control_id(&ex.control) {
                return Err(format!(
                    "privr: unknown control identifier '{}' in policy exception",
                    ex.control
                ));
            }
            if !seen_exceptions.insert(&ex.control) {
                return Err(format!(
                    "privr: duplicate exception for control '{}' in policy file",
                    ex.control
                ));
            }
            if ex.reason.trim().is_empty() {
                return Err(format!(
                    "privr: exception for control '{}' must provide a non-empty reason",
                    ex.control
                ));
            }
            if ex.accepted.trim().is_empty() {
                return Err(format!(
                    "privr: exception for control '{}' must provide an accepted state",
                    ex.control
                ));
            }
            if !validate_date(&ex.expires) {
                return Err(format!(
                    "privr: invalid expiry date '{}' in exception for control '{}': expected YYYY-MM-DD",
                    ex.expires, ex.control
                ));
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn parse_valid_toml_policy() {
        let toml = r#"
schema = 1
extends = "builtin:baseline@0.1"

[controls."windows.advertising.id"]
mode = "review"

[controls."windows.security.wpad"]
mode = "enforce"
desired = "disabled"

[[exceptions]]
control = "windows.security.wpad"
accepted = "enabled"
reason = "Legacy intranet proxy compatibility"
expires = "2027-01-01"
"#;
        let policy = CustomPolicy::from_str(toml).expect("valid policy");
        assert_eq!(policy.schema, 1);
        assert_eq!(policy.extends, Profile::Baseline);
        assert_eq!(policy.controls.len(), 2);
        assert_eq!(
            policy.controls.get("windows.advertising.id").unwrap().mode,
            Some(Mode::Review)
        );
        assert_eq!(policy.exceptions.len(), 1);
        let ex = &policy.exceptions[0];
        assert_eq!(ex.control, "windows.security.wpad");
        assert_eq!(ex.accepted, "enabled");
        assert!(!ex.is_expired("2026-11-03"));
        assert_eq!(ex.status("2026-11-03"), Exception::Active);
        assert!(ex.is_expired("2027-02-01"));
        assert_eq!(ex.status("2027-02-01"), Exception::Expired);
    }

    #[test]
    fn parse_valid_json_policy() {
        let json = r#"{
  "schema": 1,
  "extends": "strict",
  "controls": {
    "windows.advertising.id": {
      "mode": "ignore"
    }
  },
  "exceptions": [
    {
      "control": "windows.security.wpad",
      "accepted": "enabled",
      "reason": "Test exception",
      "expires": "2028-12-31"
    }
  ]
}"#;
        let policy = CustomPolicy::from_str(json).expect("valid json policy");
        assert_eq!(policy.schema, 1);
        assert_eq!(policy.extends, Profile::Strict);
        assert_eq!(
            policy.controls.get("windows.advertising.id").unwrap().mode,
            Some(Mode::Ignore)
        );
        assert_eq!(policy.exceptions.len(), 1);
    }

    #[test]
    fn reject_unknown_control_in_policy() {
        let toml = r#"
schema = 1
extends = "baseline"

[controls."windows.fake.nonexistent"]
mode = "enforce"
"#;
        let err = CustomPolicy::from_str(toml).unwrap_err();
        assert!(err.contains("unknown control identifier 'windows.fake.nonexistent'"));
    }

    #[test]
    fn reject_unsupported_schema() {
        let toml = r#"
schema = 2
extends = "baseline"
"#;
        let err = CustomPolicy::from_str(toml).unwrap_err();
        assert!(err.contains("unsupported policy schema version 2"));
    }

    #[test]
    fn reject_invalid_expiry_date() {
        let toml = r#"
schema = 1
extends = "baseline"

[[exceptions]]
control = "windows.advertising.id"
accepted = "enabled"
reason = "Testing date format"
expires = "not-a-date"
"#;
        let err = CustomPolicy::from_str(toml).unwrap_err();
        assert!(err.contains("invalid expiry date 'not-a-date'"));
    }

    #[test]
    fn reject_empty_exception_reason() {
        let toml = r#"
schema = 1
extends = "baseline"

[[exceptions]]
control = "windows.advertising.id"
accepted = "enabled"
reason = "   "
expires = "2027-01-01"
"#;
        let err = CustomPolicy::from_str(toml).unwrap_err();
        assert!(err.contains("must provide a non-empty reason"));
    }

    #[test]
    fn reject_duplicate_exceptions() {
        let toml = r#"
schema = 1
extends = "baseline"

[[exceptions]]
control = "windows.advertising.id"
accepted = "enabled"
reason = "First"
expires = "2027-01-01"

[[exceptions]]
control = "windows.advertising.id"
accepted = "disabled"
reason = "Second"
expires = "2027-06-01"
"#;
        let err = CustomPolicy::from_str(toml).unwrap_err();
        assert!(err.contains("duplicate exception"));
    }

    #[test]
    fn test_date_utc_format() {
        let (y, m, d) = current_date_utc();
        assert!(y >= 2026);
        assert!((1..=12).contains(&m));
        assert!((1..=31).contains(&d));
        let iso = today_iso();
        assert_eq!(iso.len(), 10);
        assert_eq!(&iso[4..5], "-");
        assert_eq!(&iso[7..8], "-");
    }

    #[test]
    fn parse_toml_with_inline_comments_and_hashes_in_strings() {
        let toml = r#"
# Global policy comment
schema = 1 # schema version
extends = "builtin:baseline@0.1" # base profile

[controls."windows.advertising.id"] # disable ad id
mode = "review" # review mode

[[exceptions]] # exception table
control = "windows.security.wpad" # target control
accepted = "enabled" # keep enabled
reason = "Required for ticket #1234 legacy proxy" # contains hash inside string
expires = "2028-06-30" # expiration date
"#;
        let policy = CustomPolicy::from_str(toml).expect("parse toml with comments");
        assert_eq!(policy.schema, 1);
        assert_eq!(policy.extends, Profile::Baseline);
        assert_eq!(
            policy.controls.get("windows.advertising.id").unwrap().mode,
            Some(Mode::Review)
        );
        assert_eq!(policy.exceptions.len(), 1);
        assert_eq!(
            policy.exceptions[0].reason,
            "Required for ticket #1234 legacy proxy"
        );
        assert_eq!(policy.exceptions[0].expires, "2028-06-30");
    }
}
