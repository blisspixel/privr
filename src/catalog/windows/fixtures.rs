//! File-backed, synthetic observations replayed through the compiled probes.
//!
//! No live host discovery or registry reads are permitted in this suite.

use super::*;
use crate::engine::evaluate::{Mode, evaluate};
use crate::model::outcome::{Effect, Exception, Outcome, RemediationReason, Support};
use crate::platform::windows::registry::{Registry, key};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema: u32,
    case: String,
    control: String,
    provenance: Provenance,
    host: HostFacts,
    observations: Vec<RecordedRead>,
    expected: Expected,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Provenance {
    origin: String,
    authored_on: String,
    description: String,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TargetName {
    Policy,
    Setting,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedRead {
    target: TargetName,
    view: String,
    evidence: Evidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    state: Option<SemanticState>,
    source: ManagementSource,
    uncertainty: Option<Uncertainty>,
    ineffective: Option<Ineffective>,
    outcome: Outcome,
    support: Support,
    remediation: Remediation,
    remediation_reason: Option<RemediationReason>,
    note_contains: Option<String>,
}

const ADVERTISING: &[(&str, &str)] = &[
    (
        "absent-default",
        include_str!("../../../tests/fixtures/windows.advertising.id/absent-default.json"),
    ),
    (
        "user-disabled",
        include_str!("../../../tests/fixtures/windows.advertising.id/user-disabled.json"),
    ),
    (
        "user-enabled",
        include_str!("../../../tests/fixtures/windows.advertising.id/user-enabled.json"),
    ),
    (
        "policy-disabled-conflict",
        include_str!(
            "../../../tests/fixtures/windows.advertising.id/policy-disabled-conflict.json"
        ),
    ),
    (
        "policy-user-choice-disabled",
        include_str!(
            "../../../tests/fixtures/windows.advertising.id/policy-user-choice-disabled.json"
        ),
    ),
    (
        "policy-user-choice-enabled",
        include_str!(
            "../../../tests/fixtures/windows.advertising.id/policy-user-choice-enabled.json"
        ),
    ),
    (
        "policy-user-choice-absent",
        include_str!(
            "../../../tests/fixtures/windows.advertising.id/policy-user-choice-absent.json"
        ),
    ),
    (
        "policy-user-choice-denied",
        include_str!(
            "../../../tests/fixtures/windows.advertising.id/policy-user-choice-denied.json"
        ),
    ),
    (
        "policy-user-choice-omitted",
        include_str!(
            "../../../tests/fixtures/windows.advertising.id/policy-user-choice-omitted.json"
        ),
    ),
    (
        "policy-with-omitted-user",
        include_str!(
            "../../../tests/fixtures/windows.advertising.id/policy-with-omitted-user.json"
        ),
    ),
    (
        "policy-with-denied-user",
        include_str!("../../../tests/fixtures/windows.advertising.id/policy-with-denied-user.json"),
    ),
    (
        "policy-denied",
        include_str!("../../../tests/fixtures/windows.advertising.id/policy-denied.json"),
    ),
    (
        "user-denied",
        include_str!("../../../tests/fixtures/windows.advertising.id/user-denied.json"),
    ),
    (
        "policy-malformed",
        include_str!("../../../tests/fixtures/windows.advertising.id/policy-malformed.json"),
    ),
    (
        "user-malformed",
        include_str!("../../../tests/fixtures/windows.advertising.id/user-malformed.json"),
    ),
    (
        "policy-unsupported",
        include_str!("../../../tests/fixtures/windows.advertising.id/policy-unsupported.json"),
    ),
    (
        "user-unsupported",
        include_str!("../../../tests/fixtures/windows.advertising.id/user-unsupported.json"),
    ),
    (
        "policy-undetermined",
        include_str!("../../../tests/fixtures/windows.advertising.id/policy-undetermined.json"),
    ),
    (
        "user-undetermined",
        include_str!("../../../tests/fixtures/windows.advertising.id/user-undetermined.json"),
    ),
    (
        "policy-wrong-type",
        include_str!("../../../tests/fixtures/windows.advertising.id/policy-wrong-type.json"),
    ),
    (
        "user-wrong-type",
        include_str!("../../../tests/fixtures/windows.advertising.id/user-wrong-type.json"),
    ),
    (
        "policy-short-dword",
        include_str!("../../../tests/fixtures/windows.advertising.id/policy-short-dword.json"),
    ),
    (
        "user-short-dword",
        include_str!("../../../tests/fixtures/windows.advertising.id/user-short-dword.json"),
    ),
    (
        "policy-undocumented-value",
        include_str!(
            "../../../tests/fixtures/windows.advertising.id/policy-undocumented-value.json"
        ),
    ),
    (
        "user-undocumented-value",
        include_str!("../../../tests/fixtures/windows.advertising.id/user-undocumented-value.json"),
    ),
    (
        "omitted-policy",
        include_str!("../../../tests/fixtures/windows.advertising.id/omitted-policy.json"),
    ),
    (
        "omitted-user",
        include_str!("../../../tests/fixtures/windows.advertising.id/omitted-user.json"),
    ),
];

const DIAGNOSTICS: &[(&str, &str)] = &[
    (
        "absent-default",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/absent-default.json"),
    ),
    (
        "setting-required",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/setting-required.json"),
    ),
    (
        "setting-optional",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/setting-optional.json"),
    ),
    (
        "setting-enhanced",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/setting-enhanced.json"),
    ),
    (
        "zero-professional",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/zero-professional.json"),
    ),
    (
        "zero-enterprise",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/zero-enterprise.json"),
    ),
    (
        "zero-unknown-edition",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/zero-unknown-edition.json"),
    ),
    (
        "policy-required-conflict",
        include_str!(
            "../../../tests/fixtures/windows.diagnostics.level/policy-required-conflict.json"
        ),
    ),
    (
        "policy-optional-conflict",
        include_str!(
            "../../../tests/fixtures/windows.diagnostics.level/policy-optional-conflict.json"
        ),
    ),
    (
        "policy-zero-professional",
        include_str!(
            "../../../tests/fixtures/windows.diagnostics.level/policy-zero-professional.json"
        ),
    ),
    (
        "policy-with-omitted-setting",
        include_str!(
            "../../../tests/fixtures/windows.diagnostics.level/policy-with-omitted-setting.json"
        ),
    ),
    (
        "policy-with-denied-setting",
        include_str!(
            "../../../tests/fixtures/windows.diagnostics.level/policy-with-denied-setting.json"
        ),
    ),
    (
        "policy-denied",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/policy-denied.json"),
    ),
    (
        "setting-denied",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/setting-denied.json"),
    ),
    (
        "policy-malformed",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/policy-malformed.json"),
    ),
    (
        "setting-malformed",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/setting-malformed.json"),
    ),
    (
        "policy-unsupported",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/policy-unsupported.json"),
    ),
    (
        "setting-unsupported",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/setting-unsupported.json"),
    ),
    (
        "policy-undetermined",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/policy-undetermined.json"),
    ),
    (
        "setting-undetermined",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/setting-undetermined.json"),
    ),
    (
        "policy-wrong-type",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/policy-wrong-type.json"),
    ),
    (
        "setting-wrong-type",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/setting-wrong-type.json"),
    ),
    (
        "policy-short-dword",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/policy-short-dword.json"),
    ),
    (
        "setting-short-dword",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/setting-short-dword.json"),
    ),
    (
        "policy-undocumented-value",
        include_str!(
            "../../../tests/fixtures/windows.diagnostics.level/policy-undocumented-value.json"
        ),
    ),
    (
        "setting-undocumented-value",
        include_str!(
            "../../../tests/fixtures/windows.diagnostics.level/setting-undocumented-value.json"
        ),
    ),
    (
        "omitted-policy",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/omitted-policy.json"),
    ),
    (
        "omitted-setting",
        include_str!("../../../tests/fixtures/windows.diagnostics.level/omitted-setting.json"),
    ),
];

fn replay(control: Control, files: &[(&str, &str)], setting: Target, policy: Target) {
    for (name, json) in files {
        let fixture: Fixture = serde_json::from_str(json)
            .unwrap_or_else(|error| panic!("{} {name}: {error}", control.spec.id));
        assert_eq!(fixture.schema, 1, "{name}: unsupported fixture schema");
        assert_eq!(fixture.case, *name);
        assert_eq!(fixture.control, control.spec.id);
        assert_eq!(fixture.provenance.origin, "synthetic");
        assert!(!fixture.provenance.authored_on.is_empty());
        assert!(!fixture.provenance.description.is_empty());
        assert_eq!(fixture.host.platform, Platform::Windows);

        let mut reads = BTreeMap::new();
        for read in fixture.observations {
            let (target, source) = match read.target {
                TargetName::Policy => (policy, ManagementSource::GroupPolicy),
                TargetName::Setting => (
                    setting,
                    match setting.hive {
                        Hive::CurrentUser => ManagementSource::User,
                        Hive::LocalMachine => ManagementSource::LocalPolicy,
                    },
                ),
            };
            assert_eq!(read.view, "native", "{name}: unexpected registry view");
            assert_eq!(target.view, View::Native);
            assert_eq!(read.evidence.source(), source, "{name}: wrong authority");
            assert!(
                reads.insert(key(&target), read.evidence).is_none(),
                "{name}: duplicate target observation"
            );
        }

        // Missing entries deliberately stay missing. Registry::Recorded returns
        // Undetermined rather than inventing an Absent observation.
        let registry = Registry::Recorded(reads);
        let context = Context {
            host: &fixture.host,
            registry: &registry,
        };
        let resolution = control.observe(&context);
        let expected = fixture.expected;
        assert_eq!(resolution.state, expected.state, "{name}: effective state");
        assert_eq!(resolution.source, expected.source, "{name}: authority");
        assert_eq!(
            resolution.uncertainty, expected.uncertainty,
            "{name}: uncertainty"
        );
        assert_eq!(
            resolution.ineffective, expected.ineffective,
            "{name}: ineffective"
        );
        assert!(resolution.honored, "{name}: unexpected inert interface");
        assert_eq!(resolution.effect, Effect::Active, "{name}: effect");
        match expected.note_contains {
            Some(text) => assert!(
                resolution
                    .note
                    .as_ref()
                    .is_some_and(|note| note.contains(&text)),
                "{name}: missing effective-state explanation"
            ),
            None => assert!(resolution.note.is_none(), "{name}: unexpected explanation"),
        }

        let result = evaluate(
            &control.spec,
            Mode::Enforce,
            &resolution,
            &fixture.host,
            Exception::None,
        );
        assert_eq!(result.id, fixture.control, "{name}: control identifier");
        assert_eq!(result.outcome, expected.outcome, "{name}: outcome");
        assert_eq!(
            result.management_source, expected.source,
            "{name}: result authority"
        );
        assert_eq!(result.support, expected.support, "{name}: support");
        assert_eq!(
            result.remediation, expected.remediation,
            "{name}: remediation"
        );
        assert_eq!(
            result.remediation_reason, expected.remediation_reason,
            "{name}: remediation reason"
        );
        assert_eq!(
            result.ineffective, resolution.ineffective,
            "{name}: result ineffective"
        );
        assert_eq!(result.note, resolution.note, "{name}: result explanation");
        assert!(result.is_coherent(), "{name}: incoherent result");

        if expected.uncertainty.is_some() {
            assert_ne!(result.outcome, Outcome::Pass, "{name}: false pass");
            assert!(result.outcome.conceals_state(), "{name}: concealed failure");
            assert_ne!(
                result.remediation,
                Remediation::Automatic,
                "{name}: unsafe remediation"
            );
        }
    }
}

#[test]
fn advertising_fixtures_replay_the_real_probe_and_evaluator() {
    replay(
        advertising_id(),
        ADVERTISING,
        ADVERTISING_USER,
        ADVERTISING_POLICY,
    );
}

#[test]
fn diagnostic_fixtures_replay_the_real_probe_and_evaluator() {
    replay(
        diagnostics_level(),
        DIAGNOSTICS,
        DIAGNOSTICS_SETTING,
        DIAGNOSTICS_POLICY,
    );
}

#[test]
fn every_fixture_file_is_replayed() {
    for (control, files) in [
        ("windows.advertising.id", ADVERTISING),
        ("windows.diagnostics.level", DIAGNOSTICS),
    ] {
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(control);
        let mut actual: Vec<_> = std::fs::read_dir(directory)
            .expect("fixture directory")
            .map(|entry| {
                entry
                    .expect("fixture entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8 filename")
            })
            .collect();
        let mut expected: Vec<_> = files
            .iter()
            .map(|(name, _)| format!("{name}.json"))
            .collect();
        actual.sort();
        expected.sort();
        assert_eq!(
            actual, expected,
            "{control}: a fixture is not in the replay suite"
        );
    }
}
