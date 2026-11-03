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
        assert_eq!(result.policy_mode, Mode::Enforce, "{name}: policy mode");
        assert_eq!(result.desired, control.spec.desired.0, "{name}: desired");
        assert!(
            result.source_refs.is_empty(),
            "{name}: detached source refs"
        );
        if expected.uncertainty.is_some() {
            assert_eq!(
                result.observation_basis,
                crate::model::outcome::ObservationBasis::Inconclusive,
                "{name}: basis"
            );
            assert!(result.observed.is_none(), "{name}: invented observation");
            assert_eq!(
                result.observation_reason, expected.uncertainty,
                "{name}: observation reason"
            );
            assert!(!result.confident, "{name}: uncertain result was confident");
        } else if expected.outcome == Outcome::NotApplicable {
            assert_eq!(
                result.observation_basis,
                crate::model::outcome::ObservationBasis::NotApplicable,
                "{name}: basis"
            );
            assert!(result.observed.is_none(), "{name}: invented observation");
        } else if expected.state.is_some() {
            assert_eq!(
                result.observation_basis,
                crate::model::outcome::ObservationBasis::Established,
                "{name}: basis"
            );
            assert_eq!(
                result.observed.as_deref(),
                expected.state.as_ref().map(|state| state.0.as_str()),
                "{name}: observed"
            );
            assert!(result.observation_reason.is_none(), "{name}: extra reason");
            assert_eq!(
                result.confident,
                !result.outcome.conceals_state(),
                "{name}: confidence"
            );
        }
        let rendered = serde_json::to_string(&result).expect("result json");
        assert!(!rendered.contains("\"bytes\""), "{name}: raw bytes");
        if *name == "zero-professional" || *name == "policy-zero-professional" {
            assert_eq!(result.observed.as_deref(), Some("required"), "{name}");
            assert_eq!(result.outcome, Outcome::Pass, "{name}");
            assert_eq!(
                result.ineffective,
                Some(crate::model::outcome::Ineffective::EditionGated),
                "{name}"
            );
            let note = result.note.as_deref().unwrap_or("");
            let flat_note = note.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(
                flat_note.contains("required diagnostic data"),
                "{name}: {flat_note}"
            );
            assert!(
                !flat_note
                    .to_ascii_lowercase()
                    .contains("transmission is off"),
                "{name}: {flat_note}"
            );
        }

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

const LLMNR: &[(&str, &str)] = &[
    (
        "absent-default",
        include_str!("../../../tests/fixtures/windows.security.llmnr/absent-default.json"),
    ),
    (
        "disabled-compliant",
        include_str!("../../../tests/fixtures/windows.security.llmnr/disabled-compliant.json"),
    ),
    (
        "enabled-drift",
        include_str!("../../../tests/fixtures/windows.security.llmnr/enabled-drift.json"),
    ),
    (
        "policy-denied",
        include_str!("../../../tests/fixtures/windows.security.llmnr/policy-denied.json"),
    ),
    (
        "policy-malformed",
        include_str!("../../../tests/fixtures/windows.security.llmnr/policy-malformed.json"),
    ),
];

#[test]
fn llmnr_fixtures_replay_the_real_probe_and_evaluator() {
    replay(security_llmnr(), LLMNR, LLMNR_MULTICAST, LLMNR_MULTICAST);
}

const THUMBNAIL: &[(&str, &str)] = &[
    (
        "absent-default",
        include_str!("../../../tests/fixtures/windows.storage.thumbnail-cache/absent-default.json"),
    ),
    (
        "disabled-compliant",
        include_str!(
            "../../../tests/fixtures/windows.storage.thumbnail-cache/disabled-compliant.json"
        ),
    ),
    (
        "enabled-drift",
        include_str!("../../../tests/fixtures/windows.storage.thumbnail-cache/enabled-drift.json"),
    ),
    (
        "user-denied",
        include_str!("../../../tests/fixtures/windows.storage.thumbnail-cache/user-denied.json"),
    ),
    (
        "user-malformed",
        include_str!("../../../tests/fixtures/windows.storage.thumbnail-cache/user-malformed.json"),
    ),
];

#[test]
fn thumbnail_fixtures_replay_the_real_probe_and_evaluator() {
    let thumbnail_control = controls()
        .into_iter()
        .find(|c| c.spec.id == "windows.storage.thumbnail-cache")
        .expect("thumbnail control");
    replay(
        thumbnail_control,
        THUMBNAIL,
        THUMBNAIL_CACHE.target,
        THUMBNAIL_CACHE.target,
    );
}

const COPILOT: &[(&str, &str)] = &[
    (
        "absent-default",
        include_str!("../../../tests/fixtures/windows.ai.copilot-shell/absent-default.json"),
    ),
    (
        "disabled-compliant",
        include_str!("../../../tests/fixtures/windows.ai.copilot-shell/disabled-compliant.json"),
    ),
    (
        "enabled-drift",
        include_str!("../../../tests/fixtures/windows.ai.copilot-shell/enabled-drift.json"),
    ),
    (
        "policy-denied",
        include_str!("../../../tests/fixtures/windows.ai.copilot-shell/policy-denied.json"),
    ),
    (
        "policy-malformed",
        include_str!("../../../tests/fixtures/windows.ai.copilot-shell/policy-malformed.json"),
    ),
];

#[test]
fn copilot_fixtures_replay_the_real_probe_and_evaluator() {
    let copilot_control = controls()
        .into_iter()
        .find(|c| c.spec.id == "windows.ai.copilot-shell")
        .expect("copilot control");
    replay(
        copilot_control,
        COPILOT,
        COPILOT_SHELL.target,
        COPILOT_SHELL.target,
    );
}

const RECALL: &[(&str, &str)] = &[
    (
        "build-22631-disabled",
        include_str!(
            "../../../tests/fixtures/windows.ai.recall-snapshot/build-22631-disabled.json"
        ),
    ),
    (
        "build-26100-absent-default",
        include_str!(
            "../../../tests/fixtures/windows.ai.recall-snapshot/build-26100-absent-default.json"
        ),
    ),
    (
        "build-26100-disabled-compliant",
        include_str!(
            "../../../tests/fixtures/windows.ai.recall-snapshot/build-26100-disabled-compliant.json"
        ),
    ),
    (
        "build-26100-enabled-drift",
        include_str!(
            "../../../tests/fixtures/windows.ai.recall-snapshot/build-26100-enabled-drift.json"
        ),
    ),
    (
        "policy-denied",
        include_str!("../../../tests/fixtures/windows.ai.recall-snapshot/policy-denied.json"),
    ),
    (
        "policy-malformed",
        include_str!("../../../tests/fixtures/windows.ai.recall-snapshot/policy-malformed.json"),
    ),
];

#[test]
fn recall_fixtures_replay_the_real_probe_and_evaluator() {
    let recall_control = controls()
        .into_iter()
        .find(|c| c.spec.id == "windows.ai.recall-snapshot")
        .expect("recall control");
    replay(recall_control, RECALL, RECALL_POLICY, RECALL_POLICY);
}

const WPAD_FIXTURES: &[(&str, &str)] = &[
    (
        "absent-default",
        include_str!("../../../tests/fixtures/windows.security.wpad/absent-default.json"),
    ),
    (
        "disabled-compliant",
        include_str!("../../../tests/fixtures/windows.security.wpad/disabled-compliant.json"),
    ),
    (
        "enabled-drift",
        include_str!("../../../tests/fixtures/windows.security.wpad/enabled-drift.json"),
    ),
    (
        "policy-denied",
        include_str!("../../../tests/fixtures/windows.security.wpad/policy-denied.json"),
    ),
    (
        "policy-malformed",
        include_str!("../../../tests/fixtures/windows.security.wpad/policy-malformed.json"),
    ),
];

#[test]
fn wpad_fixtures_replay_the_real_probe_and_evaluator() {
    let wpad_control = controls()
        .into_iter()
        .find(|c| c.spec.id == "windows.security.wpad")
        .expect("wpad control");
    replay(wpad_control, WPAD_FIXTURES, WPAD_POLICY, WPAD_POLICY);
}

#[test]
fn every_fixture_file_is_replayed() {
    for (control, files) in [
        ("windows.advertising.id", ADVERTISING),
        ("windows.ai.copilot-shell", COPILOT),
        ("windows.ai.recall-snapshot", RECALL),
        ("windows.diagnostics.level", DIAGNOSTICS),
        ("windows.security.llmnr", LLMNR),
        ("windows.security.wpad", WPAD_FIXTURES),
        ("windows.storage.thumbnail-cache", THUMBNAIL),
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
