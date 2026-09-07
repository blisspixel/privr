//! Windows control definitions.
//!
//! Each probe owns its own registry targets. Nothing outside this module can
//! name a path, a value, or a view.
//!
//! Binding rule: the ordinary setting value is the primary source and the
//! policy form is a secondary source consulted for precedence. Doing it the
//! other way round produces a control that is inert on the editions people
//! actually run, because many documented policies apply only to Enterprise,
//! Education, and Server.

use super::{Context, Control, Source};
use crate::engine::evaluate::{ControlSpec, Resolution, SemanticState, Uncertainty};
use crate::model::applicability::{Applicability, Predicate, Variant};
use crate::model::evidence::{Evidence, Observation, RawValue};
use crate::model::host::{HostFacts, ManagementSource, Platform};
use crate::model::outcome::{Ineffective, Maturity, Remediation, Reversibility};
use crate::platform::windows::registry::{Hive, Target, View};

fn enabled() -> SemanticState {
    SemanticState::new("enabled")
}

fn disabled() -> SemanticState {
    SemanticState::new("disabled")
}

/// The per-user advertising identifier setting.
///
/// Zero means the identifier is off. Absent means on, because Windows enables
/// it by default.
const ADVERTISING_USER: Target = Target::new(
    Hive::CurrentUser,
    r"Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo",
    "Enabled",
    View::Native,
);

/// The policy form of the same setting.
///
/// Note the inverted polarity against the user setting above: here one means
/// the identifier is off, whereas in the user setting zero means off. Two value
/// names for one semantic state, with opposite senses, is exactly the trap that
/// makes a naive "zero is private" assumption wrong. Each source is decoded by
/// its own function rather than a shared convention.
const ADVERTISING_POLICY: Target = Target::new(
    Hive::LocalMachine,
    r"SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo",
    "DisabledByGroupPolicy",
    View::Native,
);

fn decode_user_setting(value: &RawValue) -> Option<SemanticState> {
    match value.as_u32()? {
        0 => Some(disabled()),
        1 => Some(enabled()),
        // A value outside the documented set is not evidence of either state.
        _ => None,
    }
}

fn decode_policy(value: &RawValue) -> Option<SemanticState> {
    match value.as_u32()? {
        1 => Some(disabled()),
        0 => Some(enabled()),
        _ => None,
    }
}

/// Resolve the advertising identifier state.
///
/// The policy form is consulted first because it overrides the user setting
/// where it is present, then the user setting, which is the source that
/// actually governs on an unmanaged machine.
fn probe_advertising_id(ctx: &Context) -> Resolution {
    let policy = ctx
        .registry
        .read(&ADVERTISING_POLICY, ManagementSource::GroupPolicy);

    // A present policy value governs. Absent policy is not a finding: it simply
    // means the user setting decides.
    if let Evidence::Present { value, .. } = &policy {
        return match decode_policy(value) {
            Some(state) => Resolution::determined(state, ManagementSource::GroupPolicy),
            None => Resolution::uncertain(Uncertainty::Malformed, ManagementSource::GroupPolicy),
        };
    }
    // A policy we were not allowed to read might be governing this value, so we
    // cannot fall through to the user setting and claim to know the answer.
    if !policy.is_conclusive() {
        return Resolution::uncertain(Uncertainty::Denied, ManagementSource::GroupPolicy);
    }

    let user = ctx.registry.read(&ADVERTISING_USER, ManagementSource::User);
    let observation = Observation::new(vec![user]);
    Resolution::from_observation(
        &observation,
        &[ManagementSource::User],
        decode_user_setting,
        // Windows enables the advertising identifier by default, so an absent
        // value means on, not off.
        &enabled(),
    )
}

// Diagnostic data.
//
// The value zero is documented as applying only to Enterprise, Education, and
// Server. Microsoft states that using it elsewhere is "equivalent to setting
// the value of 1". On every other edition the write succeeds, the value reads
// back as zero, and the machine sends required diagnostic data regardless.
//
// This is the single most common false pass in this category, and this control
// exists as much to demonstrate it as to check it.

/// Editions that honor the lowest diagnostic level.
///
/// Enumerated rather than negated, so a future edition is treated as not
/// honoring it until someone checks, which is the safe direction.
const EDITIONS_HONORING_SECURITY_LEVEL: &[&str] = &[
    "Enterprise",
    "EnterpriseS",
    "EnterpriseG",
    "IoTEnterprise",
    "Education",
    "EnterpriseSN",
    "ServerStandard",
    "ServerDatacenter",
];

/// The policy form, which an administrator or management sets.
const DIAGNOSTICS_POLICY: Target = Target::new(
    Hive::LocalMachine,
    r"SOFTWARE\Policies\Microsoft\Windows\DataCollection",
    "AllowTelemetry",
    View::Native,
);

/// The form the settings interface and most tools write.
const DIAGNOSTICS_SETTING: Target = Target::new(
    Hive::LocalMachine,
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection",
    "AllowTelemetry",
    View::Native,
);

fn diagnostics_state(level: u32) -> Option<SemanticState> {
    match level {
        0 => Some(SemanticState::new("security")),
        1 => Some(SemanticState::new("required")),
        2 => Some(SemanticState::new("enhanced")),
        3 => Some(SemanticState::new("optional")),
        _ => None,
    }
}

fn honors_security_level(host: &HostFacts) -> Option<bool> {
    host.edition.known().map(|edition| {
        EDITIONS_HONORING_SECURITY_LEVEL
            .iter()
            .any(|candidate| candidate.eq_ignore_ascii_case(edition))
    })
}

/// Resolve the effective diagnostic level, accounting for edition gating.
fn probe_diagnostics_level(ctx: &Context) -> Resolution {
    let mut configured: Option<(u32, ManagementSource)> = None;

    for (target, source) in [
        (&DIAGNOSTICS_POLICY, ManagementSource::GroupPolicy),
        (&DIAGNOSTICS_SETTING, ManagementSource::LocalPolicy),
    ] {
        match ctx.registry.read(target, source) {
            Evidence::Present { value, .. } => match value.as_u32() {
                Some(level) => {
                    configured = Some((level, source));
                    break;
                }
                None => return Resolution::uncertain(Uncertainty::Malformed, source),
            },
            Evidence::Absent { .. } => {}
            // A source we could not read might be the one governing this value.
            _ => return Resolution::uncertain(Uncertainty::Denied, source),
        }
    }

    // Absent everywhere means the platform default governs, which is the full
    // optional level on consumer editions.
    let Some((level, source)) = configured else {
        return Resolution::determined(SemanticState::new("optional"), ManagementSource::Default);
    };

    let Some(state) = diagnostics_state(level) else {
        return Resolution::uncertain(Uncertainty::Malformed, source);
    };

    if level != 0 {
        return Resolution::determined(state, source);
    }

    // The gated case. What is configured and what the platform acts on differ.
    match honors_security_level(ctx.host) {
        Some(true) => Resolution::determined(state, source),
        Some(false) => Resolution::determined(SemanticState::new("required"), source)
            .configured_but_ineffective(
            Ineffective::EditionGated,
            "A level of 0 is configured, but this Windows edition does not honor it.              Microsoft documents value 0 as applying only to Enterprise, Education, and              Server, and as equivalent to 1 elsewhere. This machine sends required              diagnostic data.",
        ),
        // Without knowing the edition we cannot say which of two different
        // states is in effect, and guessing either way would be a false claim.
        None => Resolution::uncertain(Uncertainty::Undetermined, source),
    }
}

fn diagnostics_level() -> Control {
    Control {
        spec: ControlSpec {
            id: "windows.diagnostics.level".to_owned(),
            title: "Diagnostic data level".to_owned(),
            section: "diagnostics".to_owned(),
            applicability: Applicability::new(vec![Variant::new(
                "windows",
                vec![Predicate::Platform(Platform::Windows)],
            )]),
            // The lowest level ordinary editions actually honor. Asking for
            // less would mean reporting drift no operator could ever clear.
            desired: SemanticState::new("required"),
            reversibility: Reversibility::Exact,
            maturity: Maturity::Automated,
            verified_through: None,
            remediation: Remediation::AuditOnly,
            remediation_reason: None,
        },
        title: "Diagnostic data level",
        summary: "Windows sends diagnostic data about how the machine and its apps                   behave. The optional level adds browsing and typing activity,                   inventory, and memory captured when something crashes.",
        rationale: "Microsoft's own field lists for the optional level include text                     typed in the address bar and search box, available network names,                     the device serial number, files identified as a possible cause of a                     crash, and memory dumps that can contain everything in use at the                     time. The required level is the floor on ordinary editions.",
        tradeoff: Some(
            "Microsoft receives less information about faults you encounter, which              can mean a problem specific to your setup takes longer to be noticed.",
        ),
        mitigation: Some(
            "Local crash diagnosis is unaffected. Reliability history and the event              log continue to work, and you can still report a problem deliberately.",
        ),
        sources: &[
            Source {
                url: "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-system",
                claim: "States that value 0 applies only to Enterprise, Education, and                         Server, and is equivalent to 1 on other editions.",
                reviewed: "2026-09-07",
            },
            Source {
                url: "https://learn.microsoft.com/windows/privacy/windows-diagnostic-data",
                claim: "Enumerates the data types collected at the optional level.",
                reviewed: "2026-09-07",
            },
        ],
        probe: probe_diagnostics_level,
    }
}

fn advertising_id() -> Control {
    Control {
        spec: ControlSpec {
            id: "windows.advertising.id".to_owned(),
            title: "Advertising identifier".to_owned(),
            section: "advertising".to_owned(),
            applicability: Applicability::new(vec![Variant::new(
                "windows",
                vec![Predicate::Platform(Platform::Windows)],
            )]),
            desired: disabled(),
            reversibility: Reversibility::Exact,
            maturity: Maturity::Automated,
            // Read-only for now. Remediation arrives with the transaction
            // journal, not before.
            verified_through: None,
            remediation: Remediation::AuditOnly,
            remediation_reason: None,
        },
        title: "Advertising identifier",
        summary: "Windows gives apps a per-user identifier so advertising you see \
                  can be linked across different apps.",
        rationale: "The identifier lets separate applications correlate what you do \
                    into one profile. Turning it off does not reduce the number of \
                    ads, it removes the shared key that links them together.",
        tradeoff: Some("Advertising becomes less relevant to you."),
        mitigation: Some(
            "Nothing else depends on this identifier. Apps continue to work \
             normally and you can turn it back on at any time.",
        ),
        sources: &[Source {
            url: "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy",
            claim: "Documents the advertising identifier setting and its policy form.",
            reviewed: "2026-09-07",
        }],
        probe: probe_advertising_id,
    }
}

// User-scope toggles.
//
// These are preferred over machine-scope equivalents wherever both exist. A
// user-scope setting needs no elevation, so an unelevated check on a personal
// machine is already worth running rather than demanding a prompt before it
// says anything useful.

/// A setting that is a single value meaning on or off.
struct Toggle {
    target: Target,
    /// The stored value that means the collection is off.
    private_value: u32,
    /// The state that applies when no value is stored.
    absent_means: &'static str,
}

impl Toggle {
    fn probe(&self, ctx: &Context) -> Resolution {
        match ctx.registry.read(&self.target, ManagementSource::User) {
            Evidence::Present { value, .. } => match value.as_u32() {
                Some(stored) => Resolution::determined(
                    if stored == self.private_value {
                        disabled()
                    } else {
                        enabled()
                    },
                    ManagementSource::User,
                ),
                // A value we cannot interpret is malformed evidence, never a
                // silent fallback to the documented default.
                None => Resolution::uncertain(Uncertainty::Malformed, ManagementSource::User),
            },
            Evidence::Absent { .. } => Resolution::determined(
                SemanticState::new(self.absent_means),
                ManagementSource::Default,
            ),
            Evidence::Denied { .. } => {
                Resolution::uncertain(Uncertainty::Denied, ManagementSource::User)
            }
            _ => Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::User),
        }
    }
}

const TAILORED_EXPERIENCES: Toggle = Toggle {
    target: Target::new(
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\Privacy",
        "TailoredExperiencesWithDiagnosticDataEnabled",
        View::Native,
    ),
    private_value: 0,
    absent_means: "enabled",
};

const CLOUD_CLIPBOARD: Toggle = Toggle {
    target: Target::new(
        Hive::CurrentUser,
        r"Software\Microsoft\Clipboard",
        "CloudClipboardAutomaticUpload",
        View::Native,
    ),
    private_value: 0,
    absent_means: "disabled",
};

const WEB_SEARCH: Toggle = Toggle {
    target: Target::new(
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\Search",
        "BingSearchEnabled",
        View::Native,
    ),
    private_value: 0,
    absent_means: "enabled",
};

const SUGGESTED_APPS: Toggle = Toggle {
    target: Target::new(
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
        "SilentInstalledAppsEnabled",
        View::Native,
    ),
    private_value: 0,
    absent_means: "enabled",
};

/// Typing and inking personalisation, which is two values rather than one.
///
/// Both restrictions must be in place. Reporting the setting as off because one
/// of them is would be a false pass, and the two are set independently.
const IMPLICIT_TEXT: Target = Target::new(
    Hive::CurrentUser,
    r"Software\Microsoft\InputPersonalization",
    "RestrictImplicitTextCollection",
    View::Native,
);
const IMPLICIT_INK: Target = Target::new(
    Hive::CurrentUser,
    r"Software\Microsoft\InputPersonalization",
    "RestrictImplicitInkCollection",
    View::Native,
);

fn probe_input_personalization(ctx: &Context) -> Resolution {
    let mut all_restricted = true;

    for target in [&IMPLICIT_TEXT, &IMPLICIT_INK] {
        match ctx.registry.read(target, ManagementSource::User) {
            Evidence::Present { value, .. } => match value.as_u32() {
                // One means collection is restricted. Note the polarity is the
                // opposite of most toggles in this catalogue.
                Some(1) => {}
                Some(_) => all_restricted = false,
                None => {
                    return Resolution::uncertain(Uncertainty::Malformed, ManagementSource::User);
                }
            },
            // Absent means unrestricted, which is the collecting state.
            Evidence::Absent { .. } => all_restricted = false,
            Evidence::Denied { .. } => {
                return Resolution::uncertain(Uncertainty::Denied, ManagementSource::User);
            }
            _ => {
                return Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::User);
            }
        }
    }

    Resolution::determined(
        if all_restricted {
            disabled()
        } else {
            enabled()
        },
        ManagementSource::User,
    )
}

/// Build a control around a single user-scope toggle.
#[allow(clippy::too_many_arguments)]
fn toggle_control(
    id: &str,
    section: &str,
    title: &'static str,
    summary: &'static str,
    rationale: &'static str,
    tradeoff: Option<&'static str>,
    mitigation: Option<&'static str>,
    sources: &'static [Source],
    probe: fn(&Context) -> Resolution,
) -> Control {
    Control {
        spec: ControlSpec {
            id: id.to_owned(),
            title: title.to_owned(),
            section: section.to_owned(),
            applicability: Applicability::new(vec![Variant::new(
                "windows",
                vec![Predicate::Platform(Platform::Windows)],
            )]),
            desired: disabled(),
            reversibility: Reversibility::Exact,
            maturity: Maturity::Automated,
            verified_through: None,
            remediation: Remediation::AuditOnly,
            remediation_reason: None,
        },
        title,
        summary,
        rationale,
        tradeoff,
        mitigation,
        sources,
        probe,
    }
}

const PRIVACY_CSP: &str =
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy";
const TEXTINPUT_CSP: &str =
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-textinput";
const SEARCH_CSP: &str =
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-search";
const EXPERIENCE_CSP: &str =
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-experience";

/// Every Windows control, in stable sorted order by identifier.
pub fn controls() -> Vec<Control> {
    let mut controls = vec![
        advertising_id(),
        diagnostics_level(),
        toggle_control(
            "windows.clipboard.cross-device",
            "clipboard",
            "Cross-device clipboard",
            "What you copy can be uploaded so it can be pasted on your other devices.",
            "Copied text routinely includes passwords, tokens, addresses, and \
             fragments of private documents. Syncing it moves that material off \
             the machine to make it available elsewhere.",
            Some("You can no longer paste on another device something you copied here."),
            Some(
                "Local clipboard history is a separate setting and is unaffected. \
                 Paste on this machine works exactly as before.",
            ),
            &[Source {
                url: PRIVACY_CSP,
                claim: "Documents the cross-device clipboard setting.",
                reviewed: "2026-09-07",
            }],
            |ctx| CLOUD_CLIPBOARD.probe(ctx),
        ),
        toggle_control(
            "windows.experience.suggested-apps",
            "personalization",
            "Suggested app installs",
            "Windows can install and pin apps it suggests, without being asked each time.",
            "Choosing what to install is a decision worth keeping. Suggestions are \
             driven by profiling and the installs happen quietly, so software \
             appears that you did not choose.",
            Some("Windows stops suggesting and installing apps on your behalf."),
            Some("The Store still works normally and you can install anything yourself."),
            &[Source {
                url: EXPERIENCE_CSP,
                claim: "Documents suggested and silently installed application content.",
                reviewed: "2026-09-07",
            }],
            |ctx| SUGGESTED_APPS.probe(ctx),
        ),
        toggle_control(
            "windows.experience.tailored",
            "personalization",
            "Tailored experiences",
            "Windows uses your diagnostic data to personalise tips, advertisements, \
             and recommendations it shows you.",
            "This is the setting that turns diagnostic data into a profile used to \
             target you. Diagnostic collection and its use for personalisation are \
             two separate decisions, and this is the second one.",
            Some("Tips and recommendations become generic rather than targeted."),
            Some(
                "Nothing stops working. Windows still shows tips, they are simply \
                 not selected from your activity.",
            ),
            &[Source {
                url: PRIVACY_CSP,
                claim: "Documents tailored experiences with diagnostic data.",
                reviewed: "2026-09-07",
            }],
            |ctx| TAILORED_EXPERIENCES.probe(ctx),
        ),
        toggle_control(
            "windows.input.personalization",
            "personalization",
            "Typing and inking personalisation",
            "Windows can collect what you type and write to improve its own \
             suggestions, and can read your contacts to do it.",
            "This covers text you enter across the system rather than in one \
             application. Both the typing and the inking restrictions must be in \
             place, and they are set independently, so one alone leaves the other \
             collecting.",
            Some("Typing suggestions and autocorrect become less tailored to you."),
            Some(
                "The keyboard, handwriting, and spell check all continue to work. \
                 Only the personalisation that learns from your input stops.",
            ),
            &[Source {
                url: TEXTINPUT_CSP,
                claim: "Documents the implicit text and ink collection restrictions.",
                reviewed: "2026-09-07",
            }],
            probe_input_personalization,
        ),
        toggle_control(
            "windows.search.web",
            "search",
            "Web results in Start",
            "What you type into the Start menu is sent for web results alongside \
             the search of your own machine.",
            "The Start menu is where people look for their own files and \
             applications. Sending those terms out treats a local search as a web \
             search, and the two are rarely intended to be the same thing.",
            Some("Start stops showing web results, and searches only this machine."),
            Some("Searching the web in a browser is unaffected and unchanged."),
            &[Source {
                url: SEARCH_CSP,
                claim: "Documents web results in Windows search.",
                reviewed: "2026-09-07",
            }],
            |ctx| WEB_SEARCH.probe(ctx),
        ),
    ];
    controls.sort_by(|a, b| {
        (a.spec.section.clone(), a.spec.id.clone())
            .cmp(&(b.spec.section.clone(), b.spec.id.clone()))
    });
    controls
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::evaluate::{Mode, evaluate};
    use crate::model::host::{
        Architecture, ContainerKind, Fact, OsVersion, SessionFacts, WriteModel,
    };
    use crate::model::outcome::{Exception, Outcome};
    use crate::platform;
    use crate::platform::windows::registry::{Registry, key};
    use std::collections::BTreeMap;

    /// A context reading recorded evidence rather than the live machine.
    fn recorded<'a>(host: &'a HostFacts, registry: &'a Registry) -> Context<'a> {
        Context { host, registry }
    }

    /// Build a recording from target and evidence pairs.
    ///
    /// The recording holds the same `Evidence` type the live reader produces,
    /// so there is no separate fake that can drift from the real one.
    fn recording(entries: Vec<(Target, Evidence)>) -> Registry {
        Registry::Recorded(
            entries
                .into_iter()
                .map(|(target, evidence)| (key(&target), evidence))
                .collect::<BTreeMap<_, _>>(),
        )
    }

    fn windows_host() -> HostFacts {
        HostFacts {
            platform: Platform::Windows,
            version: Fact::Known(OsVersion::new(vec![10, 0, 26100], "10.0.26100")),
            architecture: Fact::Known(Architecture::X86_64),
            edition: Fact::Known("Professional".to_owned()),
            distribution: Fact::NotPresent,
            managed: Fact::Unknown,
            write_model: Fact::Known(WriteModel::Mutable),
            container: Fact::Known(ContainerKind::None),
            session: SessionFacts::not_present(),
            elevated: Fact::Known(false),
        }
    }

    #[test]
    fn the_lowest_diagnostic_level_is_gated_by_edition() {
        // The case this project exists for. Microsoft documents value 0 as
        // applying only to Enterprise, Education, and Server, and as equivalent
        // to 1 elsewhere. Reporting it as the security level on any other
        // edition is the most common false pass in this category.
        let mut host = windows_host();

        host.edition = Fact::Known("Enterprise".to_owned());
        assert_eq!(honors_security_level(&host), Some(true));

        for ordinary in [
            "Professional",
            "Core",
            "CoreSingleLanguage",
            "ProfessionalN",
        ] {
            host.edition = Fact::Known(ordinary.to_owned());
            assert_eq!(
                honors_security_level(&host),
                Some(false),
                "{ordinary} must not be treated as honoring level 0"
            );
        }
    }

    #[test]
    fn an_unrecognised_edition_is_assumed_not_to_honor_the_lowest_level() {
        // Enumerated rather than negated, so an edition nobody has checked is
        // treated as not honoring it until someone does.
        let mut host = windows_host();
        host.edition = Fact::Known("SomeFutureEdition".to_owned());
        assert_eq!(honors_security_level(&host), Some(false));
    }

    #[test]
    fn an_unknown_edition_leaves_the_level_undetermined() {
        // Without the edition, two different states are possible and neither
        // may be claimed.
        let mut host = windows_host();
        host.edition = Fact::Unknown;
        assert_eq!(honors_security_level(&host), None);
    }

    #[test]
    fn diagnostic_levels_map_to_documented_states_only() {
        assert_eq!(diagnostics_state(0), Some(SemanticState::new("security")));
        assert_eq!(diagnostics_state(1), Some(SemanticState::new("required")));
        assert_eq!(diagnostics_state(2), Some(SemanticState::new("enhanced")));
        assert_eq!(diagnostics_state(3), Some(SemanticState::new("optional")));
        // A value outside the documented set is not evidence of any level.
        assert_eq!(diagnostics_state(4), None);
        assert_eq!(diagnostics_state(99), None);
    }

    // Replayed evidence.
    //
    // These states cannot be produced on demand against a live machine without
    // changing it, which is why the failure paths had no coverage before. The
    // recording holds the same Evidence type the live probe produces, so there
    // is no separate fake that can drift from the real reader.

    #[test]
    fn a_denied_policy_read_never_falls_through_to_the_user_setting() {
        // The policy we were not allowed to read might be the thing governing
        // this value. Answering from the user setting would be a confident
        // guess, and it would look exactly like a real finding.
        let host = windows_host();
        let registry = recording(vec![
            (
                ADVERTISING_POLICY,
                Evidence::Denied {
                    source: ManagementSource::GroupPolicy,
                    reason: crate::model::evidence::DenialReason::Permission,
                },
            ),
            (
                ADVERTISING_USER,
                Evidence::Present {
                    source: ManagementSource::User,
                    value: RawValue::u32(0),
                },
            ),
        ]);

        let resolution = probe_advertising_id(&recorded(&host, &registry));
        assert_eq!(resolution.state, None, "answered despite a denied read");
        assert_eq!(resolution.uncertainty, Some(Uncertainty::Denied));

        let result = evaluate(
            &advertising_id().spec,
            Mode::Enforce,
            &resolution,
            &host,
            Exception::None,
        );
        assert_eq!(result.outcome, Outcome::Unknown);
        assert!(result.outcome.conceals_state());
    }

    #[test]
    fn a_policy_of_the_wrong_type_is_malformed_not_defaulted() {
        let host = windows_host();
        let registry = recording(vec![(
            ADVERTISING_POLICY,
            Evidence::Present {
                source: ManagementSource::GroupPolicy,
                value: RawValue::new(crate::model::evidence::ValueKind::String, b"1\0".to_vec()),
            },
        )]);

        let resolution = probe_advertising_id(&recorded(&host, &registry));
        assert_eq!(resolution.uncertainty, Some(Uncertainty::Malformed));
        assert_eq!(resolution.state, None);
    }

    #[test]
    fn a_governing_policy_overrides_the_user_setting() {
        // Opposite polarity in the two sources, so this also proves the
        // decoders are not shared.
        let host = windows_host();
        let registry = recording(vec![
            (
                ADVERTISING_POLICY,
                Evidence::Present {
                    source: ManagementSource::GroupPolicy,
                    value: RawValue::u32(1),
                },
            ),
            (
                ADVERTISING_USER,
                Evidence::Present {
                    source: ManagementSource::User,
                    value: RawValue::u32(1),
                },
            ),
        ]);

        let resolution = probe_advertising_id(&recorded(&host, &registry));
        // Policy 1 means disabled; user 1 means enabled. The policy governs.
        assert_eq!(resolution.state, Some(disabled()));
        assert_eq!(resolution.source, ManagementSource::GroupPolicy);
    }

    #[test]
    fn a_gated_diagnostic_level_is_reported_at_what_the_platform_does() {
        // The case the project exists for, replayed rather than depending on
        // the developer's machine happening to be configured this way.
        let mut host = windows_host();
        host.edition = Fact::Known("Professional".to_owned());

        let registry = recording(vec![
            (
                DIAGNOSTICS_POLICY,
                Evidence::Absent {
                    source: ManagementSource::GroupPolicy,
                },
            ),
            (
                DIAGNOSTICS_SETTING,
                Evidence::Present {
                    source: ManagementSource::LocalPolicy,
                    value: RawValue::u32(0),
                },
            ),
        ]);

        let resolution = probe_diagnostics_level(&recorded(&host, &registry));
        assert_eq!(
            resolution.state,
            Some(SemanticState::new("required")),
            "reported the stored value rather than the effective one"
        );
        assert_eq!(resolution.ineffective, Some(Ineffective::EditionGated));
        assert!(resolution.note.is_some());
    }

    #[test]
    fn the_same_configuration_on_enterprise_is_honored() {
        // Identical evidence, different edition, different truthful answer.
        let mut host = windows_host();
        host.edition = Fact::Known("Enterprise".to_owned());

        let registry = recording(vec![
            (
                DIAGNOSTICS_POLICY,
                Evidence::Absent {
                    source: ManagementSource::GroupPolicy,
                },
            ),
            (
                DIAGNOSTICS_SETTING,
                Evidence::Present {
                    source: ManagementSource::LocalPolicy,
                    value: RawValue::u32(0),
                },
            ),
        ]);

        let resolution = probe_diagnostics_level(&recorded(&host, &registry));
        assert_eq!(resolution.state, Some(SemanticState::new("security")));
        assert_eq!(resolution.ineffective, None);
        assert!(resolution.note.is_none());
    }

    #[test]
    fn an_unknown_edition_leaves_a_gated_level_undetermined() {
        let mut host = windows_host();
        host.edition = Fact::Unknown;

        let registry = recording(vec![
            (
                DIAGNOSTICS_POLICY,
                Evidence::Absent {
                    source: ManagementSource::GroupPolicy,
                },
            ),
            (
                DIAGNOSTICS_SETTING,
                Evidence::Present {
                    source: ManagementSource::LocalPolicy,
                    value: RawValue::u32(0),
                },
            ),
        ]);

        let resolution = probe_diagnostics_level(&recorded(&host, &registry));
        assert_eq!(
            resolution.state, None,
            "claimed a level without the edition"
        );
        assert_eq!(resolution.uncertainty, Some(Uncertainty::Undetermined));
    }

    #[test]
    fn typing_personalisation_fails_closed_when_only_one_restriction_holds() {
        // Two values set independently. One in place is not the setting being
        // off, and reporting it as off would be a false pass.
        let host = windows_host();
        let registry = recording(vec![
            (
                IMPLICIT_TEXT,
                Evidence::Present {
                    source: ManagementSource::User,
                    value: RawValue::u32(1),
                },
            ),
            (
                IMPLICIT_INK,
                Evidence::Absent {
                    source: ManagementSource::User,
                },
            ),
        ]);

        let resolution = probe_input_personalization(&recorded(&host, &registry));
        assert_eq!(
            resolution.state,
            Some(enabled()),
            "one restriction read as off"
        );
    }

    #[test]
    fn a_target_the_recording_never_captured_is_undetermined() {
        // A fixture that omits a target has not observed it absent. Treating
        // silence as absence would let a recording assert a documented default
        // it never captured.
        let host = windows_host();
        let empty = recording(Vec::new());

        let resolution = TAILORED_EXPERIENCES.probe(&recorded(&host, &empty));
        assert_eq!(resolution.state, None);
        assert_eq!(resolution.uncertainty, Some(Uncertainty::Undetermined));
    }

    #[test]
    fn typing_personalisation_needs_both_restrictions() {
        // Two values, set independently, and either one left unrestricted means
        // collection continues. Reporting the setting as off because one of them
        // is in place would be a false pass.
        let host = platform::discover();
        let ctx = Context::live(&host);
        let resolution = probe_input_personalization(&ctx);

        let text = ctx.registry.read(&IMPLICIT_TEXT, ManagementSource::User);
        let ink = ctx.registry.read(&IMPLICIT_INK, ManagementSource::User);

        let restricted = |evidence: &Evidence| match evidence {
            Evidence::Present { value, .. } => value.as_u32() == Some(1),
            _ => false,
        };

        if text.is_conclusive() && ink.is_conclusive() {
            let expected = if restricted(&text) && restricted(&ink) {
                disabled()
            } else {
                enabled()
            };
            assert_eq!(resolution.state, Some(expected));
        }
    }

    #[test]
    fn a_toggle_reports_the_documented_default_when_absent() {
        // Absent is a positive observation: the documented default governs. It
        // is never confused with a failed read.
        let missing = Toggle {
            target: Target::new(
                Hive::CurrentUser,
                r"Software\Microsoft\PrivrKeyThatDoesNotExist",
                "Anything",
                View::Native,
            ),
            private_value: 0,
            absent_means: "enabled",
        };

        let host = platform::discover();
        let resolution = missing.probe(&Context::live(&host));
        assert_eq!(resolution.state, Some(enabled()));
        assert_eq!(resolution.source, ManagementSource::Default);
        assert!(resolution.uncertainty.is_none());
    }

    #[test]
    fn every_toggle_probes_this_machine_conclusively() {
        for (name, toggle) in [
            ("tailored", &TAILORED_EXPERIENCES),
            ("clipboard", &CLOUD_CLIPBOARD),
            ("web search", &WEB_SEARCH),
            ("suggested apps", &SUGGESTED_APPS),
        ] {
            let host = platform::discover();
            let resolution = toggle.probe(&Context::live(&host));
            assert!(
                resolution.state.is_some(),
                "{name} was not determined: {resolution:?}"
            );
        }
    }

    #[test]
    fn the_catalogue_is_sorted_by_section_then_identifier() {
        // Deterministic ordering is a published property, and grouping in the
        // report depends on it.
        let controls = controls();
        let keys: Vec<(String, String)> = controls
            .iter()
            .map(|c| (c.spec.section.clone(), c.spec.id.clone()))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn every_control_states_a_desired_state_and_a_section() {
        for control in controls() {
            assert!(!control.spec.desired.0.is_empty(), "{}", control.spec.id);
            assert!(!control.spec.section.is_empty(), "{}", control.spec.id);
        }
    }

    #[test]
    fn the_two_sources_use_opposite_polarity() {
        // The trap this control exists to demonstrate. The same semantic state
        // is one value in the policy and the other in the user setting, so a
        // shared decoder would invert one of them.
        assert_eq!(decode_user_setting(&RawValue::u32(0)), Some(disabled()));
        assert_eq!(decode_policy(&RawValue::u32(0)), Some(enabled()));

        assert_eq!(decode_user_setting(&RawValue::u32(1)), Some(enabled()));
        assert_eq!(decode_policy(&RawValue::u32(1)), Some(disabled()));
    }

    #[test]
    fn an_undocumented_value_decodes_to_nothing() {
        // Neither state, so the caller reports malformed rather than guessing.
        assert_eq!(decode_user_setting(&RawValue::u32(7)), None);
        assert_eq!(decode_policy(&RawValue::u32(7)), None);
    }

    #[test]
    fn a_value_of_the_wrong_type_decodes_to_nothing() {
        use crate::model::evidence::ValueKind;
        let text = RawValue::new(ValueKind::String, b"0\0".to_vec());
        assert_eq!(decode_user_setting(&text), None);
    }

    #[test]
    fn probing_diagnostics_on_this_machine_is_conclusive() {
        let host = platform::discover();
        let resolution = probe_diagnostics_level(&Context::live(&host));
        assert!(
            resolution.state.is_some(),
            "diagnostic level was not determined: {resolution:?}"
        );
    }

    #[test]
    fn a_gated_level_is_classified_not_only_described() {
        // A caller must be able to branch on the failure rather than parse a
        // sentence, so the typed reason travels with the prose.
        let host = platform::discover();
        let resolution = probe_diagnostics_level(&Context::live(&host));

        if resolution.note.is_some() {
            assert_eq!(
                resolution.ineffective,
                Some(Ineffective::EditionGated),
                "a gated value must carry its typed reason"
            );
        }
        // The two always travel together, in both directions.
        assert_eq!(
            resolution.note.is_some(),
            resolution.ineffective.is_some(),
            "prose and classification disagree"
        );
    }

    #[test]
    fn every_ineffectiveness_reason_reads_as_a_sentence_fragment() {
        for reason in [
            Ineffective::EditionGated,
            Ineffective::SilentlyDiscarded,
            Ineffective::SupersededBySetting,
            Ineffective::RevertedByPlatform,
            Ineffective::ScopeIncomplete,
            Ineffective::WriteNotCommitted,
        ] {
            let summary = reason.summary();
            assert!(!summary.is_empty());
            // Phrased so it can follow "this setting is configured, but".
            assert!(
                !summary.ends_with('.'),
                "{reason:?} is a sentence not a clause"
            );
        }
    }

    #[test]
    fn a_gated_level_reports_what_the_platform_does_and_says_so() {
        // If this machine has the gated value configured, the reported state
        // must be what the platform acts on, and the discrepancy must be
        // stated rather than left for the operator to discover.
        let host = platform::discover();
        let resolution = probe_diagnostics_level(&Context::live(&host));

        if resolution.note.is_some() {
            assert_eq!(
                resolution.state,
                Some(SemanticState::new("required")),
                "a gated level must report the level actually in effect"
            );
            let note = resolution.note.as_deref().unwrap_or_default();
            assert!(note.contains("does not honor"), "note does not explain");
        }
    }

    #[test]
    fn probing_this_machine_produces_a_determined_state() {
        // An integration check against the real registry. Whatever this machine
        // holds, the answer must be conclusive rather than an error, because
        // both the present and absent cases are documented.
        let host = platform::discover();
        let resolution = probe_advertising_id(&Context::live(&host));

        assert!(
            resolution.state.is_some(),
            "advertising identifier state was not determined: {resolution:?}"
        );
        assert!(resolution.honored);
    }

    #[test]
    fn the_control_evaluates_end_to_end_on_this_machine() {
        let host = platform::discover();
        let control = advertising_id();
        let resolution = control.observe(&Context::live(&host));
        let result = evaluate(
            &control.spec,
            Mode::Enforce,
            &resolution,
            &host,
            Exception::None,
        );

        assert_eq!(result.id, "windows.advertising.id");
        assert_eq!(result.section, "advertising");
        // Both the present and absent cases are documented, so any Windows host
        // must reach a finding rather than an unknown.
        assert!(
            matches!(result.outcome, Outcome::Pass | Outcome::Drift),
            "expected a finding, got {:?}",
            result.outcome
        );
        assert!(result.is_coherent());
    }
}
