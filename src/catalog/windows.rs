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
use crate::model::posture::{FrictionTier, PostureDimension};
use crate::model::profile::Profile;
use crate::platform::windows::registry::{Hive, Target, View};

#[cfg(test)]
#[path = "windows/fixtures.rs"]
mod fixtures;

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
/// One restricts the identifier. Zero delegates the decision to the user.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdvertisingPolicy {
    Disabled,
    UserChoice,
}

fn decode_policy(value: &RawValue) -> Option<AdvertisingPolicy> {
    match value.as_u32()? {
        1 => Some(AdvertisingPolicy::Disabled),
        0 => Some(AdvertisingPolicy::UserChoice),
        _ => None,
    }
}

/// Resolve the advertising identifier state.
///
/// Only the enforcing policy value overrides the user setting.
fn probe_advertising_id(ctx: &Context) -> Resolution {
    let policy = ctx
        .registry
        .read(&ADVERTISING_POLICY, ManagementSource::GroupPolicy);

    // A policy we were not allowed to read might be governing this value, so we
    // cannot fall through to the user setting and claim to know the answer.
    match policy {
        Evidence::Present { source, value } => match decode_policy(&value) {
            Some(AdvertisingPolicy::Disabled) => {
                return Resolution::determined(disabled(), source);
            }
            Some(AdvertisingPolicy::UserChoice) => {}
            None => return Resolution::uncertain(Uncertainty::Malformed, source),
        },
        Evidence::Absent { .. } => {}
        Evidence::Denied { source, .. } => {
            return Resolution::uncertain(Uncertainty::Denied, source);
        }
        Evidence::Malformed { source, .. } => {
            return Resolution::uncertain(Uncertainty::Malformed, source);
        }
        Evidence::Unsupported { source } => {
            return Resolution::uncertain(Uncertainty::Unsupported, source);
        }
        Evidence::Undetermined { source, .. } => {
            return Resolution::uncertain(Uncertainty::Undetermined, source);
        }
    }

    let user = ctx.registry.read(&ADVERTISING_USER, ManagementSource::User);
    match user {
        Evidence::Absent { .. } => Resolution::determined(enabled(), ManagementSource::Default),
        evidence => Resolution::from_observation(
            &Observation::new(vec![evidence]),
            &[ManagementSource::User],
            decode_user_setting,
            &enabled(),
        ),
    }
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
            Evidence::Denied { .. } => {
                return Resolution::uncertain(Uncertainty::Denied, source);
            }
            Evidence::Malformed { .. } => {
                return Resolution::uncertain(Uncertainty::Malformed, source);
            }
            Evidence::Unsupported { .. } => {
                return Resolution::uncertain(Uncertainty::Unsupported, source);
            }
            Evidence::Undetermined { .. } => {
                return Resolution::uncertain(Uncertainty::Undetermined, source);
            }
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
            dimension: PostureDimension::DiagnosticCrash,
            friction: FrictionTier::Tier0Transparent,
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
            min_profile: Profile::Baseline,
            requires_elevation: true,
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
        apply: None,
        rollback: None,
    }
}

const ADVERTISING_TOGGLE: Toggle = Toggle {
    target: ADVERTISING_USER,
    private_value: 0,
    absent_means: "enabled",
    desired_state: "disabled",
};

fn advertising_id() -> Control {
    Control {
        spec: ControlSpec {
            id: "windows.advertising.id".to_owned(),
            title: "Advertising identifier".to_owned(),
            section: "advertising".to_owned(),
            dimension: PostureDimension::BehavioralCommercial,
            friction: FrictionTier::Tier0Transparent,
            applicability: Applicability::new(vec![Variant::new(
                "windows",
                vec![Predicate::Platform(Platform::Windows)],
            )]),
            desired: disabled(),
            reversibility: Reversibility::Exact,
            maturity: Maturity::Automated,
            verified_through: None,
            remediation: Remediation::Automatic,
            remediation_reason: None,
            min_profile: Profile::Baseline,
            requires_elevation: false,
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
            claim: "Policy enforcement and user choice for the advertising identifier.",
            reviewed: "2026-10-07",
        }],
        probe: probe_advertising_id,
        apply: Some(|ctx| ADVERTISING_TOGGLE.apply(ctx)),
        rollback: Some(|ctx, pre, post| ADVERTISING_TOGGLE.rollback(ctx, pre, post)),
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
    /// The stored value that means the collection matches desired policy.
    private_value: u32,
    /// The state that applies when no value is stored.
    absent_means: &'static str,
    /// Desired semantic state ("disabled" or "enabled").
    desired_state: &'static str,
}

impl Toggle {
    fn source(&self) -> ManagementSource {
        match self.target.hive {
            Hive::LocalMachine => ManagementSource::LocalPolicy,
            Hive::CurrentUser => ManagementSource::User,
        }
    }

    fn probe(&self, ctx: &Context) -> Resolution {
        let other_state = if self.desired_state == "disabled" {
            "enabled"
        } else {
            "disabled"
        };
        match ctx.registry.read(&self.target, self.source()) {
            Evidence::Present { value, .. } => match value.as_u32() {
                Some(stored) => Resolution::determined(
                    if stored == self.private_value {
                        SemanticState::new(self.desired_state)
                    } else {
                        SemanticState::new(other_state)
                    },
                    self.source(),
                ),
                // A value we cannot interpret is malformed evidence, never a
                // silent fallback to the documented default.
                None => Resolution::uncertain(Uncertainty::Malformed, self.source()),
            },
            Evidence::Absent { .. } => Resolution::determined(
                SemanticState::new(self.absent_means),
                ManagementSource::Default,
            ),
            Evidence::Denied { .. } => Resolution::uncertain(Uncertainty::Denied, self.source()),
            _ => Resolution::uncertain(Uncertainty::Undetermined, self.source()),
        }
    }

    fn apply(&self, ctx: &Context) -> Result<super::AppliedOp, String> {
        let current = ctx.registry.read(&self.target, self.source());
        let preimage = match current {
            Evidence::Present { value, .. } => {
                if value.as_u32() == Some(self.private_value) {
                    return Err("Target is already in desired state".to_owned());
                }
                Some(value)
            }
            Evidence::Absent { .. } => {
                if self.absent_means == self.desired_state {
                    return Err("Target is already in desired state (absent default)".to_owned());
                }
                None
            }
            Evidence::Denied { .. } => return Err("Permission denied reading target".to_owned()),
            _ => return Err("Target state undetermined".to_owned()),
        };
        let postimage = RawValue::u32(self.private_value);
        if let Err(code) = crate::platform::windows::registry::write_raw(&self.target, &postimage) {
            if code == 5 {
                return Err(
                    "Permission denied: applying this control requires administrative privileges"
                        .to_owned(),
                );
            }
            return Err(format!("Registry write failed with error code {code}"));
        }
        let verification = self.probe(ctx);
        if verification.state != Some(SemanticState::new(self.desired_state)) {
            return Err("Verification failed after writing setting".to_owned());
        }
        Ok(super::AppliedOp {
            target_key: crate::platform::windows::registry::key(&self.target),
            preimage,
            postimage,
        })
    }

    fn rollback(
        &self,
        ctx: &Context,
        preimage: &Option<RawValue>,
        postimage: &RawValue,
    ) -> Result<(), String> {
        let current = ctx.registry.read(&self.target, self.source());
        let current_matches = match current {
            Evidence::Present { value, .. } => value == *postimage,
            _ => false,
        };
        if !current_matches {
            return Err("Conflict detected: current value has changed externally".to_owned());
        }
        match preimage {
            Some(raw) => {
                if let Err(code) = crate::platform::windows::registry::write_raw(&self.target, raw)
                {
                    if code == 5 {
                        return Err("Permission denied: rolling back this control requires administrative privileges".to_owned());
                    }
                    return Err(format!("Rollback write failed with code {code}"));
                }
            }
            None => {
                if let Err(code) = crate::platform::windows::registry::delete_value(&self.target) {
                    if code == 5 {
                        return Err("Permission denied: rolling back this control requires administrative privileges".to_owned());
                    }
                    return Err(format!("Rollback deletion failed with code {code}"));
                }
            }
        }
        let restored = ctx.registry.read(&self.target, self.source());
        let verified = match (preimage, &restored) {
            (Some(expected), Evidence::Present { value, .. }) => value == expected,
            (None, Evidence::Absent { .. }) => true,
            _ => false,
        };
        if !verified {
            return Err("Verification failed after restoring setting during rollback".to_owned());
        }
        Ok(())
    }
}

/// A setting that is a string value meaning on or off (e.g. Deny vs Allow).
struct StringToggle {
    target: Target,
    /// The stored string that means the collection or capability is off.
    private_value: &'static str,
    /// The state that applies when no value is stored.
    absent_means: &'static str,
}

impl StringToggle {
    fn probe(&self, ctx: &Context) -> Resolution {
        match ctx.registry.read(&self.target, ManagementSource::User) {
            Evidence::Present { value, .. } => match value.as_str_lossy() {
                Some(stored) => Resolution::determined(
                    if stored.eq_ignore_ascii_case(self.private_value) {
                        disabled()
                    } else {
                        enabled()
                    },
                    ManagementSource::User,
                ),
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

    fn apply(&self, ctx: &Context) -> Result<super::AppliedOp, String> {
        let current = ctx.registry.read(&self.target, ManagementSource::User);
        let preimage = match current {
            Evidence::Present { value, .. } => {
                if value
                    .as_str_lossy()
                    .as_deref()
                    .map(|s| s.eq_ignore_ascii_case(self.private_value))
                    == Some(true)
                {
                    return Err("Target is already in desired state".to_owned());
                }
                Some(value)
            }
            Evidence::Absent { .. } => {
                if self.absent_means == "disabled" {
                    return Err("Target is already in desired state (absent default)".to_owned());
                }
                None
            }
            Evidence::Denied { .. } => return Err("Permission denied reading target".to_owned()),
            _ => return Err("Target state undetermined".to_owned()),
        };
        let postimage = RawValue::string_utf16(self.private_value);
        if let Err(code) = crate::platform::windows::registry::write_raw(&self.target, &postimage) {
            return Err(format!("Registry write failed with error code {code}"));
        }
        let verification = self.probe(ctx);
        if verification.state != Some(disabled()) {
            return Err("Verification failed after writing setting".to_owned());
        }
        Ok(super::AppliedOp {
            target_key: crate::platform::windows::registry::key(&self.target),
            preimage,
            postimage,
        })
    }

    fn rollback(
        &self,
        ctx: &Context,
        preimage: &Option<RawValue>,
        postimage: &RawValue,
    ) -> Result<(), String> {
        let current = ctx.registry.read(&self.target, ManagementSource::User);
        let current_matches = match current {
            Evidence::Present { value, .. } => value == *postimage,
            _ => false,
        };
        if !current_matches {
            return Err("Conflict detected: current value has changed externally".to_owned());
        }
        match preimage {
            Some(raw) => {
                if let Err(code) = crate::platform::windows::registry::write_raw(&self.target, raw)
                {
                    return Err(format!("Rollback write failed with code {code}"));
                }
            }
            None => {
                if let Err(code) = crate::platform::windows::registry::delete_value(&self.target) {
                    return Err(format!("Rollback deletion failed with code {code}"));
                }
            }
        }
        let restored = ctx.registry.read(&self.target, ManagementSource::User);
        let verified = match (preimage, &restored) {
            (Some(expected), Evidence::Present { value, .. }) => value == expected,
            (None, Evidence::Absent { .. }) => true,
            _ => false,
        };
        if !verified {
            return Err("Verification failed after restoring setting during rollback".to_owned());
        }
        Ok(())
    }
}

const FEEDBACK_FREQUENCY: Toggle = Toggle {
    target: Target::new(
        Hive::CurrentUser,
        r"Software\Microsoft\Siuf\Rules",
        "NumberOfSIUFInPeriod",
        View::Native,
    ),
    private_value: 0,
    absent_means: "enabled",
    desired_state: "disabled",
};

const WIFI_DATA_ACCESS: StringToggle = StringToggle {
    target: Target::new(
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\wifiData",
        "Value",
        View::Native,
    ),
    private_value: "Deny",
    absent_means: "enabled",
};

const ACCOUNT_INFO_ACCESS: StringToggle = StringToggle {
    target: Target::new(
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation",
        "Value",
        View::Native,
    ),
    private_value: "Deny",
    absent_means: "enabled",
};

const APP_ACTIVITY_ACCESS: StringToggle = StringToggle {
    target: Target::new(
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity",
        "Value",
        View::Native,
    ),
    private_value: "Deny",
    absent_means: "enabled",
};

const LLMNR_MULTICAST: Target = Target::new(
    Hive::LocalMachine,
    r"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient",
    "EnableMulticast",
    View::Native,
);

const LLMNR: Toggle = Toggle {
    target: LLMNR_MULTICAST,
    private_value: 0,
    absent_means: "enabled",
    desired_state: "disabled",
};

fn probe_llmnr(ctx: &Context) -> Resolution {
    LLMNR.probe(ctx)
}

fn security_llmnr() -> Control {
    Control {
        spec: ControlSpec {
            id: "windows.security.llmnr".to_owned(),
            title: "Link-Local Multicast Name Resolution".to_owned(),
            section: "security".to_owned(),
            dimension: PostureDimension::NetworkExposure,
            friction: FrictionTier::Tier0Transparent,
            applicability: Applicability::new(vec![Variant::new(
                "windows",
                vec![Predicate::Platform(Platform::Windows)],
            )]),
            desired: disabled(),
            reversibility: Reversibility::Exact,
            maturity: Maturity::Automated,
            verified_through: None,
            remediation: Remediation::Automatic,
            remediation_reason: None,
            min_profile: Profile::Baseline,
            requires_elevation: true,
        },

        title: "Link-Local Multicast Name Resolution",
        summary: "Windows broadcasts name queries in plaintext across local networks when DNS fails.",
        rationale: "LLMNR multicasts queries over UDP port 5355 without encryption or authentication. Attackers on the local network can spoof answers and harvest NetNTLM credentials.",
        tradeoff: Some("Fallback local name resolution without a DNS server is unavailable."),
        mitigation: Some(
            "Standard unicast DNS resolution through routers or DNS servers continues to function normally.",
        ),
        sources: &[Source {
            url: DNS_CLIENT_CSP,
            claim: "Documents multicast DNS resolution policy.",
            reviewed: "2026-09-21",
        }],
        probe: probe_llmnr,
        apply: Some(|ctx| LLMNR.apply(ctx)),
        rollback: Some(|ctx, pre, post| LLMNR.rollback(ctx, pre, post)),
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
    desired_state: "disabled",
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
    desired_state: "disabled",
};

const CLOUD_CLIPBOARD_SYNC: Toggle = Toggle {
    target: Target::new(
        Hive::CurrentUser,
        r"Software\Microsoft\Clipboard",
        "AllowCrossDeviceClipboard",
        View::Native,
    ),
    private_value: 0,
    absent_means: "enabled",
    desired_state: "disabled",
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
    desired_state: "disabled",
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
    desired_state: "disabled",
};

const START_SUGGESTIONS: Toggle = Toggle {
    target: Target::new(
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
        "SubscribedContent-338389Enabled",
        View::Native,
    ),
    private_value: 0,
    absent_means: "enabled",
    desired_state: "disabled",
};

const SYSTEM_SUGGESTIONS: Toggle = Toggle {
    target: Target::new(
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager",
        "SystemPaneSuggestionsEnabled",
        View::Native,
    ),
    private_value: 0,
    absent_means: "enabled",
    desired_state: "disabled",
};

const DEVICE_SEARCH_HISTORY: Toggle = Toggle {
    target: Target::new(
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\SearchSettings",
        "IsDeviceSearchHistoryEnabled",
        View::Native,
    ),
    private_value: 0,
    absent_means: "enabled",
    desired_state: "disabled",
};

const THUMBNAIL_CACHE: Toggle = Toggle {
    target: Target::new(
        Hive::CurrentUser,
        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoThumbnailCache",
        View::Native,
    ),
    private_value: 1,
    absent_means: "enabled",
    desired_state: "disabled",
};

const EDGE_METRICS: Toggle = Toggle {
    target: Target::new(
        Hive::CurrentUser,
        r"Software\Policies\Microsoft\Edge",
        "MetricsReportingEnabled",
        View::Native,
    ),
    private_value: 0,
    absent_means: "enabled",
    desired_state: "disabled",
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
    apply: Option<super::ApplyFn>,
    rollback: Option<super::RollbackFn>,
) -> Control {
    toggle_control_with_desired(
        id,
        section,
        title,
        disabled(),
        summary,
        rationale,
        tradeoff,
        mitigation,
        sources,
        probe,
        apply,
        rollback,
    )
}

fn profile_for_control(id: &str, section: &str) -> Profile {
    match section {
        "telemetry" | "diagnostics" | "advertising" | "browser" => Profile::Baseline,
        "delivery-optimization" => Profile::Baseline,
        "ai" | "clipboard" | "experience" | "input" | "search" => Profile::Strict,
        "capability" => match id {
            "windows.capability.activity" => Profile::Strict,
            _ => Profile::Restrictive,
        },
        "storage" => match id {
            "windows.storage.pagefile-clear" => Profile::Restrictive,
            _ => Profile::Strict,
        },
        "security" => match id {
            "windows.security.llmnr" | "windows.security.wpad" => Profile::Baseline,
            "windows.security.ncsi-probing" => Profile::Strict,
            _ => Profile::Restrictive,
        },
        _ => Profile::Baseline,
    }
}

fn dimension_and_friction_for_control(id: &str, section: &str) -> (PostureDimension, FrictionTier) {
    match section {
        "advertising" => (
            PostureDimension::BehavioralCommercial,
            FrictionTier::Tier0Transparent,
        ),
        "experience" => match id {
            "windows.experience.start-suggestions" => (
                PostureDimension::BehavioralCommercial,
                FrictionTier::Tier1Cosmetic,
            ),
            _ => (
                PostureDimension::BehavioralCommercial,
                FrictionTier::Tier0Transparent,
            ),
        },
        "search" => match id {
            "windows.search.web" => (
                PostureDimension::BehavioralCommercial,
                FrictionTier::Tier1Cosmetic,
            ),
            _ => (
                PostureDimension::ForensicResidue,
                FrictionTier::Tier0Transparent,
            ),
        },
        "storage" => match id {
            "windows.storage.thumbnail-cache" => (
                PostureDimension::ForensicResidue,
                FrictionTier::Tier2WorkflowAltering,
            ),
            "windows.storage.pagefile-clear" => (
                PostureDimension::ForensicResidue,
                FrictionTier::Tier2WorkflowAltering,
            ),
            _ => (
                PostureDimension::ForensicResidue,
                FrictionTier::Tier0Transparent,
            ),
        },
        "security" => match id {
            "windows.security.ncsi-probing" => (
                PostureDimension::NetworkExposure,
                FrictionTier::Tier1Cosmetic,
            ),
            _ => (
                PostureDimension::NetworkExposure,
                FrictionTier::Tier0Transparent,
            ),
        },
        "diagnostics" => (
            PostureDimension::DiagnosticCrash,
            FrictionTier::Tier0Transparent,
        ),
        "delivery-optimization" => (
            PostureDimension::NetworkExposure,
            FrictionTier::Tier0Transparent,
        ),
        "input" => (
            PostureDimension::AmbientSensor,
            FrictionTier::Tier0Transparent,
        ),
        "clipboard" => (
            PostureDimension::ForensicResidue,
            FrictionTier::Tier2WorkflowAltering,
        ),
        "ai" => (
            PostureDimension::BehavioralCommercial,
            FrictionTier::Tier0Transparent,
        ),
        "browser" => (
            PostureDimension::BehavioralCommercial,
            FrictionTier::Tier0Transparent,
        ),
        "capability" => (PostureDimension::AmbientSensor, FrictionTier::Tier1Cosmetic),
        _ => (
            PostureDimension::BehavioralCommercial,
            FrictionTier::Tier0Transparent,
        ),
    }
}

fn requires_elevation_for_control(id: &str, section: &str) -> bool {
    if id == "windows.ai.recall-snapshot" {
        return true;
    }
    match section {
        "delivery-optimization" => true,
        "security" => true,
        "diagnostics" => !matches!(id, "windows.diagnostics.feedback"),
        "storage" => true,
        _ => false,
    }
}

/// Build a control with a specified desired state.
#[allow(clippy::too_many_arguments)]
fn toggle_control_with_desired(
    id: &str,
    section: &str,
    title: &'static str,
    desired: SemanticState,
    summary: &'static str,
    rationale: &'static str,
    tradeoff: Option<&'static str>,
    mitigation: Option<&'static str>,
    sources: &'static [Source],
    probe: fn(&Context) -> Resolution,
    apply: Option<super::ApplyFn>,
    rollback: Option<super::RollbackFn>,
) -> Control {
    let (dimension, friction) = dimension_and_friction_for_control(id, section);
    Control {
        spec: ControlSpec {
            id: id.to_owned(),
            title: title.to_owned(),
            section: section.to_owned(),
            dimension,
            friction,
            applicability: Applicability::new(vec![Variant::new(
                "windows",
                vec![Predicate::Platform(Platform::Windows)],
            )]),

            desired,
            reversibility: Reversibility::Exact,
            maturity: Maturity::Automated,
            verified_through: None,
            remediation: if apply.is_some() {
                Remediation::Automatic
            } else {
                Remediation::AuditOnly
            },
            remediation_reason: None,
            min_profile: profile_for_control(id, section),
            requires_elevation: requires_elevation_for_control(id, section),
        },
        title,
        summary,
        rationale,
        tradeoff,
        mitigation,
        sources,
        probe,
        apply,
        rollback,
    }
}

const COPILOT_CSP: &str =
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowscopilot";
const WINDOWS_AI_CSP: &str =
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-windowsai";
const DELIVERY_OPTIMIZATION_DOCS: &str =
    "https://learn.microsoft.com/windows/deployment/do/waas-delivery-optimization-reference";
const WINHTTP_DOCS: &str =
    "https://learn.microsoft.com/windows/win32/winhttp/winhttp-autoproxy-support";

const COPILOT_SHELL: Toggle = Toggle {
    target: Target::new(
        Hive::CurrentUser,
        r"Software\Policies\Microsoft\Windows\WindowsCopilot",
        "TurnOffWindowsCopilot",
        View::Native,
    ),
    private_value: 1,
    absent_means: "enabled",
    desired_state: "disabled",
};

const RECALL_POLICY: Target = Target::new(
    Hive::LocalMachine,
    r"SOFTWARE\Policies\Microsoft\Windows\WindowsAI",
    "DisableAIDataAnalysis",
    View::Native,
);

const RECALL_SNAPSHOTS: Toggle = Toggle {
    target: RECALL_POLICY,
    private_value: 1,
    absent_means: "enabled",
    desired_state: "disabled",
};

fn probe_recall_snapshots(ctx: &Context) -> Resolution {
    RECALL_SNAPSHOTS.probe(ctx)
}

const DELIVERY_OPTIMIZATION_POLICY: Target = Target::new(
    Hive::LocalMachine,
    r"SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization",
    "DODownloadMode",
    View::Native,
);

const DELIVERY_OPTIMIZATION: Toggle = Toggle {
    target: DELIVERY_OPTIMIZATION_POLICY,
    private_value: 0,
    absent_means: "enabled",
    desired_state: "disabled",
};

fn probe_delivery_optimization(ctx: &Context) -> Resolution {
    match ctx
        .registry
        .read(&DELIVERY_OPTIMIZATION_POLICY, ManagementSource::LocalPolicy)
    {
        Evidence::Present { value, .. } => match value.as_u32() {
            Some(0) | Some(99) => Resolution::determined(disabled(), ManagementSource::LocalPolicy),
            Some(_) => Resolution::determined(enabled(), ManagementSource::LocalPolicy),
            None => Resolution::uncertain(Uncertainty::Malformed, ManagementSource::LocalPolicy),
        },
        Evidence::Absent { .. } => Resolution::determined(enabled(), ManagementSource::Default),
        Evidence::Denied { .. } => {
            Resolution::uncertain(Uncertainty::Denied, ManagementSource::LocalPolicy)
        }
        _ => Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::LocalPolicy),
    }
}

const WPAD_POLICY: Target = Target::new(
    Hive::LocalMachine,
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp",
    "DisableWpad",
    View::Native,
);

const WPAD: Toggle = Toggle {
    target: WPAD_POLICY,
    private_value: 1,
    absent_means: "enabled",
    desired_state: "disabled",
};

fn probe_wpad(ctx: &Context) -> Resolution {
    WPAD.probe(ctx)
}

const CRASH_DUMP_POLICY: Target = Target::new(
    Hive::LocalMachine,
    r"SYSTEM\CurrentControlSet\Control\CrashControl",
    "CrashDumpEnabled",
    View::Native,
);

fn probe_crash_dump_scope(ctx: &Context) -> Resolution {
    match ctx
        .registry
        .read(&CRASH_DUMP_POLICY, ManagementSource::LocalPolicy)
    {
        Evidence::Present { value, .. } => match value.as_u32() {
            Some(0) | Some(3) => Resolution::determined(disabled(), ManagementSource::LocalPolicy),
            Some(_) => Resolution::determined(enabled(), ManagementSource::LocalPolicy),
            None => Resolution::uncertain(Uncertainty::Malformed, ManagementSource::LocalPolicy),
        },
        Evidence::Absent { .. } => Resolution::determined(enabled(), ManagementSource::Default),
        Evidence::Denied { .. } => {
            Resolution::uncertain(Uncertainty::Denied, ManagementSource::LocalPolicy)
        }
        _ => Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::LocalPolicy),
    }
}

const INVENTORY_COLLECTOR_POLICY: Target = Target::new(
    Hive::LocalMachine,
    r"SOFTWARE\Policies\Microsoft\Windows\AppCompat",
    "DisableInventory",
    View::Native,
);

const INVENTORY_COLLECTOR: Toggle = Toggle {
    target: INVENTORY_COLLECTOR_POLICY,
    private_value: 1,
    absent_means: "enabled",
    desired_state: "disabled",
};

fn probe_inventory_collector(ctx: &Context) -> Resolution {
    INVENTORY_COLLECTOR.probe(ctx)
}

const NCSI_ACTIVE_PROBE: Target = Target::new(
    Hive::LocalMachine,
    r"SYSTEM\CurrentControlSet\Services\NlaSvc\Parameters\Internet",
    "EnableActiveProbing",
    View::Native,
);

const NCSI_POLICY_OVERRIDE: Target = Target::new(
    Hive::LocalMachine,
    r"SOFTWARE\Policies\Microsoft\Windows\NetworkConnectivityStatusIndicator",
    "NoActiveProbe",
    View::Native,
);

const NCSI_PROBING: Toggle = Toggle {
    target: NCSI_POLICY_OVERRIDE,
    private_value: 1,
    absent_means: "enabled",
    desired_state: "disabled",
};

fn probe_ncsi_probing(ctx: &Context) -> Resolution {
    if let Evidence::Present { value, .. } = ctx
        .registry
        .read(&NCSI_POLICY_OVERRIDE, ManagementSource::LocalPolicy)
    {
        return match value.as_u32() {
            Some(1) => Resolution::determined(disabled(), ManagementSource::LocalPolicy),
            Some(_) => Resolution::determined(enabled(), ManagementSource::LocalPolicy),
            None => Resolution::uncertain(Uncertainty::Malformed, ManagementSource::LocalPolicy),
        };
    }
    match ctx
        .registry
        .read(&NCSI_ACTIVE_PROBE, ManagementSource::LocalPolicy)
    {
        Evidence::Present { value, .. } => match value.as_u32() {
            Some(0) => Resolution::determined(disabled(), ManagementSource::LocalPolicy),
            Some(_) => Resolution::determined(enabled(), ManagementSource::LocalPolicy),
            None => Resolution::uncertain(Uncertainty::Malformed, ManagementSource::LocalPolicy),
        },
        Evidence::Absent { .. } => Resolution::determined(enabled(), ManagementSource::Default),
        Evidence::Denied { .. } => {
            Resolution::uncertain(Uncertainty::Denied, ManagementSource::LocalPolicy)
        }
        _ => Resolution::uncertain(Uncertainty::Undetermined, ManagementSource::LocalPolicy),
    }
}

const CRASH_CONTROL_DOCS: &str = "https://learn.microsoft.com/windows-hardware/drivers/debugger/varieties-of-kernel-mode-dump-files";
const APPCOMPAT_CSP: &str =
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-applicationcompatibility";
const NCSI_DOCS: &str =
    "https://learn.microsoft.com/windows-server/networking/ncsi/ncsi-frequently-asked-questions";
const PRIVACY_CSP: &str =
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-privacy";
const TEXTINPUT_CSP: &str =
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-textinput";
const SEARCH_CSP: &str =
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-search";
const EXPERIENCE_CSP: &str =
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-experience";
const SYSTEM_CSP: &str =
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-system";
const DNS_CLIENT_CSP: &str =
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-dnsclient";
const FILE_EXPLORER_CSP: &str =
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-fileexplorer";
const EDGE_POLICY_DOCS: &str =
    "https://learn.microsoft.com/deployedge/microsoft-edge-policies/metricsreportingenabled";
const ERROR_REPORTING_CSP: &str =
    "https://learn.microsoft.com/windows/client-management/mdm/policy-csp-errorreporting";
const PAGEFILE_CLEAR_DOCS: &str = "https://learn.microsoft.com/windows/security/threat-protection/security-policy-settings/shutdown-clear-virtual-memory-pagefile";
const FSUTIL_BEHAVIOR_DOCS: &str =
    "https://learn.microsoft.com/windows-server/administration/windows-commands/fsutil-behavior";

const ERROR_REPORTING_POLICY: Target = Target::new(
    Hive::LocalMachine,
    r"SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting",
    "Disabled",
    View::Native,
);

const ERROR_REPORTING: Toggle = Toggle {
    target: ERROR_REPORTING_POLICY,
    private_value: 1,
    absent_means: "enabled",
    desired_state: "disabled",
};

fn probe_error_reporting(ctx: &Context) -> Resolution {
    ERROR_REPORTING.probe(ctx)
}

const PAGEFILE_CLEAR_POLICY: Target = Target::new(
    Hive::LocalMachine,
    r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management",
    "ClearPageFileAtShutdown",
    View::Native,
);

const PAGEFILE_CLEAR: Toggle = Toggle {
    target: PAGEFILE_CLEAR_POLICY,
    private_value: 1,
    absent_means: "disabled",
    desired_state: "enabled",
};

fn probe_pagefile_clear(ctx: &Context) -> Resolution {
    PAGEFILE_CLEAR.probe(ctx)
}

const TRIM_NOTIFY_POLICY: Target = Target::new(
    Hive::LocalMachine,
    r"SYSTEM\CurrentControlSet\Control\FileSystem",
    "DisableDeleteNotification",
    View::Native,
);

const TRIM_NOTIFY: Toggle = Toggle {
    target: TRIM_NOTIFY_POLICY,
    private_value: 0,
    absent_means: "enabled",
    desired_state: "enabled",
};

fn probe_trim_notify(ctx: &Context) -> Resolution {
    TRIM_NOTIFY.probe(ctx)
}

/// Every Windows control, in stable sorted order by identifier.
pub fn controls() -> Vec<Control> {
    let mut controls = vec![
        advertising_id(),
        toggle_control(
            "windows.ai.copilot-shell",
            "ai",
            "Windows Copilot shell integration",
            "Windows integrates Copilot into the taskbar and shortcuts, sending queries and context to cloud services.",
            "Desktop Copilot integration sends user context, prompts, and active application references to Microsoft cloud services.",
            Some("The Copilot taskbar button and Win+C shortcut are deactivated."),
            Some("Copilot remains accessible through a web browser when deliberately visited."),
            &[Source {
                url: COPILOT_CSP,
                claim: "Documents Windows Copilot policy configuration.",
                reviewed: "2026-09-22",
            }],
            |ctx| COPILOT_SHELL.probe(ctx),
            Some(|ctx| COPILOT_SHELL.apply(ctx)),
            Some(|ctx, pre, post| COPILOT_SHELL.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.ai.recall-snapshot",
            "ai",
            "Recall screen snapshots",
            "Windows Recall captures periodic screenshots of activity and stores semantic representations.",
            "Automatic desktop snapshots record sensitive on-screen documents, credentials, and personal communications.",
            Some("Windows stops capturing periodic desktop snapshots for Recall timeline search."),
            Some("Standard screenshot tools and manual captures continue to function normally."),
            &[Source {
                url: WINDOWS_AI_CSP,
                claim: "Documents Windows AI snapshot analysis policy.",
                reviewed: "2026-09-22",
            }],
            probe_recall_snapshots,
            Some(|ctx| RECALL_SNAPSHOTS.apply(ctx)),
            Some(|ctx, pre, post| RECALL_SNAPSHOTS.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.capability.account-info",
            "capability",
            "User account information access",
            "Windows apps can read your account name, email address, and profile picture.",
            "Permitting universal account info access exposes your user identity, \
             email, and display picture to all installed store apps without specific consent.",
            Some("Apps cannot automatically populate your name or profile picture."),
            Some("You can enter account credentials or sign in manually within apps as needed."),
            &[Source {
                url: PRIVACY_CSP,
                claim: "Documents user account information capability access.",
                reviewed: "2026-09-21",
            }],
            |ctx| ACCOUNT_INFO_ACCESS.probe(ctx),
            Some(|ctx| ACCOUNT_INFO_ACCESS.apply(ctx)),
            Some(|ctx, pre, post| ACCOUNT_INFO_ACCESS.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.capability.activity",
            "capability",
            "App activity tracking",
            "Windows apps can track your in-app actions and resume states across app sessions.",
            "App activity tracking records usage workflows across applications. \
             Disabling this restricts apps to local session data.",
            Some("Cross-app timeline resumption is disabled."),
            Some("Normal document and project saving within each app continues to work."),
            &[Source {
                url: PRIVACY_CSP,
                claim: "Documents user activity capability access.",
                reviewed: "2026-09-21",
            }],
            |ctx| APP_ACTIVITY_ACCESS.probe(ctx),
            Some(|ctx| APP_ACTIVITY_ACCESS.apply(ctx)),
            Some(|ctx, pre, post| APP_ACTIVITY_ACCESS.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.capability.wifi-data",
            "capability",
            "Wi-Fi adapter and scan access",
            "Windows apps can scan nearby Wi-Fi networks and adapters, allowing location estimation.",
            "Access to Wi-Fi scan data allows applications to determine geographic \
             location through Wi-Fi BSSID triangulation even when GPS and location services are denied.",
            Some(
                "Applications that explicitly diagnose or configure Wi-Fi networks cannot scan adapters.",
            ),
            Some(
                "Wi-Fi network connection and internet access through Windows Settings and web browsers are unaffected.",
            ),
            &[Source {
                url: PRIVACY_CSP,
                claim: "Documents Wi-Fi data capability access.",
                reviewed: "2026-09-21",
            }],
            |ctx| WIFI_DATA_ACCESS.probe(ctx),
            Some(|ctx| WIFI_DATA_ACCESS.apply(ctx)),
            Some(|ctx, pre, post| WIFI_DATA_ACCESS.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.diagnostics.crash-dump-scope",
            "diagnostics",
            "Crash dump memory scope",
            "Windows captures raw physical RAM contents during kernel bugchecks and system crashes.",
            "Complete and automatic memory dumps capture physical RAM including passwords, cryptographic keys, and session tokens. Restricting crash dumps to minidumps prevents sensitive memory persistence.",
            Some(
                "Deep kernel memory and full heap crash inspection for driver developers is unavailable.",
            ),
            Some(
                "Kernel minidumps containing stop codes, call stacks, and loaded drivers are still captured for crash analysis.",
            ),
            &[Source {
                url: CRASH_CONTROL_DOCS,
                claim: "Documents kernel-mode crash dump file options and scope.",
                reviewed: "2026-09-22",
            }],
            probe_crash_dump_scope,
            None,
            None,
        ),
        toggle_control(
            "windows.diagnostics.error-reporting",
            "diagnostics",
            "Windows Error Reporting",
            "Windows Error Reporting captures process memory crash dumps and transmits diagnostic reports to Microsoft.",
            "When applications or system components crash, Windows Error Reporting writes memory minidumps and crash signatures to disk and transmits them over the network. Memory dumps can expose decrypted credentials, tokens, and active document contents.",
            Some(
                "Applications that crash will not automatically upload diagnostic telemetry to Microsoft for crash analysis.",
            ),
            Some(
                "Application event logs and crash codes remain logged locally in the Windows Event Log.",
            ),
            &[Source {
                url: ERROR_REPORTING_CSP,
                claim: "Documents Windows Error Reporting disable policy.",
                reviewed: "2026-10-01",
            }],
            probe_error_reporting,
            Some(|ctx| ERROR_REPORTING.apply(ctx)),
            Some(|ctx, pre, post| ERROR_REPORTING.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.diagnostics.feedback",
            "diagnostics",
            "Feedback frequency",
            "Windows prompts for feedback surveys and collects diagnostic impressions.",
            "System Initiated User Feedback prompts periodically interrupt the operator \
             and transmit diagnostic impressions to vendor services. Setting this to 0 prevents prompts.",
            Some("Windows will not prompt for feedback on features or experiences."),
            Some("Feedback Hub remains available to submit feedback manually whenever you choose."),
            &[Source {
                url: SYSTEM_CSP,
                claim: "Documents feedback notification and survey frequency policy.",
                reviewed: "2026-09-21",
            }],
            |ctx| FEEDBACK_FREQUENCY.probe(ctx),
            Some(|ctx| FEEDBACK_FREQUENCY.apply(ctx)),
            Some(|ctx, pre, post| FEEDBACK_FREQUENCY.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.diagnostics.inventory-collector",
            "diagnostics",
            "Application and device inventory collection",
            "Windows inventory collector catalogues installed software binaries, checksums, and attached peripherals.",
            "The compatibility inventory collector runs periodically to enumerate software files and peripheral devices for transmission to vendor analytics services.",
            Some(
                "Microsoft does not automatically pre-screen third-party application compatibility shims before major operating system upgrades.",
            ),
            Some(
                "Software installations, driver updates, and application execution continue normally.",
            ),
            &[Source {
                url: APPCOMPAT_CSP,
                claim: "Documents Inventory Collector policy configuration.",
                reviewed: "2026-09-22",
            }],
            probe_inventory_collector,
            Some(|ctx| INVENTORY_COLLECTOR.apply(ctx)),
            Some(|ctx, pre, post| INVENTORY_COLLECTOR.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.clipboard.cloud-sync",
            "clipboard",
            "Cloud clipboard synchronisation",
            "What you copy to the clipboard can be synchronised across other devices.",
            "Synchronising the clipboard transmits copied passwords, tokens, and \
             documents to cloud services to make them available on other devices.",
            Some("You cannot paste on another device content copied on this machine."),
            Some("Local clipboard history on this machine continues to work normally."),
            &[Source {
                url: PRIVACY_CSP,
                claim: "Documents the cross-device clipboard setting.",
                reviewed: "2026-09-21",
            }],
            |ctx| CLOUD_CLIPBOARD_SYNC.probe(ctx),
            Some(|ctx| CLOUD_CLIPBOARD_SYNC.apply(ctx)),
            Some(|ctx, pre, post| CLOUD_CLIPBOARD_SYNC.rollback(ctx, pre, post)),
        ),
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
            Some(|ctx| CLOUD_CLIPBOARD.apply(ctx)),
            Some(|ctx, pre, post| CLOUD_CLIPBOARD.rollback(ctx, pre, post)),
        ),
        diagnostics_level(),
        toggle_control(
            "windows.experience.start-suggestions",
            "experience",
            "Start menu recommendations",
            "Windows shows app recommendations and suggested content in the Start menu.",
            "Recommendations in the Start menu are targeted based on application \
             usage profiling to promote store software and web content.",
            Some("Windows stops suggesting apps and content in the Start menu."),
            Some("All installed applications and search remain available as normal."),
            &[Source {
                url: EXPERIENCE_CSP,
                claim: "Documents Start menu recommendation content.",
                reviewed: "2026-09-21",
            }],
            |ctx| START_SUGGESTIONS.probe(ctx),
            Some(|ctx| START_SUGGESTIONS.apply(ctx)),
            Some(|ctx, pre, post| START_SUGGESTIONS.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.experience.suggested-apps",
            "experience",
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
            Some(|ctx| SUGGESTED_APPS.apply(ctx)),
            Some(|ctx, pre, post| SUGGESTED_APPS.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.experience.system-suggestions",
            "experience",
            "Settings suggestions",
            "Windows displays suggestions and tips within system settings and notifications.",
            "Showing recommendations in configuration screens turns system management \
             interfaces into promotional channels.",
            Some("Settings panes stop displaying suggestions and tips."),
            Some("Settings functionality remains fully available without tips."),
            &[Source {
                url: EXPERIENCE_CSP,
                claim: "Documents system pane suggestions.",
                reviewed: "2026-09-21",
            }],
            |ctx| SYSTEM_SUGGESTIONS.probe(ctx),
            Some(|ctx| SYSTEM_SUGGESTIONS.apply(ctx)),
            Some(|ctx, pre, post| SYSTEM_SUGGESTIONS.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.experience.tailored",
            "experience",
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
            Some(|ctx| TAILORED_EXPERIENCES.apply(ctx)),
            Some(|ctx, pre, post| TAILORED_EXPERIENCES.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.input.personalization",
            "input",
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
            None,
            None,
        ),
        toggle_control(
            "windows.search.device-history",
            "search",
            "Device search history",
            "Windows records search queries on this device to suggest previous terms.",
            "Keeping a local search history maintains a persistent record of \
             searched terms, accessed documents, and applications.",
            Some("Windows does not suggest recently searched terms in the search flyout."),
            Some(
                "Searching files, settings, and installed applications continues to work normally.",
            ),
            &[Source {
                url: SEARCH_CSP,
                claim: "Documents device search history recording.",
                reviewed: "2026-09-21",
            }],
            |ctx| DEVICE_SEARCH_HISTORY.probe(ctx),
            Some(|ctx| DEVICE_SEARCH_HISTORY.apply(ctx)),
            Some(|ctx, pre, post| DEVICE_SEARCH_HISTORY.rollback(ctx, pre, post)),
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
            Some(|ctx| WEB_SEARCH.apply(ctx)),
            Some(|ctx, pre, post| WEB_SEARCH.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.delivery-optimization.mode",
            "delivery-optimization",
            "Delivery Optimization peer distribution",
            "Windows can share update payloads with other PCs across the local network and the internet.",
            "Peer-to-peer update distribution exposes machine presence and shares network bandwidth with unknown peers.",
            Some("Windows downloads updates directly from Microsoft CDN without peer sharing."),
            Some(
                "Updates download normally from Microsoft servers; only peer uploading and downloading is disabled.",
            ),
            &[Source {
                url: DELIVERY_OPTIMIZATION_DOCS,
                claim: "Documents Delivery Optimization download mode settings.",
                reviewed: "2026-09-22",
            }],
            probe_delivery_optimization,
            Some(|ctx| DELIVERY_OPTIMIZATION.apply(ctx)),
            Some(|ctx, pre, post| DELIVERY_OPTIMIZATION.rollback(ctx, pre, post)),
        ),
        security_llmnr(),
        toggle_control(
            "windows.security.ncsi-probing",
            "security",
            "Network Connectivity Status Indicator active probing",
            "Windows performs active HTTP requests and DNS queries to test internet connectivity whenever network links change.",
            "Active probing transmits cleartext HTTP requests to msftconnecttest.com, beaconing network association timestamps, IP address changes, and device presence to external observers.",
            Some(
                "The network icon in the taskbar may indicate no internet connection or action needed even when internet access works normally. Captive portal auto-detection is disabled.",
            ),
            Some(
                "Web browsers and all internet applications function normally. On public captive networks, navigate directly to a gateway IP address or non-HTTPS URL to log in.",
            ),
            &[Source {
                url: NCSI_DOCS,
                claim: "Documents Network Connectivity Status Indicator active probing configuration.",
                reviewed: "2026-09-22",
            }],
            probe_ncsi_probing,
            Some(|ctx| NCSI_PROBING.apply(ctx)),
            Some(|ctx, pre, post| NCSI_PROBING.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.security.wpad",
            "security",
            "Web Proxy Auto-Discovery",
            "Windows broadcasts name queries to automatically discover HTTP and HTTPS proxy servers.",
            "Unauthenticated WPAD queries can be answered by rogue devices on local networks to redirect web traffic.",
            Some(
                "Automated proxy discovery is disabled. Outbound traffic connects directly unless a proxy is explicitly configured.",
            ),
            Some(
                "Manual proxy configurations and PAC URLs in network settings continue to function normally.",
            ),
            &[Source {
                url: WINHTTP_DOCS,
                claim: "Documents Web Proxy Auto-Discovery client configuration.",
                reviewed: "2026-09-22",
            }],
            probe_wpad,
            Some(|ctx| WPAD.apply(ctx)),
            Some(|ctx, pre, post| WPAD.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.browser.edge.telemetry",
            "browser",
            "Microsoft Edge diagnostic reporting",
            "Microsoft Edge collects browsing diagnostic metrics and uncompressed crash memory dumps.",
            "Edge transmits usage telemetry and stores crash memory dumps in Crashpad containing visited URLs, cookies, and active DOM contents.",
            Some("Automatic crash dump and diagnostic transmission to Microsoft is disabled."),
            Some("Web browsing, extensions, and developer tools continue to function normally."),
            &[Source {
                url: EDGE_POLICY_DOCS,
                claim: "Documents Microsoft Edge metrics and diagnostic reporting policy.",
                reviewed: "2026-10-01",
            }],
            |ctx| EDGE_METRICS.probe(ctx),
            Some(|ctx| EDGE_METRICS.apply(ctx)),
            Some(|ctx, pre, post| EDGE_METRICS.rollback(ctx, pre, post)),
        ),
        toggle_control_with_desired(
            "windows.storage.pagefile-clear",
            "storage",
            "Paging file clear at shutdown",
            enabled(),
            "Windows clears virtual memory paging file sectors during system shutdown.",
            "The virtual memory pagefile stores inactive RAM pages containing unencrypted credentials, cryptographic keys, and sensitive documents. When clearing is disabled, residual plaintext memory persists on disk sectors across shutdowns.",
            Some("System shutdown takes longer while Windows writes zeros across the paging file."),
            Some(
                "System stability and runtime performance are unaffected; only the final shutdown sequence takes additional seconds.",
            ),
            &[Source {
                url: PAGEFILE_CLEAR_DOCS,
                claim: "Documents shutdown virtual memory pagefile clear security setting.",
                reviewed: "2026-10-01",
            }],
            probe_pagefile_clear,
            Some(|ctx| PAGEFILE_CLEAR.apply(ctx)),
            Some(|ctx, pre, post| PAGEFILE_CLEAR.rollback(ctx, pre, post)),
        ),
        toggle_control(
            "windows.storage.thumbnail-cache",
            "storage",
            "File Explorer thumbnail caching",
            "Windows Explorer renders and caches visual thumbnails of opened images, videos, and documents.",
            "Explorer generates scaled visual thumbnails in global databases (thumbcache_*.db). These thumbnails persist unencrypted on disk even after files are deleted or viewed from encrypted volumes.",
            Some(
                "Explorer displays generic file icons instead of visual picture and video previews.",
            ),
            Some(
                "Pictures, videos, and documents can still be opened and previewed directly inside applications.",
            ),
            &[Source {
                url: FILE_EXPLORER_CSP,
                claim: "Documents File Explorer thumbnail cache policy.",
                reviewed: "2026-10-01",
            }],
            |ctx| THUMBNAIL_CACHE.probe(ctx),
            Some(|ctx| THUMBNAIL_CACHE.apply(ctx)),
            Some(|ctx, pre, post| THUMBNAIL_CACHE.rollback(ctx, pre, post)),
        ),
        toggle_control_with_desired(
            "windows.storage.trim-notify",
            "storage",
            "Storage delete notification (TRIM)",
            enabled(),
            "Windows issues file delete notifications to solid-state drives when files are removed.",
            "TRIM and UNMAP notifications inform solid-state drive controllers that deleted file blocks are invalid, allowing background wear leveling and physical erasure. When disabled, deleted file contents remain in physical storage cells.",
            Some("Storage devices process TRIM notifications upon file deletion."),
            Some(
                "Standard modern solid-state drives handle TRIM natively with negligible performance overhead.",
            ),
            &[Source {
                url: FSUTIL_BEHAVIOR_DOCS,
                claim: "Documents filesystem delete notification TRIM behavior.",
                reviewed: "2026-10-01",
            }],
            probe_trim_notify,
            Some(|ctx| TRIM_NOTIFY.apply(ctx)),
            Some(|ctx, pre, post| TRIM_NOTIFY.rollback(ctx, pre, post)),
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
        let host = windows_host();
        for (text, ink, expected) in [
            (0, 0, enabled()),
            (0, 1, enabled()),
            (1, 0, enabled()),
            (1, 1, disabled()),
        ] {
            let registry = recording(vec![
                (
                    IMPLICIT_TEXT,
                    Evidence::Present {
                        source: ManagementSource::User,
                        value: RawValue::u32(text),
                    },
                ),
                (
                    IMPLICIT_INK,
                    Evidence::Present {
                        source: ManagementSource::User,
                        value: RawValue::u32(ink),
                    },
                ),
            ]);
            let resolution = probe_input_personalization(&recorded(&host, &registry));
            assert_eq!(resolution.state, Some(expected), "text={text}, ink={ink}");
        }
    }

    #[test]
    fn wifi_data_access_decodes_recorded_values() {
        let host = windows_host();
        for (value, expected) in [("Deny", disabled()), ("Allow", enabled())] {
            let registry = recording(vec![(
                WIFI_DATA_ACCESS.target,
                Evidence::Present {
                    source: ManagementSource::User,
                    value: RawValue::string_utf16(value),
                },
            )]);
            let resolution = WIFI_DATA_ACCESS.probe(&recorded(&host, &registry));
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
            desired_state: "disabled",
        };

        let host = windows_host();
        let registry = recording(vec![(
            missing.target,
            Evidence::Absent {
                source: ManagementSource::User,
            },
        )]);
        let resolution = missing.probe(&recorded(&host, &registry));
        assert_eq!(resolution.state, Some(enabled()));
        assert_eq!(resolution.source, ManagementSource::Default);
        assert!(resolution.uncertainty.is_none());
    }

    #[test]
    fn representative_toggles_decode_recorded_private_values() {
        for (name, toggle) in [
            ("tailored", &TAILORED_EXPERIENCES),
            ("clipboard", &CLOUD_CLIPBOARD),
            ("web search", &WEB_SEARCH),
            ("suggested apps", &SUGGESTED_APPS),
        ] {
            let host = windows_host();
            let registry = recording(vec![(
                toggle.target,
                Evidence::Present {
                    source: toggle.source(),
                    value: RawValue::u32(toggle.private_value),
                },
            )]);
            let resolution = toggle.probe(&recorded(&host, &registry));
            assert_eq!(
                resolution.state,
                Some(SemanticState::new(toggle.desired_state)),
                "{name}"
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
    fn user_values_and_policy_restrictions_are_distinct() {
        assert_eq!(decode_user_setting(&RawValue::u32(0)), Some(disabled()));
        assert_eq!(
            decode_policy(&RawValue::u32(0)),
            Some(AdvertisingPolicy::UserChoice)
        );

        assert_eq!(decode_user_setting(&RawValue::u32(1)), Some(enabled()));
        assert_eq!(
            decode_policy(&RawValue::u32(1)),
            Some(AdvertisingPolicy::Disabled)
        );
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
    fn absent_diagnostic_values_use_the_documented_default() {
        let host = windows_host();
        let registry = recording(vec![
            (
                DIAGNOSTICS_POLICY,
                Evidence::Absent {
                    source: ManagementSource::GroupPolicy,
                },
            ),
            (
                DIAGNOSTICS_SETTING,
                Evidence::Absent {
                    source: ManagementSource::LocalPolicy,
                },
            ),
        ]);
        let resolution = probe_diagnostics_level(&recorded(&host, &registry));
        assert_eq!(resolution.state, Some(SemanticState::new("optional")));
        assert_eq!(resolution.source, ManagementSource::Default);
    }

    #[test]
    fn a_gated_level_is_classified_not_only_described() {
        // A caller must be able to branch on the failure rather than parse a
        // sentence, so the typed reason travels with the prose.
        let mut host = windows_host();
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
        for edition in ["Professional", "Enterprise"] {
            host.edition = Fact::Known(edition.to_owned());
            let resolution = probe_diagnostics_level(&recorded(&host, &registry));
            assert_eq!(
                resolution.ineffective,
                if edition == "Professional" {
                    Some(Ineffective::EditionGated)
                } else {
                    None
                },
                "{edition}: a gated value must carry its typed reason"
            );
            assert_eq!(
                resolution.note.is_some(),
                resolution.ineffective.is_some(),
                "{edition}: prose and classification disagree"
            );
        }
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
        // When the gated value is configured, the reported state
        // must be what the platform acts on, and the discrepancy must be
        // stated rather than left for the operator to discover.
        let host = windows_host();
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
            "a gated level must report the level actually in effect"
        );
        let note = resolution.note.as_deref().unwrap_or_default();
        assert!(note.contains("does not honor"), "note does not explain");
    }

    #[test]
    fn absent_advertising_values_produce_the_documented_default() {
        let host = windows_host();
        let registry = recording(vec![
            (
                ADVERTISING_POLICY,
                Evidence::Absent {
                    source: ManagementSource::GroupPolicy,
                },
            ),
            (
                ADVERTISING_USER,
                Evidence::Absent {
                    source: ManagementSource::User,
                },
            ),
        ]);
        let resolution = probe_advertising_id(&recorded(&host, &registry));
        assert_eq!(resolution.state, Some(enabled()));
        assert!(resolution.honored);
    }

    #[test]
    fn the_control_evaluates_recorded_evidence_end_to_end() {
        let host = windows_host();
        let registry = recording(vec![
            (
                ADVERTISING_POLICY,
                Evidence::Absent {
                    source: ManagementSource::GroupPolicy,
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
        let control = advertising_id();
        let resolution = control.observe(&recorded(&host, &registry));
        let result = evaluate(
            &control.spec,
            Mode::Enforce,
            &resolution,
            &host,
            Exception::None,
        );

        assert_eq!(result.id, "windows.advertising.id");
        assert_eq!(result.section, "advertising");
        assert_eq!(result.outcome, Outcome::Pass);
        assert!(result.is_coherent());
    }

    #[test]
    fn error_reporting_probe_reads_policy() {
        let host = windows_host();
        let present = recording(vec![(
            ERROR_REPORTING_POLICY,
            Evidence::Present {
                source: ManagementSource::LocalPolicy,
                value: RawValue::u32(1),
            },
        )]);
        assert_eq!(
            probe_error_reporting(&recorded(&host, &present)).state,
            Some(disabled())
        );

        let present_enabled = recording(vec![(
            ERROR_REPORTING_POLICY,
            Evidence::Present {
                source: ManagementSource::LocalPolicy,
                value: RawValue::u32(0),
            },
        )]);
        assert_eq!(
            probe_error_reporting(&recorded(&host, &present_enabled)).state,
            Some(enabled())
        );

        let absent = recording(vec![(
            ERROR_REPORTING_POLICY,
            Evidence::Absent {
                source: ManagementSource::LocalPolicy,
            },
        )]);
        assert_eq!(
            probe_error_reporting(&recorded(&host, &absent)).state,
            Some(enabled())
        );
    }

    #[test]
    fn pagefile_clear_probe_reads_policy() {
        let host = windows_host();
        let present = recording(vec![(
            PAGEFILE_CLEAR_POLICY,
            Evidence::Present {
                source: ManagementSource::LocalPolicy,
                value: RawValue::u32(1),
            },
        )]);
        assert_eq!(
            probe_pagefile_clear(&recorded(&host, &present)).state,
            Some(enabled())
        );

        let present_disabled = recording(vec![(
            PAGEFILE_CLEAR_POLICY,
            Evidence::Present {
                source: ManagementSource::LocalPolicy,
                value: RawValue::u32(0),
            },
        )]);
        assert_eq!(
            probe_pagefile_clear(&recorded(&host, &present_disabled)).state,
            Some(disabled())
        );

        let absent = recording(vec![(
            PAGEFILE_CLEAR_POLICY,
            Evidence::Absent {
                source: ManagementSource::LocalPolicy,
            },
        )]);
        assert_eq!(
            probe_pagefile_clear(&recorded(&host, &absent)).state,
            Some(disabled())
        );
    }

    #[test]
    fn trim_notify_probe_reads_policy() {
        let host = windows_host();
        let present = recording(vec![(
            TRIM_NOTIFY_POLICY,
            Evidence::Present {
                source: ManagementSource::LocalPolicy,
                value: RawValue::u32(0),
            },
        )]);
        assert_eq!(
            probe_trim_notify(&recorded(&host, &present)).state,
            Some(enabled())
        );

        let disabled_trim = recording(vec![(
            TRIM_NOTIFY_POLICY,
            Evidence::Present {
                source: ManagementSource::LocalPolicy,
                value: RawValue::u32(1),
            },
        )]);
        assert_eq!(
            probe_trim_notify(&recorded(&host, &disabled_trim)).state,
            Some(disabled())
        );

        let absent = recording(vec![(
            TRIM_NOTIFY_POLICY,
            Evidence::Absent {
                source: ManagementSource::LocalPolicy,
            },
        )]);
        assert_eq!(
            probe_trim_notify(&recorded(&host, &absent)).state,
            Some(enabled())
        );
    }
}
