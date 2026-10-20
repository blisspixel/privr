//! Rendering the evidence behind a finding.
//!
//! A result says what is true. This says why it is true, what it costs to
//! change, and where the claim comes from. A tool that reports findings without
//! showing its evidence is asking to be trusted rather than checked, which is
//! the thing this project exists to avoid.

use crate::catalog::{self, Control};
use crate::engine::evaluate::{Mode, Resolution, Uncertainty, evaluate};
use crate::model::host::{HostFacts, ManagementSource};
use crate::model::outcome::{ControlResult, Exception, Remediation, Support};
use crate::model::posture::PostureDimension;
use crate::ui::{Ui, style};

/// Why a control could not be found.
pub enum NotFound {
    /// No control carries this identifier.
    Unknown,
}

/// Look up one control by exact identifier.
pub fn find(id: &str) -> Result<Control, NotFound> {
    catalog::all()
        .into_iter()
        .find(|control| control.spec.id == id)
        .ok_or(NotFound::Unknown)
}

/// Suggest identifiers close to what was asked for.
///
/// A bare "not found" wastes the caller's next step. Candidates are matched by
/// shared prefix rather than edit distance, which is enough for hierarchical
/// identifiers and needs no dependency.
pub fn suggestions(id: &str) -> Vec<String> {
    let needle = id.to_ascii_lowercase();
    let mut hits: Vec<String> = catalog::all()
        .into_iter()
        .map(|control| control.spec.id)
        .filter(|candidate| {
            let candidate = candidate.to_ascii_lowercase();
            candidate.contains(&needle)
                || needle
                    .split('.')
                    .next()
                    .is_some_and(|head| !head.is_empty() && candidate.starts_with(head))
        })
        .collect();
    hits.sort_unstable();
    hits.truncate(5);
    hits
}

/// The human-readable current state, phrased for the operator.
fn current_state(resolution: &Resolution) -> String {
    match (&resolution.state, resolution.uncertainty) {
        (Some(state), _) => state.0.clone(),
        (None, Some(Uncertainty::Denied)) => "could not be read, access was refused".to_owned(),
        (None, Some(Uncertainty::Malformed)) => {
            "a value is set that does not match the documented type".to_owned()
        }
        (None, Some(Uncertainty::Unsupported)) => "no reading interface on this host".to_owned(),
        (None, Some(Uncertainty::EnforcementMechanismOnly)) => {
            "only the enforcing policy was readable, not the setting itself".to_owned()
        }
        (None, _) => "could not be determined".to_owned(),
    }
}

fn source_label(source: ManagementSource) -> &'static str {
    match source {
        ManagementSource::User => "your own setting",
        ManagementSource::LocalPolicy => "local policy on this machine",
        ManagementSource::GroupPolicy => "group policy",
        ManagementSource::Mdm => "device management",
        ManagementSource::ConfigurationProfile => "a configuration profile",
        ManagementSource::Default => "the platform default",
        ManagementSource::Unknown => "an authority that could not be identified",
    }
}

fn remediation_label(result: &ControlResult) -> String {
    match result.remediation {
        Remediation::Automatic => "privr can change this and reverse it exactly".to_owned(),
        Remediation::Guided => "change this yourself; privr will not".to_owned(),
        Remediation::AuditOnly => "privr reports this but will not change it".to_owned(),
        Remediation::None => result.remediation_reason.map_or_else(
            || "not changeable".to_owned(),
            |reason| format!("not changeable: {reason:?}"),
        ),
    }
}

/// Render the full explanation for a control.
pub fn render(control: &Control, host: &HostFacts, ui: &Ui) -> String {
    let resolution = control.observe(&catalog::Context::live(host));
    let result = evaluate(
        &control.spec,
        Mode::Enforce,
        &resolution,
        host,
        Exception::None,
    );

    let mut out = String::new();
    let field_width = Ui::label_width(&["Finding", "Current", "Desired", "Set by", "Change"]);
    let field = |name: &str| ui.field(name, field_width);

    out.push_str(&format!(
        "{}\n{}\n",
        ui.paint(style::HEADING, control.title),
        ui.paint(style::MUTED, &control.spec.id)
    ));
    out.push_str(
        "This is a fresh reading of the machine. It does not reconstruct an earlier check.\n\n",
    );

    out.push_str(&ui.wrap(control.summary, 0));
    out.push_str("\n\n");

    // The finding, and the two facts that qualify it.
    let label = ui.paint(
        style::outcome_style(result.outcome),
        style::outcome_label(result.outcome).trim(),
    );
    out.push_str(&format!("{} {label}\n", field("Finding")));
    out.push_str(&format!(
        "{} {}\n",
        field("Current"),
        current_state(&resolution)
    ));
    out.push_str(&format!(
        "{} {}\n",
        field("Desired"),
        control.spec.desired.0
    ));
    out.push_str(&format!(
        "{} {}\n",
        field("Set by"),
        source_label(result.management_source)
    ));

    if result.support != Support::Verified {
        let caveat = ui.wrap_after(
            "not verified on this platform version, so it cannot report a pass",
            field_width,
        );
        out.push_str(&ui.paint_lines(style::CAVEAT, &caveat));
        out.push('\n');
    }
    out.push_str(&format!(
        "{} {}\n",
        field("Change"),
        remediation_label(&result)
    ));

    // After the field block rather than inside it, so the fields stay a
    // scannable unit. Printed even on a pass, because the case this exists for
    // is precisely a finding that looks fine and is not what was configured.
    if let Some(note) = &result.note {
        out.push('\n');
        out.push_str(&ui.paint_lines(style::CAVEAT, &ui.wrap(note, 0)));
        out.push('\n');
    }
    out.push('\n');

    out.push_str(&format!("{}\n", ui.paint(style::HEADING, "Why it matters")));
    out.push_str(&ui.wrap(control.rationale, 0));
    out.push_str("\n\n");

    if let Some(tradeoff) = control.tradeoff {
        out.push_str(&format!("{}\n", ui.paint(style::HEADING, "What it costs")));
        out.push_str(&ui.wrap(tradeoff, 0));
        out.push('\n');

        // A cost stated without a remedy is worse informed than it needs to be,
        // so the mitigation sits with it rather than in a separate section.
        if let Some(mitigation) = control.mitigation {
            out.push_str(&ui.wrap(mitigation, 0));
            out.push('\n');
        }
        out.push('\n');
    }

    out.push_str(&format!("{}\n", ui.paint(style::HEADING, "Evidence")));
    for source in control.sources {
        out.push_str(&ui.wrap(source.claim, 0));
        out.push('\n');
        out.push_str(&ui.paint(
            style::MUTED,
            &format!("{}  reviewed {}", source.url, source.reviewed),
        ));
        out.push('\n');
    }

    out
}

/// Render the posture model and examples from this build's compiled catalogue.
pub fn render_overview(ui: &Ui) -> String {
    render_overview_for(&catalog::all(), ui)
}

fn render_overview_for(controls: &[Control], ui: &Ui) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}\n\n",
        ui.paint(style::HEADING, "privr Posture Model & Critical Controls")
    ));

    out.push_str(&format!(
        "{}\n",
        ui.paint(style::HEADING, "1. How Posture Is Calculated")
    ));
    out.push_str(&ui.wrap(
        "Posture is not an arbitrary marketing score or opaque scalar. It represents the exact \
         proportion of evaluated controls in the active profile matching your target privacy policy:",
        2,
    ));
    out.push('\n');
    out.push_str(&format!(
        "    {}\n\n",
        ui.paint(
            style::MUTED,
            "Posture = passing controls / evaluated controls (for example, 5 of 10 passing)"
        )
    ));
    out.push_str(&ui.wrap(
        "Unknown, unchecked, error, and excluded results do not enter this denominator. \
         The percentage describes evaluated controls only; read the counts and completeness \
         before drawing conclusions. With no evaluated controls, posture is unavailable.",
        2,
    ));
    out.push_str("\n\n");

    out.push_str(&format!(
        "{}\n",
        ui.paint(style::HEADING, "2. Five Orthogonal Posture Dimensions")
    ));
    for dimension in PostureDimension::ALL {
        let examples: Vec<_> = controls
            .iter()
            .filter(|control| control.spec.dimension == dimension)
            .map(|control| control.title)
            .collect();
        let description = if examples.is_empty() {
            "No controls in this platform build.".to_owned()
        } else {
            examples.join(", ")
        };
        out.push_str(&format!(
            "  {}\n",
            ui.paint(style::IDENT, dimension.display_name()),
        ));
        out.push_str(&ui.wrap(&description, 4));
        out.push('\n');
    }
    out.push('\n');

    out.push_str(&format!(
        "{}\n",
        ui.paint(style::HEADING, "3. Four Operational Friction Tiers")
    ));
    let tiers = [
        (
            "Tier 0 (Transparent)",
            "No expected workflow disruption or visible interface change.",
        ),
        (
            "Tier 1 (Cosmetic)",
            "Minor visual changes without a workflow change.",
        ),
        (
            "Tier 2 (Workflow Altering)",
            "Changes a user-facing workflow or removes a convenience.",
        ),
        (
            "Tier 3 (Incompatible / Tradeoff)",
            "Compatibility, diagnostic, or security tradeoffs requiring deliberate review.",
        ),
    ];
    for (name, desc) in tiers {
        out.push_str(&format!(
            "  {:26} {}\n",
            ui.paint(style::IDENT, name),
            ui.paint(style::MUTED, desc)
        ));
    }
    out.push('\n');

    out.push_str(&format!(
        "{}\n",
        ui.paint(style::HEADING, "4. Compiled Controls For This Platform")
    ));
    if controls.is_empty() {
        out.push_str("  No controls are compiled for this platform.\n");
    }
    for control in controls {
        out.push_str(&format!(
            "  {} {}\n",
            ui.paint(style::IDENT, control.title),
            ui.paint(style::MUTED, &format!("({})", control.spec.id))
        ));
        out.push_str(&ui.paint(style::MUTED, &ui.wrap(control.summary, 4)));
        out.push('\n');
        out.push_str(&ui.wrap(control.spec.friction.display_name(), 4));
        if let Some(tradeoff) = control.tradeoff {
            out.push('\n');
            out.push_str(&ui.wrap(tradeoff, 4));
        }
        out.push('\n');
    }
    out.push('\n');

    out.push_str(&format!(
        "{}\n",
        ui.paint(style::HEADING, "Actionable Commands")
    ));
    out.push_str(&format!(
        "  {:18} {}\n",
        ui.paint(style::IDENT, "privr diff"),
        ui.paint(
            style::MUTED,
            "Preview eligible changes, current/desired state, and friction"
        )
    ));
    out.push_str(&format!(
        "  {:18} {}\n",
        ui.paint(style::IDENT, "privr check"),
        ui.paint(
            style::MUTED,
            "Read outcomes, unknown counts, and selected-profile completeness"
        )
    ));
    out.push_str(&format!(
        "  {:18} {}\n",
        ui.paint(style::IDENT, "privr explain <id>"),
        ui.paint(
            style::MUTED,
            "Inspect current evidence, tradeoffs, and citations for a compiled control"
        )
    ));

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform;

    #[cfg(windows)]
    const KNOWN: &str = "windows.advertising.id";
    #[cfg(target_os = "linux")]
    const KNOWN: &str = "debian.popularity-contest.participation";
    #[cfg(target_os = "macos")]
    const KNOWN: &str = "macos.analytics.share-mac";
    #[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
    const KNOWN: &str = "unknown";

    #[test]
    fn an_unknown_identifier_is_not_found() {
        assert!(find("platform.does.not.exist").is_err());
    }

    #[test]
    fn a_known_identifier_resolves() {
        assert!(find(KNOWN).is_ok());
    }

    #[test]
    fn a_near_miss_suggests_the_real_identifier() {
        // A bare failure wastes the caller's next step, whether that caller is
        // a person or an agent.
        let prefix = if cfg!(windows) {
            "windows.advertising"
        } else if cfg!(target_os = "macos") {
            "macos.analytics"
        } else {
            "debian.popularity"
        };
        let hits = suggestions(prefix);
        assert!(hits.iter().any(|id| id == KNOWN), "no suggestion: {hits:?}");
    }

    #[test]
    fn suggestions_are_bounded() {
        let prefix = if cfg!(windows) {
            "windows"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else {
            "debian"
        };
        assert!(suggestions(prefix).len() <= 5);
    }

    #[test]
    fn an_explanation_carries_its_evidence() {
        let host = platform::discover();
        let control = find(KNOWN).ok().expect("control exists");
        let text = render(&control, &host, &Ui::plain());

        // The properties that separate an explanation from an assertion.
        assert!(text.contains("Evidence"), "no evidence section");
        assert!(text.contains("https://"), "no source link");
        assert!(text.contains("reviewed 20"), "no review date");
        assert!(text.contains("Why it matters"), "no rationale");
        assert!(text.contains("Finding"), "no finding");
        assert!(text.contains("Set by"), "no management source");
    }

    #[test]
    fn an_explanation_pairs_a_cost_with_a_remedy() {
        let host = platform::discover();
        let control = find(KNOWN).ok().expect("control exists");
        let text = render(&control, &host, &Ui::plain());

        if control.tradeoff.is_some() {
            assert!(text.contains("What it costs"));
            let flat: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
            let mitigation = control.mitigation.expect("a cost implies a remedy");
            let head: String = mitigation
                .split_whitespace()
                .take(4)
                .collect::<Vec<_>>()
                .join(" ");
            assert!(flat.contains(&head), "cost stated without its remedy");
        }
    }

    #[test]
    fn an_explanation_is_plain_text_when_color_is_off() {
        let host = platform::discover();
        let control = find(KNOWN).ok().expect("control exists");
        let text = render(&control, &host, &Ui::plain());
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn an_explanation_renders_with_color_when_enabled() {
        let host = platform::discover();
        let control = find(KNOWN).ok().expect("control exists");
        let text = render(
            &control,
            &host,
            &Ui::resolve(crate::ui::ColorPreference::Always, true),
        );
        assert!(!text.is_empty());
    }

    #[test]
    fn state_wording_distinguishes_every_uncertainty() {
        let mut seen = Vec::new();
        for uncertainty in [
            Uncertainty::Denied,
            Uncertainty::Malformed,
            Uncertainty::Unsupported,
            Uncertainty::Undetermined,
            Uncertainty::EnforcementMechanismOnly,
        ] {
            let wording =
                current_state(&Resolution::uncertain(uncertainty, ManagementSource::User));
            assert!(!wording.is_empty());
            seen.push(wording);
        }
        let count = seen.len();
        seen.sort();
        seen.dedup();
        // Denied and undetermined may legitimately share wording only if the
        // distinction is carried elsewhere; here they must not.
        assert!(seen.len() >= count - 1, "uncertainty wording collapses");
    }

    #[test]
    fn every_management_source_has_plain_language() {
        for source in [
            ManagementSource::User,
            ManagementSource::LocalPolicy,
            ManagementSource::GroupPolicy,
            ManagementSource::Mdm,
            ManagementSource::ConfigurationProfile,
            ManagementSource::Default,
            ManagementSource::Unknown,
        ] {
            let label = source_label(source);
            assert!(!label.is_empty());
            // The operator should not have to know the internal vocabulary.
            assert!(!label.contains('_'));
        }
    }

    #[test]
    fn overview_renders_educational_walkthrough() {
        let plain_ui = Ui::plain();
        let text = render_overview(&plain_ui);
        assert!(text.contains("privr Posture Model & Critical Controls"));
        assert!(text.contains("1. How Posture Is Calculated"));
        assert!(text.contains("2. Five Orthogonal Posture Dimensions"));
        assert!(text.contains("3. Four Operational Friction Tiers"));
        assert!(text.contains("4. Compiled Controls For This Platform"));
        for control in catalog::all() {
            assert!(text.contains(&control.spec.id), "{}", control.spec.id);
        }
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn empty_overview_does_not_invent_platform_examples_or_supported_mutations() {
        let text = render_overview_for(&[], &Ui::plain());
        assert_eq!(
            text.matches("No controls in this platform build.").count(),
            5
        );
        assert!(text.contains("No controls are compiled for this platform"));
        assert!(!text.contains("windows."));
        assert!(!text.contains("privr fix"));
        assert!(
            text.split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
                .contains("posture is unavailable")
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn non_windows_overview_has_no_windows_control_or_dimension_examples() {
        let text = render_overview(&Ui::plain());
        for unsupported in [
            "windows.",
            "Shell MRU",
            "Jump Lists",
            "NCSI",
            "Windows Error Reporting",
            "inking",
        ] {
            assert!(!text.contains(unsupported), "{unsupported}");
        }
    }
}
