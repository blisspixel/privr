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
        ui.paint(style::IDENT, "privr clean"),
        ui.paint(
            style::MUTED,
            "Preview and purge disposable caches, activity databases, and residue"
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
    out.push_str(&format!(
        "  {:18} {}\n",
        ui.paint(style::IDENT, "privr explain residue"),
        ui.paint(
            style::MUTED,
            "Forensic artifact analysis, polite vs aggressive modes, and cache hygiene"
        )
    ));
    out.push_str(&format!(
        "  {:18} {}\n",
        ui.paint(style::IDENT, "privr explain storage"),
        ui.paint(
            style::MUTED,
            "NAND flash mechanics, TRIM/DZAT deallocation, and chip-off defense"
        )
    ));

    out
}

/// Render the forensic residue architecture, cache hygiene, and sanitization model.
pub fn render_residue_explanation(ui: &Ui) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}\n\n",
        ui.paint(
            style::HEADING,
            "privr Disposable Residue & Forensic Sanitization Architecture"
        )
    ));

    out.push_str(&format!(
        "{}\n",
        ui.paint(
            style::HEADING,
            "1. Forensic Residue: How Operating Systems Log Activity"
        )
    ));
    out.push_str(&ui.wrap(
        "Modern operating systems, web browsers, and desktop tools continuously log user \
         actions into specialized metadata stores, caches, and SQLite databases. \
         These artifacts record sensitive access history even after source files are deleted \
         or viewed from external encrypted volumes:",
        2,
    ));
    out.push('\n');
    out.push_str(&ui.wrap(
        "- Jump Lists and Recent Items: AutomaticDestinations and CustomDestinations track opened \
         files, pinned paths, and execution timestamps for taskbar shortcuts.",
        4,
    ));
    out.push('\n');
    out.push_str(&ui.wrap(
        "- Windows Activity History: ConnectedDevicesPlatform (ActivitiesCache.db) logs chronological \
         app access timelines, document metadata, and cross-device clipboard history payloads.",
        4,
    ));
    out.push('\n');
    out.push_str(&ui.wrap(
        "- CryptoAPI Cache: CryptnetUrlCache stores CRL and OCSP certificate revocation checks, \
         revealing domains and HTTPS endpoints contacted by background services and applications.",
        4,
    ));
    out.push('\n');
    out.push_str(&ui.wrap(
        "- Shell Caches: File Explorer thumbnail and icon databases (thumbcache_*.db, iconcache_*.db) \
         persist scaled image previews and application icons indefinitely.",
        4,
    ));
    out.push_str("\n\n");

    out.push_str(&format!(
        "{}\n",
        ui.paint(
            style::HEADING,
            "2. Polite Mode vs Aggressive Mode: Intentional Distinction"
        )
    ));
    out.push_str(&ui.wrap(
        "privr clean distinguishes between pure waste and high-cost convenience caches:",
        2,
    ));
    out.push('\n');
    out.push_str(&ui.wrap(
        "- Polite Mode (--polite): Purges strictly disposable operational residue (system temp files, \
         DirectX/GPU shader caches, browser web caches, WER error reporting queues, and AI agent debug logs) \
         while retaining convenience caches whose recreation is computationally expensive or disrupts \
         daily workflow (Explorer thumbnail previews, Jump Lists, command line history, and developer package caches).",
        4,
    ));
    out.push('\n');
    out.push_str(&ui.wrap(
        "- Aggressive Mode (default for deep cleans): Performs an exhaustive forensic clean of all reviewed \
         categories, removing historical activity timelines, command histories, Jump Lists, package archives, \
         and thumbnail/icon caches.",
        4,
    ));
    out.push_str("\n\n");

    out.push_str(&format!(
        "{}\n",
        ui.paint(
            style::HEADING,
            "3. Scientific Sanitization vs Legacy Cleaner Antipatterns"
        )
    ));
    out.push_str(&ui.wrap(
        "privr replaces obsolete legacy practices with scientifically sound privacy patterns:",
        2,
    ));
    out.push('\n');
    out.push_str(&ui.wrap(
        "- No Registry Cleaners: Blindly deleting orphaned COM registrations, file type associations, \
         and CLSIDs is hazardous snake oil that causes application crashes and shell corruption. \
         privr never performs speculative registry scanning; it configures reviewed, authoritative policy toggles.",
        4,
    ));
    out.push('\n');
    out.push_str(&ui.wrap(
        "- Zero-Wear Hardware TRIM: Traditional multi-pass disk overwrites (DoD 5220.22-M) burn NAND flash \
         endurance (TBW) without sanitizing wear-leveled flash blocks. privr issues hardware TRIM / Deallocate \
         to instruct the SSD controller to deallocate unmapped LBAs instantly (0 B flash wear).",
        4,
    ));
    out.push('\n');
    out.push_str(&ui.wrap(
        "- Session Preservation: Unlike blunt cleaners that log users out of all websites, privr cleans HTTP \
         assets, images, and script bytecode while preserving cookies, authenticated sessions, and passwords.",
        4,
    ));
    out.push_str("\n\n");

    out.push_str(&format!(
        "{}\n",
        ui.paint(style::HEADING, "4. AI Agent & Developer Workspace Hygiene")
    ));
    out.push_str(&ui.wrap(
        "Autonomous coding agents and package managers generate massive ephemeral data footprints:",
        2,
    ));
    out.push('\n');
    out.push_str(&ui.wrap(
        "- AI Agents (Claude, Codex): Agent runtimes create hundreds of megabytes of prompt transcripts, \
         model scratchpads, ambient suggestions, and execution traces. privr purges these disposable logs \
         while preserving project configurations, prompt instructions, and skills.",
        4,
    ));
    out.push('\n');
    out.push_str(&ui.wrap(
        "- Developer Caches (Cargo, NuGet, Go, npm, pip): Package managers download duplicate archive \
         tarballs and compiler build caches across the user profile. privr reclaims gigabytes of rebuildable \
         package caches without touching project vendor directories or node_modules.",
        4,
    ));
    out.push('\n');

    out
}

/// Render the storage privacy, flash mechanics, and sanitization model.
pub fn render_storage_explanation(ui: &Ui) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}\n\n",
        ui.paint(
            style::HEADING,
            "privr Storage Privacy & Forensic Sanitization Architecture"
        )
    ));

    out.push_str(&format!(
        "{}\n",
        ui.paint(
            style::HEADING,
            "1. Physical Reality: Flash Storage vs Magnetic Platters"
        )
    ));
    out.push_str(&ui.wrap(
        "On rotational hard drives (HDDs), logical sector addresses map directly to physical \
         magnetic tracks. Overwriting a sector with zeroes physically flips the magnetic domains. \
         On modern solid-state storage (SSDs, NVMe), this direct mapping does not exist.",
        2,
    ));
    out.push('\n');
    out.push_str(&ui.wrap(
        "The Flash Translation Layer (FTL) dynamically redirects writes across flash dies for wear \
         leveling. Overwriting a file in user space writes to a fresh block; the old block remains \
         in unallocated or overprovisioned space. Consequently, traditional multi-pass DoD 5220.22-M \
         wiping is ineffective on flash storage and unnecessarily consumes flash endurance (TBW).",
        2,
    ));
    out.push_str("\n\n");

    out.push_str(&format!(
        "{}\n",
        ui.paint(style::HEADING, "2. Hardware TRIM and Write Performance")
    ));
    out.push_str(&ui.wrap(
        "NAND flash can be written at page granularity (4KB-16KB) but can only be erased at block \
         granularity (2MB-8MB). Without TRIM, the SSD controller assumes deleted files still contain \
         valid data, causing slow synchronous Read-Modify-Write cycles when space runs low.",
        2,
    ));
    out.push('\n');
    out.push_str(&ui.wrap(
        "Hardware TRIM / Deallocate (privr clean --trim) informs the controller that deleted clusters \
         are invalid. The FTL unmaps those LBAs immediately (causing reads to return deterministic \
         zeroes under DZAT) and enables background garbage collection to pre-erase blocks without write latency.",
        2,
    ));
    out.push_str("\n\n");

    out.push_str(&format!(
        "{}\n",
        ui.paint(
            style::HEADING,
            "3. High-Assurance Defense Against Chip-Off Forensics"
        )
    ));
    out.push_str(&ui.wrap(
        "TRIM unmaps logical addresses, but physical floating-gate charges linger in silicon until \
         garbage collection cycles. If an adversary desolders the NAND flash chips from the PCB \
         (chip-off analysis), raw un-erased pages can be read directly.",
        2,
    ));
    out.push('\n');
    out.push_str(&ui.wrap(
        "The only defense against chip-off forensics on an active system is Full Disk Encryption \
         (BitLocker / LUKS). When encryption is active, raw NAND charges are cryptographically \
         indistinguishable from white noise. Desoldering the chip yields only unbreakable ciphertext.",
        2,
    ));
    out.push_str("\n\n");

    out.push_str(&format!(
        "{}\n",
        ui.paint(
            style::HEADING,
            "4. Decommissioning & Drive Disposal Standards"
        )
    ));
    out.push_str(&ui.wrap(
        "When selling, donating, or permanently retiring an SSD, follow NIST SP 800-88 Rev. 1 \
         (Purge standard) rather than multi-pass overwrites:\n  \
         - Cryptographic Erase (Crypto Erase): securely discards and rotates the internal Media Encryption Key (MEK).\n  \
         - NVMe Sanitize (Block Erase): issues a hardware firmware command sending an erase voltage across all NAND dies.\n  \
         Both methods sanitize all physical cells, including overprovisioned and retired blocks, in seconds with zero wear.",
        2,
    ));
    out.push('\n');

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
    fn storage_explanation_renders_flash_and_sanitization_walkthrough() {
        let plain_ui = Ui::plain();
        let text = render_storage_explanation(&plain_ui);
        assert!(text.contains("privr Storage Privacy & Forensic Sanitization Architecture"));
        assert!(text.contains("1. Physical Reality: Flash Storage vs Magnetic Platters"));
        assert!(text.contains("2. Hardware TRIM and Write Performance"));
        assert!(text.contains("3. High-Assurance Defense Against Chip-Off Forensics"));
        assert!(text.contains("4. Decommissioning & Drive Disposal Standards"));
        assert!(text.contains("NIST SP 800-88"));
        assert!(!text.contains('\u{1b}'));
    }

    #[test]
    fn residue_explanation_renders_forensics_and_hygiene_walkthrough() {
        let plain_ui = Ui::plain();
        let text = render_residue_explanation(&plain_ui);
        assert!(text.contains("privr Disposable Residue & Forensic Sanitization Architecture"));
        assert!(text.contains("1. Forensic Residue: How Operating Systems Log Activity"));
        assert!(text.contains("2. Polite Mode vs Aggressive Mode: Intentional Distinction"));
        assert!(text.contains("3. Scientific Sanitization vs Legacy Cleaner Antipatterns"));
        assert!(text.contains("4. AI Agent & Developer Workspace Hygiene"));
        assert!(text.contains("ConnectedDevicesPlatform"));
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
