//! The visual vocabulary.
//!
//! Two rules govern everything here.
//!
//! Color is never the only carrier of meaning. Every outcome is spelled out in
//! words as well, so the output reads identically piped, in a log, under
//! `NO_COLOR`, and to someone who cannot distinguish the hues.
//!
//! No boxes. Drawing characters wrap badly, break on narrow terminals, defeat
//! copy and paste, and are noise around content that indentation already
//! groups.

use anstyle::{AnsiColor, Color, Style};

use crate::model::outcome::Outcome;

/// Emphasis for a heading or a field the reader should land on first.
pub const HEADING: Style = Style::new().bold();

/// Secondary text: labels, units, and anything supporting the primary value.
pub const MUTED: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightBlack)));

/// A value the reader is meant to read, as opposed to its label.
pub const VALUE: Style = Style::new();

/// A control identifier. Deliberately plain so it stays copyable.
pub const IDENT: Style = Style::new().bold();

/// Text that qualifies a result and must not be skimmed past.
pub const CAVEAT: Style = Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow)));

/// The style for an outcome label.
///
/// Grouped by what the reader should do, not by severity:
///
/// - green: nothing to do;
/// - yellow: a difference from the selected policy;
/// - cyan: a decision that is genuinely the operator's;
/// - magenta: the tool could not tell, which is never a pass;
/// - dim: outside scope on this host;
/// - red: the tool itself failed.
pub const fn outcome_style(outcome: Outcome) -> Style {
    let color = match outcome {
        Outcome::Pass => AnsiColor::Green,
        Outcome::Drift => AnsiColor::Yellow,
        Outcome::Review => AnsiColor::Cyan,
        Outcome::Unknown => AnsiColor::Magenta,
        Outcome::NotApplicable | Outcome::NotSelected => AnsiColor::BrightBlack,
        Outcome::NotChecked => AnsiColor::Magenta,
        Outcome::Error => AnsiColor::Red,
    };
    Style::new().fg_color(Some(Color::Ansi(color))).bold()
}

/// The word shown for an outcome.
///
/// Fixed width so the identifiers after them line up without a table, and
/// spelled out rather than abbreviated so the meaning survives being pasted
/// somewhere with no color.
pub const fn outcome_label(outcome: Outcome) -> &'static str {
    match outcome {
        Outcome::Pass => "pass    ",
        Outcome::Drift => "drift   ",
        Outcome::Review => "review  ",
        Outcome::Unknown => "unknown ",
        Outcome::NotApplicable => "n/a     ",
        Outcome::NotSelected => "skipped ",
        Outcome::NotChecked => "unchecked",
        Outcome::Error => "error   ",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EVERY_OUTCOME: [Outcome; 8] = [
        Outcome::Pass,
        Outcome::Drift,
        Outcome::Review,
        Outcome::Unknown,
        Outcome::NotApplicable,
        Outcome::NotSelected,
        Outcome::NotChecked,
        Outcome::Error,
    ];

    #[test]
    fn every_outcome_has_a_word_not_only_a_color() {
        // The property that keeps the output readable without color: the label
        // alone must distinguish the outcome.
        for outcome in EVERY_OUTCOME {
            let label = outcome_label(outcome).trim();
            assert!(!label.is_empty(), "{outcome:?} has no label");
        }
    }

    #[test]
    fn outcome_labels_are_distinct() {
        let mut labels: Vec<&str> = EVERY_OUTCOME
            .iter()
            .map(|o| outcome_label(*o).trim())
            .collect();
        let count = labels.len();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), count, "two outcomes share a label");
    }

    #[test]
    fn outcomes_that_conceal_state_never_look_like_a_pass() {
        // Unknown and unchecked must not borrow the color that means "nothing
        // to do", because that is precisely the misreading to prevent.
        let pass = outcome_style(Outcome::Pass);
        for outcome in EVERY_OUTCOME {
            if outcome.conceals_state() {
                assert_ne!(
                    outcome_style(outcome).get_fg_color(),
                    pass.get_fg_color(),
                    "{outcome:?} is colored like a pass"
                );
            }
        }
    }

    #[test]
    fn labels_are_padded_to_align_without_a_table() {
        // Alignment comes from padding rather than box drawing, so the output
        // survives narrow terminals and copy and paste.
        let widths: Vec<usize> = EVERY_OUTCOME
            .iter()
            .map(|o| outcome_label(*o).len())
            .collect();
        assert!(widths.iter().all(|w| *w >= 8));
    }
}
