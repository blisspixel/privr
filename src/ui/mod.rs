//! Terminal presentation.
//!
//! For this product the printed report is the interface, so the rules here are
//! part of the contract rather than decoration:
//!
//! - standard output carries results, standard error carries everything else,
//!   so a pipe or an agent parse is never polluted;
//! - color is a second channel and never the only one;
//! - an explicit choice beats the environment, and the environment beats the
//!   default;
//! - no box drawing, which wraps badly and defeats copy and paste.

pub mod progress;
pub mod style;

use std::io::IsTerminal;

use anstyle::Style;
use colorchoice::ColorChoice;

pub use progress::Spinner;

impl From<crate::cli::ColorWhen> for ColorPreference {
    fn from(value: crate::cli::ColorWhen) -> Self {
        match value {
            crate::cli::ColorWhen::Auto => Self::Auto,
            crate::cli::ColorWhen::Always => Self::Always,
            crate::cli::ColorWhen::Never => Self::Never,
        }
    }
}

/// What the caller asked for on the command line.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum ColorPreference {
    #[default]
    Auto,
    Always,
    Never,
}

/// Presentation settings resolved once, then passed down.
#[derive(Clone, Copy, Debug)]
pub struct Ui {
    color: bool,
    unicode: bool,
    width: usize,
}

impl Ui {
    /// Resolve settings from the caller's preference and the environment.
    pub fn resolve(preference: ColorPreference, stream_is_terminal: bool) -> Self {
        let color = match preference {
            // An explicit flag wins over everything, including NO_COLOR. The
            // specification is clear that a flag is the user speaking most
            // recently and most deliberately.
            ColorPreference::Always => true,
            ColorPreference::Never => false,
            ColorPreference::Auto => {
                if anstyle_query::no_color() {
                    false
                } else if anstyle_query::clicolor_force() {
                    true
                } else {
                    stream_is_terminal && anstyle_query::term_supports_color()
                }
            }
        };

        Self {
            color,
            unicode: detect_unicode(),
            width: detect_width(),
        }
    }

    /// Settings for the current process, reading standard output.
    pub fn for_stdout(preference: ColorPreference) -> Self {
        Self::resolve(preference, std::io::stdout().is_terminal())
    }

    /// Settings that render nothing decorative, for tests and captured output.
    pub const fn plain() -> Self {
        Self {
            color: false,
            unicode: false,
            width: 80,
        }
    }

    pub const fn color(&self) -> bool {
        self.color
    }

    pub const fn unicode(&self) -> bool {
        self.unicode
    }

    pub const fn width(&self) -> usize {
        self.width
    }

    /// Wrap `text` in `style`, or return it unchanged when color is off.
    pub fn paint(&self, style: Style, text: &str) -> String {
        if self.color {
            format!("{style}{text}{style:#}")
        } else {
            text.to_owned()
        }
    }

    /// Start a spinner that matches this terminal's capabilities.
    pub fn spinner(&self, message: &str) -> Spinner {
        Spinner::start(message, self.unicode)
    }

    /// Wrap prose to the usable width at whitespace, indenting continuations.
    ///
    /// Explanations are sentences, and a sentence that runs off the edge of a
    /// terminal is a sentence nobody reads.
    pub fn wrap(&self, text: &str, indent: usize) -> String {
        let limit = self.width.saturating_sub(indent).max(24);
        let pad = " ".repeat(indent);

        let mut lines = Vec::new();
        let mut current = String::new();
        for word in text.split_whitespace() {
            if current.is_empty() {
                current.push_str(word);
            } else if current.chars().count() + 1 + word.chars().count() <= limit {
                current.push(' ');
                current.push_str(word);
            } else {
                lines.push(current.clone());
                current.clear();
                current.push_str(word);
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }

        lines
            .iter()
            .map(|line| format!("{pad}{line}"))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Whether the terminal can be trusted with characters outside ASCII.
fn detect_unicode() -> bool {
    // A modern Windows terminal sets its own marker. The legacy console does
    // not, and renders box and braille characters as noise, so ASCII is the
    // safe assumption there.
    if cfg!(windows) {
        return std::env::var_os("WT_SESSION").is_some()
            || std::env::var_os("TERM_PROGRAM").is_some()
            || std::env::var("TERM").is_ok_and(|term| term != "dumb");
    }
    !matches!(std::env::var("TERM").as_deref(), Ok("dumb"))
}

/// The usable output width.
///
/// Terminal size is not queried, which would need platform calls in a crate
/// that otherwise needs none. `COLUMNS` covers the case that matters, and the
/// fallback is a width that reads well everywhere.
fn detect_width() -> usize {
    std::env::var("COLUMNS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|width| *width >= 40)
        .map_or(88, |width| width.min(100))
}

/// Translate our preference into the choice `anstream` understands.
pub const fn color_choice(color: bool) -> ColorChoice {
    if color {
        ColorChoice::Always
    } else {
        ColorChoice::Never
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_explicit_flag_overrides_the_environment() {
        // The specification is explicit that a flag outranks NO_COLOR, because
        // it is the more recent and more deliberate instruction.
        assert!(Ui::resolve(ColorPreference::Always, false).color());
        assert!(!Ui::resolve(ColorPreference::Never, true).color());
    }

    #[test]
    fn automatic_color_is_off_when_output_is_not_a_terminal() {
        // The property that keeps a pipe clean: redirected output carries no
        // control sequences unless the caller asks for them.
        assert!(!Ui::resolve(ColorPreference::Auto, false).color());
    }

    #[test]
    fn plain_settings_render_text_unchanged() {
        let ui = Ui::plain();
        let painted = ui.paint(style::HEADING, "Profile");
        assert_eq!(painted, "Profile");
        assert!(!painted.contains('\u{1b}'));
    }

    #[test]
    fn painting_with_color_wraps_and_resets() {
        let ui = Ui {
            color: true,
            unicode: true,
            width: 80,
        };
        let painted = ui.paint(style::HEADING, "Profile");
        assert!(painted.contains("Profile"));
        assert!(painted.contains('\u{1b}'), "no escape sequence emitted");
        assert!(painted.ends_with("\u{1b}[0m"), "style was not reset");
    }

    #[test]
    fn wrapping_respects_the_width_and_indent() {
        let ui = Ui {
            color: false,
            unicode: false,
            width: 40,
        };
        let text = "The identifier lets separate applications correlate what you do \
                    into one profile across apps.";
        let wrapped = ui.wrap(text, 4);

        for line in wrapped.lines() {
            assert!(line.starts_with("    "), "line lost its indent: {line}");
            assert!(line.chars().count() <= 40, "line too wide: {line}");
        }
        assert!(wrapped.lines().count() > 1, "text did not wrap");
    }

    #[test]
    fn wrapping_preserves_every_word() {
        let ui = Ui::plain();
        let text = "one two three four five six seven eight nine ten";
        let wrapped = ui.wrap(text, 2);

        let original: Vec<&str> = text.split_whitespace().collect();
        let result: Vec<&str> = wrapped.split_whitespace().collect();
        assert_eq!(original, result);
    }

    #[test]
    fn a_very_narrow_terminal_still_produces_output() {
        let ui = Ui {
            color: false,
            unicode: false,
            width: 10,
        };
        let wrapped = ui.wrap("a somewhat longer sentence than the width", 4);
        assert!(!wrapped.is_empty());
    }

    #[test]
    fn width_detection_stays_within_readable_bounds() {
        let width = detect_width();
        assert!((40..=100).contains(&width), "unreasonable width {width}");
    }
}
