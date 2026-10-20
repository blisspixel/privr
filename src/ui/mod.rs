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

        let measured = if stream_is_terminal {
            terminal_size::terminal_size().map(|(width, _)| width.0 as usize)
        } else {
            None
        };
        let columns = std::env::var("COLUMNS").ok();

        Self {
            color,
            unicode: detect_unicode(),
            width: choose_width(columns.as_deref(), measured),
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

    /// Fixed settings for rendering tests. Width is clamped to the same 40-100
    /// range live detection uses.
    pub const fn render(color: bool, unicode: bool, width: usize) -> Self {
        Self {
            color,
            unicode,
            width: if width < 40 {
                40
            } else if width > 100 {
                100
            } else {
                width
            },
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

    /// Start a spinner when text output is requested, inert otherwise.
    pub fn spinner_for(&self, message: &str, format: crate::cli::OutputFormat) -> Spinner {
        if format != crate::cli::OutputFormat::Text {
            Spinner::inert()
        } else {
            self.spinner(message)
        }
    }

    /// Pad `label` to `width` as plain text, then paint it.
    ///
    /// Padding before painting keeps the columns aligned when colour is on.
    /// Escape sequences are not part of the width.
    pub fn field(&self, label: &str, width: usize) -> String {
        self.paint(style::MUTED, &format!("{label:<width$}"))
    }

    /// Width of the longest label in a block, in characters.
    pub fn label_width(labels: &[&str]) -> usize {
        labels
            .iter()
            .map(|label| label.chars().count())
            .max()
            .unwrap_or(0)
    }

    /// Paint each line on its own, so every line carries its own reset.
    pub fn paint_lines(&self, style: Style, text: &str) -> String {
        let mut painted = String::new();
        for (index, line) in text.split('\n').enumerate() {
            if index > 0 {
                painted.push('\n');
            }
            painted.push_str(&self.paint(style, line));
        }
        painted
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

    /// Wrap `text` so the first line follows an already-printed label.
    ///
    /// Continuation lines use a hanging indent of `used` columns.
    pub fn wrap_after(&self, text: &str, used: usize) -> String {
        let limit = self.width.saturating_sub(used).max(16);
        let mut lines = Vec::new();
        let mut current = String::new();
        for word in text.split_whitespace() {
            if current.is_empty() {
                current.push_str(word);
            } else if current.chars().count() + 1 + word.chars().count() <= limit {
                current.push(' ');
                current.push_str(word);
            } else {
                lines.push(std::mem::take(&mut current));
                current.push_str(word);
            }
        }
        if !current.is_empty() {
            lines.push(current);
        }
        let hang = " ".repeat(used);
        lines
            .iter()
            .enumerate()
            .map(|(index, line)| {
                if index == 0 {
                    line.clone()
                } else {
                    format!("{hang}{line}")
                }
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Display name for a platform identifier. JSON keeps the lowercase identifier.
pub fn platform_name(id: &str) -> &str {
    match id {
        "linux" => "Linux",
        "windows" => "Windows",
        "macos" => "macOS",
        other => other,
    }
}

/// Resolve a width from `COLUMNS`, then a measured terminal, then 88.
///
/// The result is clamped to 40-100. `COLUMNS` is an override, including when
/// it asks for a wider layout than the fallback.
pub fn choose_width(columns: Option<&str>, measured: Option<usize>) -> usize {
    let override_width = columns.and_then(|value| value.parse::<usize>().ok());
    override_width.or(measured).unwrap_or(88).clamp(40, 100)
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
    fn width_uses_columns_then_the_terminal_then_the_fallback() {
        assert_eq!(choose_width(Some("120"), Some(60)), 100);
        assert_eq!(choose_width(Some("60"), Some(80)), 60);
        assert_eq!(choose_width(Some("10"), None), 40);
        assert_eq!(choose_width(None, Some(72)), 72);
        assert_eq!(choose_width(None, None), 88);
        assert_eq!(choose_width(Some("nope"), None), 88);
    }

    #[test]
    fn field_padding_ignores_colour_sequences() {
        let plain = Ui::plain();
        let colored = Ui::render(true, false, 80);
        let plain_field = plain.field("Operating System", 20);
        let colored_field = colored.field("Operating System", 20);
        assert_eq!(plain_field, "Operating System    ");
        assert!(colored_field.contains("Operating System    "));
        assert!(colored_field.ends_with("\u{1b}[0m"));
        let stripped = strip_sgr(&colored_field);
        assert_eq!(stripped, plain_field);
    }

    #[test]
    fn painted_lines_each_carry_their_own_reset() {
        let ui = Ui::render(true, false, 80);
        let painted = ui.paint_lines(style::CAVEAT, "one\ntwo");
        for line in painted.lines() {
            assert!(line.contains('\u{1b}'), "{line}");
            assert!(line.contains("\u{1b}[0m"), "{line}");
        }
    }

    fn strip_sgr(text: &str) -> String {
        let mut out = String::new();
        let mut chars = text.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\u{1b}' {
                for next in chars.by_ref() {
                    if next == 'm' {
                        break;
                    }
                }
            } else {
                out.push(ch);
            }
        }
        out
    }
}
