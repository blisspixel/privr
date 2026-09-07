//! Progress reporting for work that takes long enough to notice.
//!
//! Three rules:
//!
//! Progress goes to standard error. Standard output carries results, so a
//! spinner must never appear in a pipe, a redirect, or an agent's parse.
//!
//! Progress appears only on a terminal. A non-interactive run gets nothing,
//! rather than a stream of control sequences in a log file.
//!
//! The spinner always clears itself, including when the work fails or the
//! process unwinds, so it can never leave a half-drawn line behind.

use std::io::{IsTerminal, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Braille frames, which animate smoothly and occupy one cell.
const UNICODE_FRAMES: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
/// The fallback for terminals that cannot render the above.
const ASCII_FRAMES: [&str; 4] = ["|", "/", "-", "\\"];

const INTERVAL: Duration = Duration::from_millis(80);

/// A running spinner. Stops and clears when dropped.
pub struct Spinner {
    running: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Spinner {
    /// Start a spinner, or return an inert one when output is not a terminal.
    pub fn start(message: &str, unicode: bool) -> Self {
        if !std::io::stderr().is_terminal() {
            return Self::inert();
        }

        let running = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&running);
        let message = message.to_owned();

        let handle = thread::spawn(move || {
            let frames: &[&str] = if unicode {
                &UNICODE_FRAMES
            } else {
                &ASCII_FRAMES
            };
            let mut index = 0;
            while flag.load(Ordering::Relaxed) {
                let mut err = std::io::stderr().lock();
                // Carriage return and clear-to-end, so each frame overwrites
                // the previous one rather than accumulating lines.
                let _ = write!(err, "\r\x1b[2K{} {message}", frames[index % frames.len()]);
                let _ = err.flush();
                drop(err);

                index = index.wrapping_add(1);
                thread::sleep(INTERVAL);
            }
        });

        Self {
            running,
            handle: Some(handle),
        }
    }

    /// A spinner that draws nothing, for non-interactive use.
    pub fn inert() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            handle: None,
        }
    }

    /// Whether this spinner is actually drawing.
    pub fn is_active(&self) -> bool {
        self.handle.is_some()
    }

    /// Stop and erase the line.
    pub fn finish(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
            let mut err = std::io::stderr().lock();
            let _ = write!(err, "\r\x1b[2K");
            let _ = err.flush();
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        // Clearing on drop rather than only on an explicit stop means an early
        // return or an unwind cannot leave a partial frame on the terminal.
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_spinner_is_inert_when_output_is_not_a_terminal() {
        // Test output is captured, so this exercises the real branch: no
        // control sequences may reach a redirected stream.
        let spinner = Spinner::start("checking", true);
        assert!(!spinner.is_active());
    }

    #[test]
    fn an_inert_spinner_stops_cleanly_and_repeatedly() {
        let mut spinner = Spinner::inert();
        assert!(!spinner.is_active());
        spinner.finish();
        // Finishing twice must not panic or block, because Drop also finishes.
        spinner.finish();
    }

    #[test]
    fn frame_sets_are_single_width_and_non_empty() {
        for frame in UNICODE_FRAMES {
            assert_eq!(frame.chars().count(), 1, "frame {frame} is not one cell");
        }
        for frame in ASCII_FRAMES {
            assert_eq!(frame.len(), 1);
            assert!(frame.is_ascii());
        }
    }
}
