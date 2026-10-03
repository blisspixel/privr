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
const MIN_DISPLAY_DURATION: Duration = Duration::from_millis(200);

/// A running spinner. Stops and clears when dropped.
pub struct Spinner {
    running: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    start_time: Option<std::time::Instant>,
    cleanup: Option<Box<dyn FnOnce() + Send>>,
}

impl Spinner {
    /// Start a spinner, or return an inert one when output is not a terminal.
    pub fn start(message: &str, unicode: bool) -> Self {
        if !std::io::stderr().is_terminal() {
            return Self::inert();
        }

        Self::start_with_writer(
            message,
            unicode,
            true,
            || Box::new(anstream::stderr()) as Box<dyn Write + Send>,
            Box::new(|| {
                let mut err = anstream::stderr();
                let _ = write!(err, "\r\x1b[2K");
                let _ = err.flush();
            }),
        )
    }

    /// Start a spinner with an explicit terminal availability flag and custom writer.
    pub fn start_with_writer<F>(
        message: &str,
        unicode: bool,
        is_terminal: bool,
        writer_factory: F,
        cleanup: Box<dyn FnOnce() + Send>,
    ) -> Self
    where
        F: Fn() -> Box<dyn Write + Send> + Send + 'static,
    {
        if !is_terminal {
            return Self::inert();
        }

        let frames: &'static [&'static str] = if unicode {
            &UNICODE_FRAMES
        } else {
            &ASCII_FRAMES
        };

        // Draw initial frame immediately for zero-latency feedback.
        {
            let mut err = writer_factory();
            let _ = write!(err, "\r\x1b[2K{} {message}", frames[0]);
            let _ = err.flush();
        }

        let start_time = std::time::Instant::now();
        let running = Arc::new(AtomicBool::new(true));
        let flag = Arc::clone(&running);
        let msg = message.to_owned();

        let handle = thread::spawn(move || {
            let mut index = 1;
            while flag.load(Ordering::Relaxed) {
                thread::sleep(INTERVAL);
                if !flag.load(Ordering::Relaxed) {
                    break;
                }
                let mut err = writer_factory();
                // Carriage return and clear-to-end, so each frame overwrites
                // the previous one rather than accumulating lines.
                let _ = write!(err, "\r\x1b[2K{} {msg}", frames[index % frames.len()]);
                let _ = err.flush();
                index = index.wrapping_add(1);
            }
        });

        Self {
            running,
            handle: Some(handle),
            start_time: Some(start_time),
            cleanup: Some(cleanup),
        }
    }

    /// A spinner that draws nothing, for non-interactive use.
    pub fn inert() -> Self {
        Self {
            running: Arc::new(AtomicBool::new(false)),
            handle: None,
            start_time: None,
            cleanup: None,
        }
    }

    /// Whether this spinner is actually drawing.
    pub fn is_active(&self) -> bool {
        self.handle.is_some()
    }

    /// Stop and erase the line.
    pub fn finish(&mut self) {
        if self.running.swap(false, Ordering::Relaxed) {
            if let Some(start_time) = self.start_time.take() {
                let elapsed = start_time.elapsed();
                if elapsed < MIN_DISPLAY_DURATION {
                    thread::sleep(MIN_DISPLAY_DURATION - elapsed);
                }
            }
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
            if let Some(cleanup) = self.cleanup.take() {
                cleanup();
            }
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
    fn an_active_spinner_runs_and_finishes_cleanly() {
        let buffer = Arc::new(std::sync::Mutex::new(Vec::new()));
        let b1 = Arc::clone(&buffer);
        let b2 = Arc::clone(&buffer);

        struct BufWriter(Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for BufWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let mut spinner = Spinner::start_with_writer(
            "scanning controls",
            true,
            true,
            move || Box::new(BufWriter(Arc::clone(&b1))),
            Box::new(move || {
                let mut w = BufWriter(b2);
                let _ = write!(w, "\r\x1b[2K");
            }),
        );
        assert!(spinner.is_active());
        spinner.finish();
        assert!(!spinner.is_active());
        // Second finish call must be idempotent.
        spinner.finish();

        let out = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        assert!(out.contains("scanning controls"));
        assert!(out.contains("\x1b[2K"));
    }

    #[test]
    fn an_active_ascii_spinner_cleans_up_on_drop() {
        let buffer = Arc::new(std::sync::Mutex::new(Vec::new()));
        let b1 = Arc::clone(&buffer);
        let b2 = Arc::clone(&buffer);

        struct BufWriter(Arc<std::sync::Mutex<Vec<u8>>>);
        impl Write for BufWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let spinner = Spinner::start_with_writer(
            "ascii scanning",
            false,
            true,
            move || Box::new(BufWriter(Arc::clone(&b1))),
            Box::new(move || {
                let mut w = BufWriter(b2);
                let _ = write!(w, "\r\x1b[2K");
            }),
        );
        assert!(spinner.is_active());
        drop(spinner);
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
