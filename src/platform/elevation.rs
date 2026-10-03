//! Privilege elevation utilities.
//!
//! Provides native in-place elevation for applying machine-scope changes without
//! requiring the user to switch terminals or execute manual commands.
//! On Windows, triggers Shell.Application ShellExecute with verb "runas" (UAC).
//! On Unix, triggers sudo.

use std::path::Path;

/// Result of an elevated execution attempt.
#[derive(Debug, PartialEq, Eq)]
pub enum ElevationResult {
    /// Elevation succeeded and child completed with the given exit code.
    Success { exit_code: i32, output: String },
    /// The user explicitly declined or cancelled the elevation prompt.
    Cancelled,
    /// Elevation failed to launch or is unsupported.
    Failed(String),
}

/// Escapes a single argument for the Windows command line specification.
pub fn escape_arg(arg: &str) -> String {
    if !arg.contains(' ') && !arg.contains('\t') && !arg.contains('"') && !arg.is_empty() {
        return arg.to_string();
    }
    let mut escaped = String::from("\"");
    for c in arg.chars() {
        if c == '"' {
            escaped.push('\\');
        }
        escaped.push(c);
    }
    escaped.push('"');
    escaped
}

/// Builds a single escaped command line string from a slice of argument strings.
pub fn build_command_line(args: &[&str]) -> String {
    args.iter()
        .map(|a| escape_arg(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A writer that writes to both an underlying writer and an optional secondary file.
pub struct DualWriter<'a> {
    primary: &'a mut dyn std::io::Write,
    secondary: Option<std::fs::File>,
}

impl<'a> DualWriter<'a> {
    pub fn new(primary: &'a mut dyn std::io::Write, path: Option<&Path>) -> Self {
        let secondary = path.and_then(|p| {
            if let Some(parent) = p.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(p)
                .ok()
        });
        Self { primary, secondary }
    }
}

impl<'a> std::io::Write for DualWriter<'a> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.primary.write(buf)?;
        if let Some(ref mut sec) = self.secondary {
            let _ = sec.write_all(&buf[..n]);
        }
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _ = self.primary.flush();
        if let Some(ref mut sec) = self.secondary {
            let _ = sec.flush();
        }
        Ok(())
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::*;

    pub fn run_elevated_windows(args: &[&str], temp_file: Option<&Path>) -> ElevationResult {
        let current_exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                return ElevationResult::Failed(format!(
                    "failed to locate current executable: {e}"
                ));
            }
        };

        let exe_str = current_exe.to_string_lossy().into_owned();
        let mut full_args = args.to_vec();
        let temp_str;
        let done_path = temp_file.map(|p| p.with_extension("done"));

        if let Some(path) = temp_file {
            temp_str = path.to_string_lossy().into_owned();
            full_args.push("--elevated-output");
            full_args.push(&temp_str);
        }

        let cmdline = build_command_line(&full_args);

        // Escape for PowerShell single-quote string literal
        let ps_exe = exe_str.replace('\'', "''");
        let ps_args = cmdline.replace('\'', "''");

        let script = format!(
            "$exe = '{ps_exe}'; \
             $params = '{ps_args}'; \
             try {{ \
                 $app = New-Object -ComObject Shell.Application; \
                 $app.ShellExecute($exe, $params, '', 'runas', 0); \
             }} catch {{ \
                 exit 1223; \
             }}"
        );

        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status();

        match status {
            Ok(s) => {
                if s.code() == Some(1223) {
                    return ElevationResult::Cancelled;
                }
            }
            Err(e) => {
                return ElevationResult::Failed(format!("failed to launch elevation host: {e}"));
            }
        }

        if let (Some(temp_path), Some(done)) = (temp_file, done_path) {
            let start = std::time::Instant::now();
            let timeout = std::time::Duration::from_secs(300);

            while !done.exists() {
                if start.elapsed() > timeout {
                    let _ = std::fs::remove_file(&done);
                    return ElevationResult::Failed("elevation execution timed out".into());
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }

            let code_str = std::fs::read_to_string(&done).unwrap_or_else(|_| "0".into());
            let exit_code = code_str.trim().parse::<i32>().unwrap_or(0);
            let output = std::fs::read_to_string(temp_path).unwrap_or_default();

            let _ = std::fs::remove_file(&done);

            ElevationResult::Success { exit_code, output }
        } else {
            ElevationResult::Success {
                exit_code: 0,
                output: String::new(),
            }
        }
    }
}

#[cfg(unix)]
mod unix_impl {
    use super::*;

    pub fn run_elevated_unix(args: &[&str], temp_file: Option<&Path>) -> ElevationResult {
        let current_exe = match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                return ElevationResult::Failed(format!(
                    "failed to locate current executable: {e}"
                ));
            }
        };

        let mut full_args = args.to_vec();
        let temp_str;
        if let Some(path) = temp_file {
            temp_str = path.to_string_lossy().into_owned();
            full_args.push("--elevated-output");
            full_args.push(&temp_str);
        }

        match std::process::Command::new("sudo")
            .arg(current_exe)
            .args(&full_args)
            .status()
        {
            Ok(status) => {
                let code = status.code().unwrap_or(1);
                let output = if let Some(path) = temp_file {
                    std::fs::read_to_string(path).unwrap_or_default()
                } else {
                    String::new()
                };
                ElevationResult::Success {
                    exit_code: code,
                    output,
                }
            }
            Err(e) => ElevationResult::Failed(format!("sudo execution failed: {e}")),
        }
    }
}

/// Request elevation for the current executable with the given arguments.
pub fn run_elevated(args: &[&str], temp_file: Option<&Path>) -> ElevationResult {
    #[cfg(windows)]
    {
        windows_impl::run_elevated_windows(args, temp_file)
    }
    #[cfg(unix)]
    {
        unix_impl::run_elevated_unix(args, temp_file)
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (args, temp_file);
        ElevationResult::Failed("elevation is not supported on this platform".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn escape_arg_handles_simple_and_complex_strings() {
        assert_eq!(escape_arg("simple"), "simple");
        assert_eq!(escape_arg("with space"), "\"with space\"");
        assert_eq!(escape_arg("with\"quote"), "\"with\\\"quote\"");
        assert_eq!(escape_arg(""), "\"\"");
    }

    #[test]
    fn build_command_line_joins_correctly() {
        let args = ["apply", "--yes", "--workload", "general", "path with space"];
        let cmd = build_command_line(&args);
        assert_eq!(cmd, "apply --yes --workload general \"path with space\"");
    }

    #[test]
    fn dual_writer_writes_to_both_targets() {
        let dir = std::env::temp_dir().join(format!("privr-test-dual-{}", std::process::id()));
        let file_path = dir.join("output.txt");
        let mut primary_buf = Vec::new();

        {
            let mut writer = DualWriter::new(&mut primary_buf, Some(&file_path));
            writer.write_all(b"hello world\n").expect("write");
            writer.flush().expect("flush");
        }

        assert_eq!(primary_buf, b"hello world\n");
        let file_content = std::fs::read_to_string(&file_path).expect("read file");
        assert_eq!(file_content, "hello world\n");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn dual_writer_with_no_secondary_writes_to_primary() {
        let mut primary_buf = Vec::new();
        {
            let mut writer = DualWriter::new(&mut primary_buf, None);
            writer.write_all(b"direct write").expect("write");
            writer.flush().expect("flush");
        }
        assert_eq!(primary_buf, b"direct write");
    }
}
