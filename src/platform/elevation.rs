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

    pub(crate) fn base64_encode(data: &[u8]) -> String {
        const CHARSET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
        for chunk in data.chunks(3) {
            let b0 = chunk[0];
            let b1 = if chunk.len() > 1 { chunk[1] } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] } else { 0 };
            out.push(CHARSET[(b0 >> 2) as usize] as char);
            out.push(CHARSET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
            if chunk.len() > 1 {
                out.push(CHARSET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
            } else {
                out.push('=');
            }
            if chunk.len() > 2 {
                out.push(CHARSET[(b2 & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
        out
    }

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

        if let Some(path) = temp_file {
            temp_str = path.to_string_lossy().into_owned();
            full_args.push("--elevated-output");
            full_args.push(&temp_str);
        }

        let cmdline = build_command_line(&full_args);

        // Escape single quotes for PowerShell single-quoted string literals
        let ps_exe = exe_str.replace('\'', "''");
        let ps_args = cmdline.replace('\'', "''");

        let script = format!(
            "$ErrorActionPreference = 'Stop'; \
             try {{ \
                 $p = Start-Process -FilePath '{ps_exe}' -ArgumentList '{ps_args}' -Verb RunAs -Wait -PassThru; \
                 if ($null -ne $p) {{ exit $p.ExitCode; }} else {{ exit 0; }} \
             }} catch {{ \
                 exit 1223; \
             }}"
        );

        let utf16_bytes: Vec<u8> = script
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let encoded = base64_encode(&utf16_bytes);

        let status = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
            .status();

        match status {
            Ok(s) => {
                let code = s.code().unwrap_or(1);
                if code == 1223 {
                    return ElevationResult::Cancelled;
                }
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
            Err(e) => ElevationResult::Failed(format!("failed to launch elevation host: {e}")),
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

    #[test]
    #[cfg(windows)]
    fn base64_encode_round_trips() {
        use windows_impl::base64_encode;
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    #[cfg(windows)]
    fn test_powershell_encoded_script_execution() {
        use windows_impl::base64_encode;
        let script = "Write-Output 'OK'; exit 0;";
        let utf16_bytes: Vec<u8> = script
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let encoded = base64_encode(&utf16_bytes);
        let out = std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-EncodedCommand", &encoded])
            .output()
            .expect("exec");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("OK"));
    }
}
