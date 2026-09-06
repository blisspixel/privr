use std::io::{ErrorKind, Write};

use clap::Parser;
use privr::{Cli, run};

/// Exit code used when standard output cannot be written.
const EXIT_IO_ERROR: i32 = 2;

fn main() {
    let cli = Cli::parse();
    let exit_code = {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        let stderr = std::io::stderr();
        let mut err = stderr.lock();

        let code = run(cli, &mut out, &mut err);

        // Flush explicitly. `std::process::exit` skips destructors, so buffered
        // output would otherwise be discarded.
        match out.flush() {
            Ok(()) => code,
            // A closed pipe is not a failure. `privr list | head` must exit
            // cleanly rather than reporting an error the caller did not cause.
            Err(error) if error.kind() == ErrorKind::BrokenPipe => code,
            Err(error) => {
                let _ = writeln!(err, "privr: could not write output: {error}");
                EXIT_IO_ERROR
            }
        }
    };

    std::process::exit(exit_code);
}
