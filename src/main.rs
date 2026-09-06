use clap::Parser;
use privr::{Cli, run};

fn main() {
    let cli = Cli::parse();
    let exit_code = run(cli, &mut std::io::stdout(), &mut std::io::stderr());
    std::process::exit(exit_code);
}
