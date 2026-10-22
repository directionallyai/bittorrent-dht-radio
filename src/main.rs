use clap::Parser;

fn main() {
    let cli = radio::cli::Cli::parse();
    let code = match radio::cli::dispatch(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            e.code
        }
    };
    std::process::exit(code);
}
