use std::process::ExitCode;

fn main() -> ExitCode {
    match xtask::run(std::env::args_os().skip(1)) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("error: failed to write xtask output: {error}");
            ExitCode::FAILURE
        }
    }
}
