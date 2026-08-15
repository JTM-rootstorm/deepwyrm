use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const EXIT_NOT_IMPLEMENTED: u8 = 1;
pub const EXIT_USAGE: u8 = 2;

const COMMANDS: &[&str] = &[
    "format",
    "check",
    "abi",
    "build",
    "image",
    "run",
    "inspect-image",
    "gdb",
    "test",
    "toolchain",
];
const TEST_TIERS: &[&str] = &["host", "guest", "integration"];
const HELP: &str = r#"Deepwyrm project tasks

Status: DW0-A host tooling is available. VM, image, debugger, guest, and
integration operations remain planned and are not implemented.

Usage:
  cargo xtask <command>

Commands:
  format                             Verify Rust formatting
  check                              Run the workspace check
  abi generate                       Generate ABI-owned artifacts
  abi check                          Verify generated ABI artifacts have no drift
  test host [filter]                 Run focused host tests
  toolchain                          Report host tool availability
  build                              Build Deepwyrm [not implemented]
  image                              Construct boot media [not implemented]
  run                                Run the reference VM [not implemented]
  inspect-image                      Inspect boot media [not implemented]
  gdb                                Start a debugger session [not implemented]
  test guest [filter]                Run guest tests [not implemented]
  test integration [filter]          Run integration tests [not implemented]
  help [command]                     Show status and usage
"#;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Action {
    Help(Option<String>),
    Command(Invocation),
    Toolchain,
    NotImplemented(String),
    UsageError(String),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Invocation {
    Format,
    Check,
    AbiGenerate,
    AbiCheck,
    HostTests(Option<String>),
}

pub fn run<I, S>(args: I) -> io::Result<u8>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let args = args
        .into_iter()
        .map(Into::into)
        .map(|arg| arg.into_string())
        .collect::<Result<Vec<_>, _>>();

    match args {
        Ok(args) => dispatch(parse(&args)),
        Err(_) => {
            let mut stderr = io::stderr().lock();
            writeln!(stderr, "error: arguments must be valid UTF-8")?;
            writeln!(stderr, "Run `cargo xtask help` for usage.")?;
            Ok(EXIT_USAGE)
        }
    }
}

fn dispatch(action: Action) -> io::Result<u8> {
    match action {
        Action::Help(command) => {
            let mut stdout = io::stdout().lock();
            print_help(&mut stdout, command.as_deref())?;
            Ok(0)
        }
        Action::Command(invocation) => run_invocation(invocation),
        Action::Toolchain => print_toolchain_diagnostics(),
        Action::NotImplemented(command) => {
            let mut stderr = io::stderr().lock();
            writeln!(
                stderr,
                "error: `cargo xtask {command}` is planned but not implemented"
            )?;
            writeln!(
                stderr,
                "No build, image, VM, debugger, guest, or integration operation was performed."
            )?;
            Ok(EXIT_NOT_IMPLEMENTED)
        }
        Action::UsageError(message) => {
            let mut stderr = io::stderr().lock();
            writeln!(stderr, "error: {message}")?;
            writeln!(stderr, "Run `cargo xtask help` for usage.")?;
            Ok(EXIT_USAGE)
        }
    }
}

fn run_invocation(invocation: Invocation) -> io::Result<u8> {
    let mut command = Command::new("cargo");
    command.current_dir(workspace_root());

    match invocation {
        Invocation::Format => {
            command.args(["fmt", "--all", "--", "--check"]);
        }
        Invocation::Check => {
            command.args(["check", "--locked", "--workspace", "--all-targets"]);
        }
        Invocation::AbiGenerate => {
            command.args(["run", "--locked", "--package", "abi-gen", "--", "generate"]);
        }
        Invocation::AbiCheck => {
            command.args(["run", "--locked", "--package", "abi-gen", "--", "check"]);
        }
        Invocation::HostTests(filter) => {
            command.args(["test", "--locked"]);
            if filter.as_deref() == Some("abi") {
                command.args(["--package", "abi-gen", "--package", "deepwyrm-abi"]);
            } else {
                command.args(["--workspace", "--all-targets"]);
                if let Some(filter) = filter {
                    command.args(["--", &filter]);
                }
            }
        }
    }

    let status = command.status()?;
    Ok(status.code().unwrap_or(EXIT_NOT_IMPLEMENTED as i32) as u8)
}

fn print_toolchain_diagnostics() -> io::Result<u8> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "Deepwyrm host tool availability")?;
    writeln!(
        stdout,
        "This report does not assert toolchain adoption or pinning."
    )?;

    for (name, program) in [
        ("cargo", "cargo"),
        ("rustc", "rustc"),
        ("clang", "clang"),
        ("clang++", "clang++"),
        ("ld.lld", "ld.lld"),
        ("llvm-ar", "llvm-ar"),
        ("llvm-readelf", "llvm-readelf"),
        ("llvm-objdump", "llvm-objdump"),
        ("llvm-objcopy", "llvm-objcopy"),
        ("llvm-symbolizer", "llvm-symbolizer"),
        ("llvm-nm", "llvm-nm"),
        ("gdb", "gdb"),
    ] {
        write!(stdout, "{name}: ")?;
        match Command::new(program).arg("--version").output() {
            Ok(output) if output.status.success() => {
                let version_output = String::from_utf8_lossy(&output.stdout);
                let version = version_output.lines().next().unwrap_or("available");
                writeln!(stdout, "{version}")?;
            }
            Ok(output) => {
                writeln!(stdout, "unavailable (exit {})", output.status)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                writeln!(stdout, "not found")?;
            }
            Err(error) => {
                writeln!(stdout, "unavailable ({error})")?;
            }
        }
    }

    Ok(0)
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("xtask manifest is nested under tools/xtask")
        .to_path_buf()
}

fn parse(args: &[String]) -> Action {
    let Some(command) = args.first().map(String::as_str) else {
        return Action::UsageError("a command is required".into());
    };

    if matches!(command, "help" | "-h" | "--help") {
        return parse_help(&args[1..]);
    }

    if !COMMANDS.contains(&command) {
        return Action::UsageError(format!("unknown command `{command}`"));
    }

    if args
        .get(1)
        .is_some_and(|arg| matches!(arg.as_str(), "-h" | "--help"))
    {
        if args.len() == 2 {
            return Action::Help(Some(command.into()));
        }
        return Action::UsageError(format!("unexpected arguments after `{command} --help`"));
    }

    match command {
        "format" if args.len() == 1 => Action::Command(Invocation::Format),
        "check" if args.len() == 1 => Action::Command(Invocation::Check),
        "abi" => parse_abi(&args[1..]),
        "test" => parse_test(&args[1..]),
        "toolchain" if args.len() == 1 => Action::Toolchain,
        "build" | "image" | "run" | "inspect-image" | "gdb" if args.len() == 1 => {
            Action::NotImplemented(command.into())
        }
        _ => Action::UsageError(format!("`{command}` does not accept those arguments")),
    }
}

fn parse_abi(args: &[String]) -> Action {
    match args {
        [subcommand] if subcommand == "generate" => Action::Command(Invocation::AbiGenerate),
        [subcommand] if subcommand == "check" => Action::Command(Invocation::AbiCheck),
        [] => Action::UsageError("`abi` requires `generate` or `check`".into()),
        [subcommand] => Action::UsageError(format!(
            "unknown ABI operation `{subcommand}`; expected `generate` or `check`"
        )),
        _ => Action::UsageError("`abi` accepts exactly one operation".into()),
    }
}

fn parse_help(args: &[String]) -> Action {
    match args {
        [] => Action::Help(None),
        [command] if COMMANDS.contains(&command.as_str()) => Action::Help(Some(command.clone())),
        [command] => Action::UsageError(format!("unknown help topic `{command}`")),
        _ => Action::UsageError("help accepts at most one command".into()),
    }
}

fn parse_test(args: &[String]) -> Action {
    let Some(tier) = args.first().map(String::as_str) else {
        return Action::UsageError("`test` requires one of: host, guest, integration".into());
    };

    if !TEST_TIERS.contains(&tier) {
        return Action::UsageError(format!(
            "unknown test tier `{tier}`; expected host, guest, or integration"
        ));
    }

    if args.len() > 2 {
        return Action::UsageError("`test` accepts at most one filter".into());
    }
    let filter = args.get(1).cloned();
    match tier {
        "host" => Action::Command(Invocation::HostTests(filter)),
        "guest" | "integration" => {
            Action::NotImplemented(display_test_command(tier, filter.as_deref()))
        }
        _ => unreachable!("test tier membership was checked above"),
    }
}

fn display_test_command(tier: &str, filter: Option<&str>) -> String {
    filter.map_or_else(
        || format!("test {tier}"),
        |filter| format!("test {tier} {filter}"),
    )
}

fn print_help(mut writer: impl Write, command: Option<&str>) -> io::Result<()> {
    match command {
        None => writer.write_all(HELP.as_bytes()),
        Some("abi") => write!(
            writer,
            "Usage: cargo xtask abi <generate|check>\n\n\
             `generate` updates generator-owned artifacts; `check` rejects ABI drift.\n"
        ),
        Some("test") => write!(
            writer,
            "Usage: cargo xtask test <host|guest|integration> [filter]\n\n\
             `test host` is available in DW0-A. Guest and integration tests remain planned.\n"
        ),
        Some(command @ ("format" | "check" | "toolchain")) => write!(
            writer,
            "Usage: cargo xtask {command}\n\nStatus: available DW0-A host tooling.\n"
        ),
        Some(command) => write!(
            writer,
            "Usage: cargo xtask {command}\n\n\
             Status: planned but not implemented. Invoking this operation exits nonzero.\n"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{Action, COMMANDS, Invocation, parse};

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).into()).collect()
    }

    #[test]
    fn dw0a_host_commands_have_explicit_invocations() {
        for (args, invocation) in [
            (&["format"][..], Invocation::Format),
            (&["check"][..], Invocation::Check),
            (&["abi", "generate"][..], Invocation::AbiGenerate),
            (&["abi", "check"][..], Invocation::AbiCheck),
            (&["test", "host"][..], Invocation::HostTests(None)),
            (
                &["test", "host", "abi"][..],
                Invocation::HostTests(Some("abi".into())),
            ),
        ] {
            assert_eq!(parse(&strings(args)), Action::Command(invocation));
        }
    }

    #[test]
    fn deferred_operations_remain_explicitly_not_implemented() {
        for command in ["build", "image", "run", "inspect-image", "gdb"] {
            assert_eq!(
                parse(&strings(&[command])),
                Action::NotImplemented(command.into())
            );
        }
        for tier in ["guest", "integration"] {
            assert_eq!(
                parse(&strings(&["test", tier, "example-filter"])),
                Action::NotImplemented(format!("test {tier} example-filter"))
            );
        }
    }

    #[test]
    fn help_is_available_for_each_command() {
        for command in COMMANDS {
            assert_eq!(
                parse(&strings(&["help", command])),
                Action::Help(Some((*command).into()))
            );
            assert_eq!(
                parse(&strings(&[command, "--help"])),
                Action::Help(Some((*command).into()))
            );
        }
    }

    #[test]
    fn malformed_commands_are_usage_errors() {
        for args in [
            strings(&[]),
            strings(&["unknown"]),
            strings(&["abi"]),
            strings(&["abi", "unknown"]),
            strings(&["test"]),
            strings(&["test", "unknown"]),
            strings(&["test", "host", "one", "two"]),
            strings(&["format", "unexpected"]),
        ] {
            assert!(matches!(parse(&args), Action::UsageError(_)));
        }
    }
}
