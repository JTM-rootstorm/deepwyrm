use std::ffi::OsString;
use std::io::{self, Write};

pub const EXIT_NOT_IMPLEMENTED: u8 = 1;
pub const EXIT_USAGE: u8 = 2;

const COMMANDS: &[&str] = &["build", "image", "run", "inspect-image", "gdb", "test"];
const TEST_TIERS: &[&str] = &["host", "guest", "integration"];
const HELP: &str = r#"Deepwyrm project tasks

Status: command surface only; all operational commands are planned but not implemented.

Usage:
  cargo xtask <command>

Commands:
  build                              Build Deepwyrm [not implemented]
  image                              Construct boot media [not implemented]
  run                                Run the reference VM [not implemented]
  inspect-image                      Inspect boot media [not implemented]
  gdb                                Start a debugger session [not implemented]
  test host [filter ...]             Run host tests [not implemented]
  test guest [filter ...]            Run guest tests [not implemented]
  test integration [filter ...]      Run integration tests [not implemented]
  help [command]                     Show status and usage
"#;

#[derive(Clone, Debug, Eq, PartialEq)]
enum Action {
    Help(Option<String>),
    NotImplemented(String),
    UsageError(String),
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
        Action::NotImplemented(command) => {
            let mut stderr = io::stderr().lock();
            writeln!(
                stderr,
                "error: `cargo xtask {command}` is planned but not implemented"
            )?;
            writeln!(
                stderr,
                "No build, image, VM, debugger, or test operation was performed."
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
        "test" => parse_test(&args[1..]),
        _ if args.len() == 1 => Action::NotImplemented(command.into()),
        _ => Action::UsageError(format!("`{command}` does not accept arguments yet")),
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

    let filter = args[1..].join(" ");
    let command = if filter.is_empty() {
        format!("test {tier}")
    } else {
        format!("test {tier} {filter}")
    };
    Action::NotImplemented(command)
}

fn print_help(mut writer: impl Write, command: Option<&str>) -> io::Result<()> {
    match command {
        None => writer.write_all(HELP.as_bytes()),
        Some("test") => write!(
            writer,
            "Usage: cargo xtask test <host|guest|integration> [filter ...]\n\n\
             Status: planned but not implemented. Invoking this operation exits nonzero.\n"
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
    use super::{Action, parse};

    fn strings(args: &[&str]) -> Vec<String> {
        args.iter().map(|arg| (*arg).into()).collect()
    }

    #[test]
    fn every_top_level_operation_is_explicitly_not_implemented() {
        for command in ["build", "image", "run", "inspect-image", "gdb"] {
            assert_eq!(
                parse(&strings(&[command])),
                Action::NotImplemented(command.into())
            );
        }
    }

    #[test]
    fn every_test_tier_is_explicitly_not_implemented() {
        for tier in ["host", "guest", "integration"] {
            assert_eq!(
                parse(&strings(&["test", tier, "example-filter"])),
                Action::NotImplemented(format!("test {tier} example-filter"))
            );
        }
    }

    #[test]
    fn help_is_available_for_each_command() {
        for command in ["build", "image", "run", "inspect-image", "gdb", "test"] {
            assert_eq!(
                parse(&strings(&["help", command])),
                Action::Help(Some(command.into()))
            );
            assert_eq!(
                parse(&strings(&[command, "--help"])),
                Action::Help(Some(command.into()))
            );
        }
    }

    #[test]
    fn malformed_commands_are_usage_errors() {
        for args in [
            strings(&[]),
            strings(&["unknown"]),
            strings(&["test"]),
            strings(&["test", "unknown"]),
            strings(&["build", "unexpected"]),
        ] {
            assert!(matches!(parse(&args), Action::UsageError(_)));
        }
    }
}
