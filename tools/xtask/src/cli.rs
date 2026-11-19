use super::*;

pub(super) fn parse(args: &[String]) -> Action {
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
        return if args.len() == 2 {
            Action::Help(Some(command.into()))
        } else {
            Action::UsageError(format!("unexpected arguments after `{command} --help`"))
        };
    }
    match command {
        "format" if args.len() == 1 => Action::Command(Invocation::Format),
        "check" if args.len() == 1 => Action::Command(Invocation::Check),
        "clippy" if args.len() == 1 => Action::Command(Invocation::Clippy),
        "doc" if args.len() == 1 => Action::Command(Invocation::Rustdoc),
        "kernel-check" if args.len() == 1 => Action::Command(Invocation::KernelCheck),
        "abi" => parse_abi(&args[1..]),
        "test" => parse_test(&args[1..]),
        "toolchain" if args.len() == 1 => Action::Toolchain,
        "toolchain" => Action::UsageError("`toolchain` accepts no arguments".into()),
        "build" | "image" | "inspect-image" if args.len() == 1 => {
            Action::NotImplemented(command.into())
        }
        _ => Action::UsageError(format!("`{command}` does not accept those arguments")),
    }
}

pub(super) fn parse_abi(args: &[String]) -> Action {
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

pub(super) fn parse_test(args: &[String]) -> Action {
    let Some(tier) = args.first().map(String::as_str) else {
        return Action::UsageError("`test` requires one of: host, integration".into());
    };
    if !TEST_TIERS.contains(&tier) {
        return Action::UsageError(format!(
            "unknown test tier `{tier}`; expected host or integration"
        ));
    }
    match tier {
        "host" => match args {
            [_] => Action::Command(Invocation::HostTests(None)),
            [_, filter] => match filter.as_str() {
                "abi" => Action::Command(Invocation::HostTests(Some(HostTestFilter::Abi))),
                "memory" => {
                    Action::Command(Invocation::HostTests(Some(HostTestFilter::Memory)))
                }
                "handles" => {
                    Action::Command(Invocation::HostTests(Some(HostTestFilter::Handles)))
                }
                "tasks" => {
                    Action::Command(Invocation::HostTests(Some(HostTestFilter::Tasks)))
                }
                "ipc" => Action::Command(Invocation::HostTests(Some(HostTestFilter::Ipc))),
                _ => Action::UsageError(
                    "unknown host-test filter; expected `abi`, `memory`, `handles`, `tasks`, or `ipc`"
                        .into(),
                ),
            },
            _ => Action::UsageError("`test host` accepts at most one filter".into()),
        },
        "integration" if args.len() <= 2 => Action::NotImplemented(display_test_command(tier, args.get(1).map(String::as_str))),
        _ => Action::UsageError("`test integration` accepts at most one filter".into()),
    }
}

pub(super) fn parse_help(args: &[String]) -> Action {
    match args {
        [] => Action::Help(None),
        [command] if COMMANDS.contains(&command.as_str()) => Action::Help(Some(command.clone())),
        [command] => Action::UsageError(format!("unknown help topic `{command}`")),
        _ => Action::UsageError("help accepts at most one command".into()),
    }
}

pub(super) fn display_test_command(tier: &str, filter: Option<&str>) -> String {
    filter.map_or_else(
        || format!("test {tier}"),
        |filter| format!("test {tier} {filter}"),
    )
}

pub(super) fn print_help(mut writer: impl Write, command: Option<&str>) -> io::Result<()> {
    match command {
        None => writer.write_all(HELP.as_bytes()),
        Some("abi") => write!(
            writer,
            "Usage: cargo xtask abi <generate|check>\n\n`generate` updates generator-owned artifacts; `check` rejects ABI drift.\n"
        ),
        Some("test") => write!(
            writer,
            "Usage: cargo xtask test <host|integration> ...\n\nUnfiltered `test host` runs the workspace tests. Host filters are `abi`, `memory`, `handles`, `tasks`, and `ipc`. `test host ipc` runs the bounded IPC, wait, time, handle-transfer, timer, finalizer, and process-creation host suite.\n"
        ),
        Some("toolchain") => write!(
            writer,
            "Usage: cargo xtask toolchain\n\nReports host tool availability.\n"
        ),
        Some(command @ ("format" | "check")) => write!(
            writer,
            "Usage: cargo xtask {command}\n\nStatus: available host tooling.\n"
        ),
        Some("clippy") => write!(
            writer,
            "Usage: cargo xtask clippy\n\nWarnings-denied Clippy over the production kernel on the target lane first, then the host workspace, then the lint ratchet: host Clippy at warn level for clippy::wildcard_enum_match_arm and clippy::undocumented_unsafe_blocks per package, plus `unsafe {{` blocks lacking a `// SAFETY:` comment in the target-only files host Clippy cannot see. Fails if any count exceeds tooling/lint-ratchet.txt; prints any count that fell so the baseline can be tightened.\n"
        ),
        Some("kernel-check") => write!(
            writer,
            "Usage: cargo xtask kernel-check\n\nBuilds the production kernel and a stack analysis copy on the target lane. Checks that production is a static freestanding image, that the analysis copy's code is byte-identical to production, and that the deepest direct-call chain from each kernel entry leaves a quarter of its stack spare. Calls through registers are not bounded here; dev-boot's stack high-water marks cover them.\n"
        ),
        Some("doc") => write!(
            writer,
            "Usage: cargo xtask doc\n\nWarnings-denied rustdoc over the workspace, dependencies excluded.\n"
        ),
        Some(command) => write!(
            writer,
            "Usage: cargo xtask {command}\n\nStatus: planned but not implemented. Invoking this operation exits nonzero.\n"
        ),
    }
}
