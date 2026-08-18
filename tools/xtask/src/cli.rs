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
        "abi" => parse_abi(&args[1..]),
        "run" => parse_harness_command(HarnessKind::Run, &args[1..]),
        "gdb" => parse_harness_command(HarnessKind::Gdb, &args[1..]),
        "test" => parse_test(&args[1..]),
        "guest-result" => parse_guest_result(&args[1..]),
        "toolchain" if args.len() == 1 => Action::Toolchain,
        "toolchain" => parse_toolchain(&args[1..]),
        "build" | "image" | "inspect-image" if args.len() == 1 => {
            Action::NotImplemented(command.into())
        }
        _ => Action::UsageError(format!("`{command}` does not accept those arguments")),
    }
}

pub(super) fn parse_toolchain(args: &[String]) -> Action {
    match args {
        [subcommand, root_flag, root, config_flag, clang_config]
            if subcommand == "verify-build-tools"
                && root_flag == "--root"
                && config_flag == "--clang-config" =>
        {
            Action::VerifyBuildTools {
                root: root.into(),
                clang_config: clang_config.into(),
            }
        }
        _ => Action::UsageError(
            "`toolchain verify-build-tools` requires `--root <path> --clang-config <path>`".into(),
        ),
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

pub(super) fn parse_harness_command(kind: HarnessKind, args: &[String]) -> Action {
    match args {
        [plan, request_flag, request_path] if plan == "--plan" && request_flag == "--request" => {
            Action::Command(Invocation::HarnessPlan(kind, request_path.into(), None))
        }
        _ => Action::UsageError(format!(
            "`{}` requires `--plan --request <path>`; execution is unavailable",
            kind.request_kind()
        )),
    }
}

pub(super) fn parse_test(args: &[String]) -> Action {
    let Some(tier) = args.first().map(String::as_str) else {
        return Action::UsageError("`test` requires one of: host, guest, integration".into());
    };
    if !TEST_TIERS.contains(&tier) {
        return Action::UsageError(format!(
            "unknown test tier `{tier}`; expected host, guest, or integration"
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
                _ => Action::UsageError(
                    "unknown host-test filter; expected `abi`, `memory`, `handles`, or `tasks`".into(),
                ),
            },
            _ => Action::UsageError("`test host` accepts at most one filter".into()),
        },
        "guest" => match args {
            [_, selector, plan, request_flag, request_path] if plan == "--plan" && request_flag == "--request" => {
                if let Err(error) = validate_selector(selector) { return Action::UsageError(error); }
                Action::Command(Invocation::HarnessPlan(HarnessKind::GuestTest, request_path.into(), Some(selector.into())))
            }
            _ => Action::UsageError("`test guest` requires `<selector> --plan --request <path>`; execution is unavailable".into()),
        },
        "integration" if args.len() <= 2 => Action::NotImplemented(display_test_command(tier, args.get(1).map(String::as_str))),
        _ => Action::UsageError("`test integration` accepts at most one filter".into()),
    }
}

pub(super) fn parse_guest_result(args: &[String]) -> Action {
    match args {
        [
            serial_log,
            request_flag,
            request_path,
            exit_flag,
            exit_status,
        ] if request_flag == "--request" && exit_flag == "--exit-status" => match exit_status
            .parse()
        {
            Ok(exit_status) => Action::GuestResult {
                serial_log: serial_log.into(),
                request_path: request_path.into(),
                exit_status,
            },
            Err(_) => Action::UsageError("`guest-result --exit-status` must be an integer".into()),
        },
        _ => Action::UsageError(
            "`guest-result` requires `<serial-log> --request <path> --exit-status <code>`".into(),
        ),
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
            "Usage: cargo xtask test <host|guest|integration> ...\n\nHost filters are `abi`, `memory`, and `handles`. `test guest` emits a plan only; guest execution remains coordinator-owned.\n"
        ),
        Some(command @ ("run" | "gdb")) => write!(
            writer,
            "Usage: cargo xtask {command} --plan --request <path>\n\nThis emits commands and evidence contracts; it never launches QEMU.\n"
        ),
        Some("guest-result") => write!(
            writer,
            "Usage: cargo xtask guest-result <serial-log> --request <path> --exit-status <code>\n\nClassifies one fixed-width DWTEST1 terminal record against the observed QEMU exit status. It does not prove capture freshness.\n"
        ),
        Some("toolchain") => write!(
            writer,
            "Usage: cargo xtask toolchain [verify-build-tools --root <path> --clang-config <path>]\n\nThe verifier performs only identity checks; it never builds or executes Clang.\n"
        ),
        Some(command @ ("format" | "check")) => write!(
            writer,
            "Usage: cargo xtask {command}\n\nStatus: available host tooling.\n"
        ),
        Some(command) => write!(
            writer,
            "Usage: cargo xtask {command}\n\nStatus: planned but not implemented. Invoking this operation exits nonzero.\n"
        ),
    }
}
