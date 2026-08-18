use std::process::{Command, Output};

fn xtask(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .expect("xtask should launch")
}

#[test]
fn help_distinguishes_available_host_tooling_from_deferred_operations() {
    let output = xtask(&["help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help should be UTF-8");
    for command in [
        "format",
        "check",
        "abi generate",
        "abi check",
        "test host",
        "memory",
        "handles",
        "run --plan",
        "gdb --plan",
        "guest-result",
        "toolchain",
        "verify-build-tools",
    ] {
        assert!(stdout.contains(command), "help omitted `{command}`");
    }
    assert!(stdout.contains("not implemented"));
}

#[test]
fn deferred_operations_fail_nonzero_without_doing_work() {
    let commands: &[&[&str]] = &[
        &["build"],
        &["image"],
        &["inspect-image"],
        &["test", "integration"],
    ];

    for args in commands {
        let output = xtask(args);
        assert_eq!(
            output.status.code(),
            Some(1),
            "unexpected status for {args:?}"
        );
        assert!(
            output.stdout.is_empty(),
            "operation wrote to stdout: {args:?}"
        );
        let stderr = String::from_utf8(output.stderr).expect("error should be UTF-8");
        assert!(
            stderr.contains("planned but not implemented"),
            "operation did not explain its status: {args:?}"
        );
        assert!(
            stderr.contains(
                "No build, image, VM, debugger, guest, or integration operation was performed."
            ),
            "operation did not confirm its inert behavior: {args:?}"
        );
    }
}

#[test]
fn invalid_syntax_is_distinct_from_an_unimplemented_operation() {
    for args in [
        &[][..],
        &["abi"][..],
        &["abi", "invalid"][..],
        &["test"][..],
        &["test", "invalid"][..],
        &["test", "host", "not-a-filter"][..],
        &["unknown"][..],
    ] {
        let output = xtask(args);
        assert_eq!(
            output.status.code(),
            Some(2),
            "unexpected status for {args:?}"
        );
        let stderr = String::from_utf8(output.stderr).expect("error should be UTF-8");
        assert!(stderr.contains("error:"));
        assert!(stderr.contains("Run `cargo xtask help` for usage."));
    }
}

#[test]
fn toolchain_diagnostics_are_host_only_and_do_not_claim_a_pin() {
    let output = xtask(&["toolchain"]);

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("diagnostics should be UTF-8");
    assert!(stdout.contains("host tool availability"));
    assert!(stdout.contains("does not assert toolchain adoption or pinning"));
    for tool in ["clang:", "ld.lld:", "llvm-readelf:", "gdb:"] {
        assert!(stdout.contains(tool), "diagnostics omitted `{tool}`");
    }
}
