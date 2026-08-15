use std::process::{Command, Output};

fn xtask(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(args)
        .output()
        .expect("xtask should launch")
}

#[test]
fn help_succeeds_and_labels_the_surface_as_not_implemented() {
    let output = xtask(&["help"]);

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help should be UTF-8");
    assert!(stdout.contains("command surface only"));
    assert!(stdout.contains("planned but not implemented"));
    for command in ["build", "image", "run", "inspect-image", "gdb", "test host"] {
        assert!(stdout.contains(command), "help omitted `{command}`");
    }
}

#[test]
fn every_operation_fails_nonzero_without_doing_work() {
    let commands: &[&[&str]] = &[
        &["build"],
        &["image"],
        &["run"],
        &["inspect-image"],
        &["gdb"],
        &["test", "host"],
        &["test", "guest", "ipc"],
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
            stderr.contains("No build, image, VM, debugger, or test operation was performed."),
            "operation did not confirm its inert behavior: {args:?}"
        );
    }
}

#[test]
fn invalid_syntax_is_distinct_from_an_unimplemented_operation() {
    for args in [
        &[][..],
        &["test"][..],
        &["test", "invalid"][..],
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
