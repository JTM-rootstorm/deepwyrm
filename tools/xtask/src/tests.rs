use super::*;

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).into()).collect()
}

#[test]
fn available_commands_have_explicit_actions() {
    for (args, expected) in [
        (&["format"][..], Action::Command(Invocation::Format)),
        (&["check"][..], Action::Command(Invocation::Check)),
        (&["abi", "check"][..], Action::Command(Invocation::AbiCheck)),
        (
            &["test", "host", "abi"][..],
            Action::Command(Invocation::HostTests(Some(HostTestFilter::Abi))),
        ),
        (
            &["test", "host", "memory"][..],
            Action::Command(Invocation::HostTests(Some(HostTestFilter::Memory))),
        ),
        (
            &["test", "host", "handles"][..],
            Action::Command(Invocation::HostTests(Some(HostTestFilter::Handles))),
        ),
        (
            &["test", "host", "tasks"][..],
            Action::Command(Invocation::HostTests(Some(HostTestFilter::Tasks))),
        ),
        (
            &["test", "host", "ipc"][..],
            Action::Command(Invocation::HostTests(Some(HostTestFilter::Ipc))),
        ),
    ] {
        assert_eq!(parse(&strings(args)), expected);
    }
}

#[test]
fn handle_host_gate_covers_lifetime_and_authority_boundaries() {
    assert!(HANDLE_HOST_TEST_FILTERS.contains(&"memory::vm::object::tests::"));
    assert_eq!(
        HANDLE_HOST_INTEGRATION_TESTS,
        &[
            "object_registry_ui",
            "memory_authority_ui",
            "physical_ownership_ui"
        ]
    );
}

#[test]
fn task_host_gate_covers_scheduler_resources_and_target_guard_contracts() {
    for filter in [
        "sync::tests::",
        "task::tests::",
        "task::scheduler::tests::",
        "task::execution::tests::",
        "arch::x86_64::syscall::tests::",
        "arch::x86_64::exceptions::tests::",
        "memory::user_range::tests::",
        "memory::usercopy::tests::",
        "syscall::abi_bytes::tests::",
        "syscall::adapters::tests::",
        "syscall::native::tests::",
        "service::tests::e_task_state_query_reuses_inspect_gated_service_lookup",
        "object::finalizer::tests::",
        "object::finalizer::memory_route_tests::",
        "memory::vm::object::tests::production_binding_consumes_creation_before_first_publication",
        "root_region_handle_close_preserves_address_space_until_process_exit",
    ] {
        assert!(TASK_HOST_TEST_FILTERS.contains(&filter));
    }
    assert_eq!(
        TASK_HOST_INTEGRATION_TESTS,
        &[
            "object_registry_ui",
            "memory_authority_ui",
            "task_authority_ui",
            "x86_64_activation_contract",
            "x86_64_entry_contract",
            "x86_64_syscall_contract",
            "x86_64_exception_contract",
            "x86_64_memory_guest_contract",
        ]
    );
}

#[test]
fn ipc_host_gate_covers_bounded_focused_f11_contracts() {
    for filter in [
        "handle::table::tests::",
        "handle::model_tests::",
        "ipc::tests::",
        "wait::tests::",
        "wait::engine::tests::",
        "wait::operation::tests::",
        "time::deadline::tests::",
        "time::pm_timer::tests::",
        "time::timer::tests::",
        "atomic_wait::tests::",
        "task::blocked_operation::tests::",
        "task::scheduler::tests::",
        "task::execution::tests::",
        "object::finalizer::tests::channel_",
        "object::finalizer::tests::armed_timer_",
        "syscall::abi_bytes::tests::f1_",
        "syscall::adapters::tests::event_",
        "syscall::adapters::tests::channel_",
        "syscall::adapters::tests::timer_",
        "syscall::adapters::tests::wait_",
        "syscall::adapters::tests::public_finite_wait_",
        "syscall::adapters::tests::public_timer_wait_",
        "syscall::adapters::tests::public_wait_",
        "syscall::adapters::tests::native_timer_",
        "syscall::adapters::tests::native_wait_",
        "syscall::adapters::tests::native_process_create_",
        "syscall::adapters::tests::process_create_",
    ] {
        assert!(IPC_HOST_TEST_FILTERS.contains(&filter));
    }
    assert_eq!(
        IPC_HOST_INTEGRATION_TESTS,
        &[
            "object_registry_ui",
            "task_authority_ui",
            "x86_64_syscall_contract",
            "f11_ipc_ui",
            "f11_ownership_model",
        ]
    );
    assert!(!IPC_HOST_TEST_FILTERS.contains(&"memory::vm::object::tests::"));
    assert!(!IPC_HOST_TEST_FILTERS.contains(&"arch::x86_64::exceptions::tests::"));
}

#[test]
fn malformed_commands_are_usage_errors() {
    for args in [
        strings(&[]),
        strings(&["run"]),
        strings(&["gdb", "--plan"]),
        strings(&["test", "guest", "bad selector", "--plan", "--request", "x"]),
        strings(&["guest-result"]),
    ] {
        assert!(matches!(parse(&args), Action::UsageError(_)));
    }
}

fn clippy_message(package_id: &str, lint: &str, file: &str, line: u32, column: u32) -> String {
    format!(
        concat!(
            r#"{{"reason":"compiler-message","package_id":"{package_id}","#,
            r#""target":{{"kind":["lib"],"name":"x"}},"message":{{"rendered":"warning: é\n --> {file}:{line}:{column}\n","#,
            r#""$message_type":"diagnostic","children":[{{"children":[],"code":null,"level":"help","message":"h","rendered":null,"spans":[]}}],"#,
            r#""code":{{"code":"{lint}","explanation":null}},"level":"warning","message":"m","#,
            r#""spans":[{{"file_name":"other.rs","is_primary":false,"line_start":1,"column_start":1}},"#,
            r#"{{"byte_end":10,"file_name":"{file}","is_primary":true,"line_start":{line},"column_start":{column},"text":[]}}]}}}}"#
        ),
        package_id = package_id,
        lint = lint,
        file = file,
        line = line,
        column = column,
    )
}

#[test]
fn the_lint_ratchet_counts_each_finding_once_per_package_and_lint() {
    let kernel = "path+file:///w/kernel#deepwyrm-kernel@0.0.0";
    let stream = [
        r#"{"reason":"compiler-artifact","package_id":"x"}"#.to_owned(),
        clippy_message(
            kernel,
            "clippy::wildcard_enum_match_arm",
            "kernel/src/a.rs",
            3,
            9,
        ),
        // The same finding again, as `--all-targets` reports it for the
        // library's test harness.
        clippy_message(
            kernel,
            "clippy::wildcard_enum_match_arm",
            "kernel/src/a.rs",
            3,
            9,
        ),
        clippy_message(
            kernel,
            "clippy::wildcard_enum_match_arm",
            "kernel/src/a.rs",
            4,
            9,
        ),
        clippy_message(
            kernel,
            "clippy::undocumented_unsafe_blocks",
            "kernel/src/a.rs",
            3,
            9,
        ),
        clippy_message(
            "abi-gen 0.0.0 (path+file:///w/tools/abi-gen)",
            "clippy::undocumented_unsafe_blocks",
            "tools/abi-gen/src/main.rs",
            1,
            1,
        ),
        clippy_message(kernel, "clippy::needless_return", "kernel/src/a.rs", 5, 1),
        r#"{"reason":"build-finished","success":true}"#.to_owned(),
    ]
    .join("\n");
    let counts = count_clippy_findings(&stream).unwrap();
    let key = |scope: &str, lint: &str| (scope.to_owned(), lint.to_owned());
    assert_eq!(
        counts,
        BTreeMap::from([
            (key("abi-gen", "clippy::undocumented_unsafe_blocks"), 1),
            (
                key("deepwyrm-kernel", "clippy::undocumented_unsafe_blocks"),
                1
            ),
            (key("deepwyrm-kernel", "clippy::wildcard_enum_match_arm"), 2),
        ])
    );
}

#[test]
fn the_lint_ratchet_refuses_a_stream_that_did_not_finish() {
    // A parser that matched nothing would otherwise read as a clean tree.
    let unfinished = r#"{"reason":"compiler-artifact","package_id":"x"}"#;
    assert!(count_clippy_findings(unfinished).is_err());
    let failed = r#"{"reason":"build-finished","success":false}"#;
    assert!(count_clippy_findings(failed).is_err());
    assert!(count_clippy_findings("{\"reason\":").is_err());
}

#[test]
fn the_unsafe_text_counter_needs_a_safety_comment_in_the_four_lines_before() {
    let source = "\
// SAFETY: documented five lines up, too far.
a();
b();
c();
d();
let x = unsafe { e() };
// SAFETY: documented.
let y = unsafe { f() };
// SAFETY: covers this line's two blocks.
let z = unsafe { g() } + unsafe { h() };
j();
k();
l();
// SAFETY without the colon convention.
let w = unsafe { i() };
";
    assert_eq!(count_unsafe_blocks_without_safety_comment(source), 2);
}

#[test]
fn the_lint_ratchet_counts_test_attributes_only_where_code_opens_them() {
    let source = "\
#[test]
fn a() {}
    #[test]
    fn b() {}
// #[test] in a comment
let text = \"#[test]\";
#[cfg(test)]
#[test_case]
";
    assert_eq!(count_test_attributes(source), 2);
}

#[test]
fn every_target_only_file_exists_and_has_a_zero_test_row() {
    let source = fs::read_to_string(workspace_root().join(LINT_RATCHET_BASELINE)).unwrap();
    let baseline = parse_ratchet_baseline(&source).unwrap();
    for file in TARGET_ONLY_FILES {
        assert!(
            workspace_root().join(file).is_file(),
            "{file} is listed as target-only but does not exist"
        );
        assert_eq!(
            baseline.get(&(file.to_owned(), TEST_TEXT_COUNTER.to_owned())),
            Some(&0),
            "{file} has no zero orphaned-test row"
        );
    }
}

#[test]
fn the_lint_ratchet_fails_rises_and_reports_falls() {
    let key = |scope: &str| (scope.to_owned(), "lint".to_owned());
    let baseline = BTreeMap::from([(key("a"), 5), (key("b"), 5), (key("c"), 5)]);
    let current = BTreeMap::from([(key("a"), 5), (key("b"), 6), (key("d"), 1)]);
    let comparison = compare_ratchet(&baseline, &current);
    assert_eq!(
        comparison.higher,
        BTreeMap::from([(key("b"), (5, 6)), (key("d"), (0, 1))])
    );
    assert_eq!(comparison.lower, BTreeMap::from([(key("c"), (5, 0))]));
}

#[test]
fn the_checked_in_lint_baseline_parses_and_names_both_text_files() {
    let source = fs::read_to_string(workspace_root().join(LINT_RATCHET_BASELINE)).unwrap();
    let baseline = parse_ratchet_baseline(&source).unwrap();
    for file in SAFETY_TEXT_FILES {
        assert!(
            baseline.contains_key(&(file.to_owned(), SAFETY_TEXT_COUNTER.to_owned())),
            "{file} has no text-counter row"
        );
    }
    assert!(parse_ratchet_baseline("a b").is_err());
    assert!(parse_ratchet_baseline("a b 1\na b 2").is_err());
    assert!(parse_ratchet_baseline("a b -1").is_err());
}
