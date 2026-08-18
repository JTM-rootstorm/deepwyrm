use std::fs;
use std::path::PathBuf;

fn source(name: &str) -> String {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(manifest.join(name)).unwrap_or_else(|error| panic!("read {name}: {error}"))
}

fn activation_test_support() -> String {
    source("src/arch/x86_64/mm/activation/test_support.rs")
}

#[test]
fn c3_memory_dispatch_occurs_only_after_the_deep_root_is_active() {
    let kernel = source("src/lib.rs");
    let activation = kernel
        .find("arch::x86_64::mm::activate_bootstrap_deep_paging(")
        .expect("C2 activation call");
    let dispatch = kernel
        .find("test_support::run_memory_guest_test(active_paging)")
        .expect("C3 memory guest dispatch");
    assert!(
        activation < dispatch,
        "memory tests must consume the active C2 session"
    );
    assert!(
        kernel[..activation].contains("test if test.is_memory_foundation() => {}"),
        "memory selectors must pass through the early terminal-test dispatch"
    );
    assert_eq!(
        kernel
            .match_indices("run_memory_guest_test(active_paging)")
            .count(),
        1,
        "the live memory guest dispatch must have one production call site"
    );
}

#[test]
fn c3_live_root_rechecks_exact_kernel_guards_before_selector_work() {
    let activation = activation_test_support();
    let guard_walk = activation
        .split_once("fn guard_leaf_is_exact_zero(&mut self")
        .expect("exact active guard walk")
        .1
        .split_once("fn validate_live_kernel_guard_layout")
        .expect("exact guard walk terminator")
        .0;
    assert!(guard_walk.contains("!= PRESENT | WRITABLE"));
    assert!(guard_walk.contains("validate_table_child(current, child)"));
    assert!(guard_walk.contains("Ok(entry == 0)"));
    let validator = activation
        .split_once("fn validate_live_kernel_guard_layout(&mut self)")
        .expect("post-C2 kernel guard validator")
        .1
        .split_once("fn allocate_zeroed")
        .expect("kernel guard validator terminator")
        .0;
    assert!(validator.contains("for stack in ist.stacks()"));
    assert!(validator.contains("linked_thread_kernel_stack_layout()"));
    assert!(validator.contains("for stack in thread_stacks"));
    assert!(validator.contains("self.guard_leaf_is_exact_zero(stack.guard_page)?"));
    assert!(validator.contains("while page < stack.top"));
    assert!(validator.contains("E3_THREAD_STACK_COUNT"));
    assert!(validator.contains("E3_THREAD_STACK_SIZE"));
    assert!(validator.contains("KernelImageSegment::WritableData"));
    assert!(validator.contains("PRESENT | WRITABLE | NO_EXECUTE"));

    let runner = activation
        .split_once("pub(crate) fn run_memory_foundation_test(")
        .expect("consuming live-root runner")
        .1;
    let guard_check = runner
        .find("authority.validate_live_kernel_guard_layout()")
        .expect("post-C2 live guard check");
    let selector_dispatch = runner.find("match test").expect("selector dispatch");
    assert!(guard_check < selector_dispatch);
}

#[test]
fn c3_test_authority_is_target_only_linear_and_nonescaping() {
    let activation = activation_test_support();
    let activation_facade = source("src/arch/x86_64/mm/activation.rs");
    let module = source("src/test_support/mod.rs");
    let runner = source("src/test_support/memory.rs");

    assert!(activation_facade.contains("#[path = \"activation/test_support.rs\"]"));
    assert!(activation_facade.contains("mod test_support;"));
    assert!(!activation_facade.contains("struct ActiveRootTestAuthority<"));
    assert!(module.contains("mod memory;"));
    assert!(module.contains("target_arch = \"x86_64\", target_os = \"none\""));
    assert!(activation.contains("struct ActiveRootTestAuthority<"));
    assert!(!activation.contains("pub(crate) struct ActiveRootTestAuthority"));
    assert!(activation.contains(
        "#[cfg(all(feature = \"test-support\", target_os = \"none\", target_arch = \"x86_64\"))]\nstruct ActiveRootTestAuthority<"
    ));
    assert!(activation.contains("_not_send_sync: core::marker::PhantomData<*mut ()>"));
    assert!(activation.contains("fn bind_test_publisher<'borrow>("));
    assert!(!activation.contains("pub(crate) fn bind_test_publisher"));
    assert!(activation.contains("const TEST_REGION_START: u64 = 0x0000_0000_4000_0000;"));
    assert!(activation.contains("let user_half = page.is_user_half();"));
    assert!(activation.contains("if effective_user != user_half"));
    assert!(activation.contains("pub(crate) fn run_memory_foundation_test(\n        mut self,"));
    assert!(activation.contains(") -> ! {\n        let authority = &mut ActiveRootTestAuthority"));
    assert!(activation.contains("fn run_mapped_case(&mut self, test:"));
    assert!(activation.contains(
        "use crate::memory::address_region::{\n            AddressSpaceAuthority, AddressSpaceTransactionFailure,"
    ));
    assert!(activation.contains("let result = (|| -> Result<(), u32> {"));
    assert!(activation.contains("Ok(()) => crate::test_support::complete_pass(0)"));
    assert!(activation.contains("Err(detail) => crate::test_support::complete_fail(detail)"));
    assert!(runner.contains("active: ActiveDeepPaging<LiveActivePagingTarget<'_"));
    assert!(!runner.contains("active: &mut ActiveDeepPaging"));
    assert!(activation.contains("deepwyrm_c3_one_shot_ui"));
    assert!(activation.contains("let claimed = active;\n    core::hint::black_box(&active);"));
    assert_eq!(
        runner
            .match_indices("run_memory_foundation_test(BUILD_GUEST_TEST)")
            .count(),
        1
    );
    for forbidden in [
        "PageTableRoot",
        "FrameRoleManager",
        "AddressSpaceKey",
        "unsafe",
    ] {
        assert!(
            !runner.contains(forbidden),
            "selector runner must not acquire raw memory authority: {forbidden}"
        );
    }
}

#[test]
fn c3_fault_probes_are_selector_bound_exact_and_terminal() {
    let support = source("src/test_support/x86_64.rs");
    let identity = source("src/test_support/identity.rs");
    let exceptions = source("src/arch/x86_64/exceptions.rs");

    for fact in [
        "EXPECTED_FAULT_ADDRESS",
        "EXPECTED_FAULT_RIP",
        "EXPECTED_FAULT_ERROR",
        "EXPECTED_FAULT_PROCESSOR",
    ] {
        assert!(
            support.contains(fact),
            "missing expected-fault fact: {fact}"
        );
    }
    assert!(support.contains("EXPECTED_FAULT_EMPTY,\n                EXPECTED_FAULT_WRITING"));
    assert!(
        support.contains("EXPECTED_FAULT_STATE.store(EXPECTED_FAULT_ARMED, Ordering::Release)")
    );
    assert!(support.contains("complete_fail(0x5046_464c)"));
    assert!(identity.contains("BuildGuestTest::MemoryUnmapping, 0"));
    assert!(identity.contains("BuildGuestTest::MemoryPermissions, 3"));
    assert!(exceptions.contains("crate::test_support::complete_exception(exception)"));
    assert!(!exceptions.contains("complete_exception_vector(exception.vector.vector())"));
}

#[test]
fn c2_cpu_profile_excludes_an_untested_smap_access_override() {
    let activation = source("src/arch/x86_64/mm/activation.rs");
    let support = source("src/test_support/x86_64.rs");

    assert!(activation.contains("smap_enabled: cr4 & (1 << 21) != 0"));
    assert!(activation.contains("access_flag_set: rflags & (1 << 18) != 0"));
    assert!(activation.matches("|| cpu.smap_enabled").count() >= 2);
    assert!(activation.matches("|| cpu.access_flag_set").count() >= 2);
    for forbidden in ["asm!(\"stac\"", "asm!(\"clac\"", "fn smap_enabled"] {
        assert!(
            !support.contains(forbidden),
            "test support must not carry an unexercised SMAP override: {forbidden}"
        );
    }
}

#[test]
fn c3_guest_mappings_are_nonidentity_and_cross_page_write_is_atomic() {
    let activation = activation_test_support();
    assert_eq!(
        activation.matches("if backing_physical == first").count(),
        1
    );
    assert!(activation.matches("if backing_physical == second").count() >= 2);

    let invalid = activation
        .split_once("BuildGuestTest::MemoryInvalidPointer => {")
        .expect("invalid-pointer guest body")
        .1
        .split_once("BuildGuestTest::MemoryUserKernelIsolation => {")
        .expect("invalid-pointer body terminator")
        .0;
    for required in [
        "(first, MemoryProtection::READ_WRITE)",
        "(second, MemoryProtection::READ)",
        "crate::memory::usercopy::copy_to_user(",
        "write_crossing",
        "b\"BADWRITE\"",
        "self.read_alias_word(probe)? != Self::ALIAS_VALUE",
        "self.read_alias_word(second)? != Self::ALIAS_VALUE",
        "objects.active_lease_count() == 2",
    ] {
        assert!(
            invalid.contains(required) || activation.contains(required),
            "invalid-pointer live cross-page oracle omitted `{required}`"
        );
    }
}

#[test]
fn permission_transitions_retain_the_exact_backing_frame() {
    let activation = activation_test_support();
    let permissions = activation
        .split_once("BuildGuestTest::MemoryPermissions => {")
        .expect("permissions guest body")
        .1
        .split_once("BuildGuestTest::MemoryInvalidPointer => {")
        .expect("permissions body terminator")
        .0;
    assert_eq!(
        permissions
            .matches("physical_start != backing_physical")
            .count(),
        5,
        "every initial, accepted, rejected, and restored permissions state must retain the exact backing frame"
    );
}
