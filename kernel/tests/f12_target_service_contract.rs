//! DW0-F12 build-owned selector and production-isolation contract.
//!
//! This external integration crate intentionally checks only source-visible
//! target wiring.  The real composed service graph remains crate-private and
//! is exercised by its dedicated internal test module; exposing it here would
//! weaken the kernel authority boundary merely for test convenience.

use std::fs;
use std::path::PathBuf;

fn source(relative: &str) -> String {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    fs::read_to_string(manifest.join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

#[test]
fn f12_selector_13_is_build_owned_and_target_gated() {
    let build = source("build.rs");
    let identity = source("src/test_support/identity.rs");

    assert!(build.contains("fn is_f12_userspace_selector(selector: &str) -> bool"));
    assert!(
        build.contains("selector == \"ipc-blocking-smoke\""),
        "only the canonical F12 selector may enable the composed target runtime"
    );
    assert!(build.contains("cargo:rustc-cfg=deepwyrm_f12_guest"));
    assert!(build.contains("build_f12_user_artifact("));
    assert!(
        build.contains("if selector.as_deref().is_some_and(is_f12_userspace_selector)"),
        "the F12 user artifact must be linked only for its selected test build"
    );

    for marker in [
        "IpcBlockingSmoke",
        "Self::IpcBlockingSmoke => 13",
        "string_equals(value, \"ipc-blocking-smoke\")",
        "pub(crate) const fn is_f12_userspace(self) -> bool",
    ] {
        assert!(
            identity.contains(marker),
            "missing F12 identity marker `{marker}`"
        );
    }
}

#[test]
fn f12_runtime_dispatches_after_activation_and_is_absent_from_production() {
    let kernel = source("src/lib.rs");
    let activation = source("src/arch/x86_64/mm/activation/test_support.rs");

    let activation_boundary = kernel
        .find("arch::x86_64::mm::activate_bootstrap_deep_paging(")
        .expect("Deep-owned paging activation");
    let dispatch = kernel
        .find("active_paging.run_ipc_blocking_userspace_test(test_support::BUILD_GUEST_TEST)")
        .expect("unique F12 post-activation dispatch");
    assert!(
        activation_boundary < dispatch,
        "the F12 runtime must receive the live Deep-owned root, never pre-activation state"
    );
    assert_eq!(
        kernel
            .match_indices("run_ipc_blocking_userspace_test(test_support::BUILD_GUEST_TEST)")
            .count(),
        1,
        "the composed F12 runtime needs one target-only call site"
    );
    assert!(kernel.contains("test if test.is_f12_userspace() => {}"));
    let production = kernel
        .rsplit_once("#[cfg(not(feature = \"test-support\"))]")
        .expect("production post-activation branch")
        .1;
    assert!(
        !production.contains("run_ipc_blocking_userspace_test"),
        "production must not retain a test-runtime dispatch"
    );

    assert!(activation.contains("#[cfg(deepwyrm_f12_guest)]"));
    assert!(activation.contains("mod f12;"));
    assert!(activation.contains("run_ipc_blocking_userspace_test"));
}
