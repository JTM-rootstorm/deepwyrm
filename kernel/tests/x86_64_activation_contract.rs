use std::fs;
use std::path::PathBuf;

#[test]
fn c2_source_has_one_retire_then_one_cr3_write() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let activation = fs::read_to_string(manifest_dir.join("src/arch/x86_64/mm/activation.rs"))
        .expect("read live C2 activation source");
    assert_eq!(
        activation.match_indices("\"mov cr3, {}\"").count(),
        1,
        "the live C2 target must contain exactly one CR3 write instruction"
    );
    let retirement = activation
        .find("handoff.retire_before_activation();")
        .expect("explicit terminal transition retirement");
    let cr3_write = activation
        .find("\"mov cr3, {}\"")
        .expect("single CR3 write");
    assert!(
        retirement < cr3_write,
        "transition authority must retire before the irreversible CR3 write"
    );
    let post_write = &activation[cr3_write..];
    let active_construction = post_write
        .find("LiveActivePagingTarget {")
        .expect("infallible active target construction");
    assert!(
        !post_write[..active_construction].contains("expect(")
            && !post_write[..active_construction].contains("assert"),
        "the post-CR3 path must contain no recoverable or panic-capable check"
    );
}

#[test]
fn c2_linker_bounds_and_linearity_markers_are_unique() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let activation = fs::read_to_string(manifest_dir.join("src/arch/x86_64/mm/activation.rs"))
        .expect("read live C2 activation source");
    let linker = fs::read_to_string(manifest_dir.join("arch/x86_64/linker.ld"))
        .expect("read live linker script");
    let entry = fs::read_to_string(manifest_dir.join("src/arch/x86_64/entry.S"))
        .expect("read live entry assembly");

    for symbol in [
        "__dw_text_start =",
        "__dw_text_end =",
        "__dw_rodata_start =",
        "__dw_rodata_end =",
        "__dw_data_start =",
        "__dw_data_end =",
    ] {
        assert_eq!(
            linker.match_indices(symbol).count(),
            1,
            "linker segment bound must be unique: {symbol}"
        );
    }
    for symbol in ["__dw_boot_stack_bottom:", "__dw_boot_stack_top:"] {
        assert_eq!(
            entry.match_indices(symbol).count(),
            1,
            "boot-stack carrier bound must be a unique linker-visible symbol: {symbol}"
        );
    }
    assert!(
        linker.contains("__dw_boot_stack_top - __dw_boot_stack_bottom"),
        "the linker must retain the exact boot-stack extent assertion"
    );
    assert!(
        activation.match_indices("PhantomData<*mut ()>").count() >= 3,
        "inactive, prepared-target, and active authorities remain !Send/!Sync"
    );
    assert!(
        !activation.contains("pub(crate) fn publish_replace")
            && !activation.contains("pub(crate) fn with_active_session"),
        "C2 must not expose safe post-activation publication before address-space/root binding exists"
    );
}

#[test]
fn c2_large_bootstrap_state_is_not_stack_owned() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let kernel = fs::read_to_string(manifest_dir.join("src/lib.rs"))
        .expect("read live kernel bootstrap source");
    let activation = fs::read_to_string(manifest_dir.join("src/arch/x86_64/mm/activation.rs"))
        .expect("read live activation source");
    let transition = fs::read_to_string(manifest_dir.join("src/arch/x86_64/mm/transition.rs"))
        .expect("read live transition source");
    let physical = fs::read_to_string(manifest_dir.join("src/memory/physical.rs"))
        .expect("read live physical allocator source");
    let layout = fs::read_to_string(manifest_dir.join("arch/x86_64/layout.toml"))
        .expect("read live architecture layout");

    assert!(layout.contains("kernel_boot_stack_size = 131072"));
    for storage in [
        "static BOOTSTRAP_ROLE_MANAGER",
        "static BOOTSTRAP_RESERVATIONS",
        "static BOOTSTRAP_SANITIZED_MAP",
    ] {
        assert!(
            kernel.contains(storage),
            "missing static bootstrap storage: {storage}"
        );
    }
    for storage in [
        "static BUILD_WORKSPACE",
        "static GRAPH_VALIDATION_WORKSPACE",
    ] {
        assert!(
            activation.contains(storage),
            "missing static activation workspace: {storage}"
        );
    }
    assert!(
        !kernel.contains("let mut roles ="),
        "the large role registry must never be a kernel_main stack local"
    );
    assert!(
        transition.contains("table_frames: &'a [u64]")
            && transition.contains("size_of::<LiveTransitionMapper<'static>>() <= 256"),
        "the target transition mapper must borrow its fixed carrier and enforce a compact type bound"
    );
    assert!(
        physical.contains("unsafe fn from_candidates_in"),
        "the fixed-capacity allocator must initialize in its final static manager field"
    );
}

#[test]
fn c2_kernel_image_exclusion_precedes_first_table_allocation() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let activation = fs::read_to_string(manifest_dir.join("src/arch/x86_64/mm/activation.rs"))
        .expect("read live activation source");
    let builder_start = activation
        .find("fn build_and_bind_deep_root<")
        .expect("production inactive-root builder");
    let builder = &activation[builder_start..];
    let boundary = builder
        .find("validate_kernel_boot_boundary(memory_witness, &declarations)")
        .expect("normalized RESERVED and bootstrap-reservation witness validation");
    let exclusion = builder
        .find("roles.stage_kernel_image_roles(declarations)")
        .expect("typed pre-allocation kernel exclusion");
    let owner = builder
        .find(".create_table_owner()")
        .expect("first table-owner creation");
    let allocation = builder
        .find("allocate_owned_table(")
        .expect("first table allocation");
    assert!(
        boundary < exclusion && exclusion < owner && owner < allocation,
        "normalized RESERVED coverage and disjoint bootstrap provenance must precede role publication and table allocation"
    );
}
