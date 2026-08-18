use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

struct CompileFailCase<'a> {
    fixture: &'a str,
    expected_error: &'a str,
}

#[test]
fn raw_allocator_mechanisms_remain_ownership_scoped() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let physical = fs::read_to_string(manifest_dir.join("src/memory/physical.rs"))
        .expect("read live physical allocator source");
    let boot_map = fs::read_to_string(manifest_dir.join("src/memory/boot_map.rs"))
        .expect("read live boot-map source");
    let ownership = fs::read_to_string(manifest_dir.join("src/memory/ownership.rs"))
        .expect("read live ownership boundary source");

    for declaration in [
        "pub(super) struct PhysicalFrameAllocator",
        "pub(super) fn from_candidates",
        "pub(super) fn allocate_run",
        "pub(super) fn free_run",
    ] {
        assert_eq!(
            physical.match_indices(declaration).count(),
            1,
            "live raw mechanism must remain uniquely ownership-scoped: {declaration}"
        );
    }
    assert_eq!(
        boot_map
            .match_indices("pub(super) fn initialize_frame_allocator")
            .count(),
        1,
        "live raw initializer must remain uniquely ownership-scoped"
    );
    for child in ["boot_map.rs", "frame_roles.rs", "physical.rs"] {
        assert!(
            ownership.contains(&format!("#[path = \"{child}\"]")),
            "ownership boundary must path-load {child} as its child"
        );
    }
}

#[test]
fn physical_ownership_compile_fail_contracts() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output_dir = env::temp_dir().join(format!(
        "deepwyrm-physical-ownership-ui-{}",
        std::process::id()
    ));
    fs::create_dir_all(&output_dir).expect("create ownership UI-test output directory");

    let cases = [
        CompileFailCase {
            fixture: "raw_allocator_type.rs",
            expected_error: "error[E0603]: struct `PhysicalFrameAllocator` is private",
        },
        CompileFailCase {
            fixture: "raw_allocator_initializer.rs",
            expected_error: "error[E0603]: function `initialize_frame_allocator` is private",
        },
        CompileFailCase {
            fixture: "safe_frame_role_manager_init.rs",
            expected_error: "error[E0133]: call to unsafe function `manager::<impl frame_roles::FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>>::from_boot_map` is unsafe and requires unsafe block",
        },
        CompileFailCase {
            fixture: "private_frame_role_manager_new.rs",
            expected_error: "error[E0624]: associated function `new` is private",
        },
        CompileFailCase {
            fixture: "reused_sanitized_map.rs",
            expected_error: "error[E0382]: use of moved value: `map`",
        },
        CompileFailCase {
            fixture: "allocation_grant_clone.rs",
            expected_error: "error[E0277]: the trait bound `frame_roles::AllocationGrant: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "zeroed_grant_clone.rs",
            expected_error: "error[E0277]: the trait bound `frame_roles::ZeroedGrant: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "object_backing_grant_clone.rs",
            expected_error: "error[E0277]: the trait bound `frame_roles::ObjectBackingGrant: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "table_candidate_grant_clone.rs",
            expected_error: "error[E0277]: the trait bound `frame_roles::TableCandidateGrant: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "staged_table_commit_clone.rs",
            expected_error: "error[E0277]: the trait bound `frame_roles::StagedTableCommit: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "safe_x86_address_space_publisher_new.rs",
            expected_error: "error[E0133]: call to unsafe function `X86AddressSpacePublisher::<'a, T, RANGE_CAPACITY, ROLE_CAPACITY, CANDIDATE_CAPACITY, ENTRY_CAPACITY, INVALIDATION_CAPACITY>::new` is unsafe and requires unsafe block",
        },
        CompileFailCase {
            fixture: "transition_scratch_mapper_clone.rs",
            expected_error: "error[E0277]: the trait bound `LiveTransitionMapper<'_>: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "transition_scratch_mapper_send.rs",
            expected_error: "error[E0277]: `*mut ()` cannot be sent between threads safely",
        },
        CompileFailCase {
            fixture: "transition_scratch_mapper_sync.rs",
            expected_error: "error[E0277]: `*mut ()` cannot be shared between threads safely",
        },
        CompileFailCase {
            fixture: "transition_activation_handoff_moves_mapper.rs",
            expected_error: "error[E0382]: use of moved value: `mapper`",
        },
        CompileFailCase {
            fixture: "transition_private_module.rs",
            expected_error: "error[E0603]: module `private` is private",
        },
        CompileFailCase {
            fixture: "transition_private_constructor.rs",
            expected_error: "error[E0624]: associated function `from_private_parts` is private",
        },
        CompileFailCase {
            fixture: "transition_mapper_backend_escape.rs",
            expected_error: "error[E0616]: field `mapper` of struct `LiveTransitionMapper` is private",
        },
        CompileFailCase {
            fixture: "transition_mapper_raw_zero.rs",
            expected_error: "error[E0599]: no method named `zero_frame` found for mutable reference `&mut LiveTransitionMapper<'_>` in the current scope",
        },
        CompileFailCase {
            fixture: "safe_claim_live_transition_mapper.rs",
            expected_error: "error[E0133]: call to unsafe function `claim_live_transition_mapper` is unsafe and requires unsafe block",
        },
        CompileFailCase {
            fixture: "inactive_root_authority_send.rs",
            expected_error: "error[E0277]: `*mut ()` cannot be sent between threads safely",
        },
        CompileFailCase {
            fixture: "inactive_root_authority_sync.rs",
            expected_error: "error[E0277]: `*mut ()` cannot be shared between threads safely",
        },
        CompileFailCase {
            fixture: "private_inactive_root_authority_bind.rs",
            expected_error: "error[E0624]: associated function `bind` is private",
        },
    ];

    for case in cases {
        run_compile_fail_case(&cargo, &manifest_dir, &output_dir, &case);
    }

    fs::remove_dir_all(&output_dir).expect("remove ownership UI-test output directory");
}

fn run_compile_fail_case(
    cargo: &std::ffi::OsStr,
    manifest_dir: &Path,
    output_dir: &Path,
    case: &CompileFailCase<'_>,
) {
    let fixture = manifest_dir.join("tests/ui").join(case.fixture);
    let crate_name = case.fixture.trim_end_matches(".rs").replace('-', "_");
    let case_dir = output_dir.join(&crate_name);
    fs::create_dir_all(&case_dir).expect("create ownership UI case directory");
    let abi_path = manifest_dir
        .parent()
        .expect("kernel has workspace parent")
        .join("crates/deepwyrm-abi");
    let manifest = format!(
        "[package]\nname = {crate_name:?}\nversion = \"0.0.0\"\nedition = \"2024\"\n\n[dependencies]\ndeepwyrm-abi = {{ path = {abi_path:?} }}\n\n[lib]\npath = {fixture:?}\n",
    );
    let manifest_path = case_dir.join("Cargo.toml");
    fs::write(&manifest_path, manifest).expect("write ownership UI case manifest");

    let output = Command::new(cargo)
        .arg("check")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .arg("--target-dir")
        .arg(output_dir.join("target"))
        .env("CARGO_TERM_COLOR", "never")
        .output()
        .unwrap_or_else(|error| {
            panic!("failed to execute Cargo for {}: {error}", fixture.display())
        });

    assert!(
        !output.status.success(),
        "{} unexpectedly compiled; the ownership boundary widened",
        fixture.display()
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let first_error = stderr
        .lines()
        .find(|line| line.starts_with("error["))
        .unwrap_or_else(|| panic!("{} emitted no Cargo error:\n{}", fixture.display(), stderr));
    assert_eq!(
        first_error,
        case.expected_error,
        "{} failed with an unexpected first error:\n{}",
        fixture.display(),
        stderr
    );
}
