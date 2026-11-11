use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

struct CompileFailCase<'a> {
    fixture: &'a str,
    expected_error: &'a str,
}

#[test]
fn f11_move_only_ipc_wait_time_and_architecture_contracts() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_dir = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("kernel is nested below the workspace root");
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let deps_dir = env::current_exe()
        .expect("resolve current test executable")
        .parent()
        .expect("test executable has dependency directory")
        .to_path_buf();
    let abi_rlib = newest_abi_rlib(&deps_dir);
    let output_dir = workspace_dir
        .join(".tmp")
        .join("f11-ui")
        .join(std::process::id().to_string());
    fs::create_dir_all(&output_dir).expect("create project-local F11 UI output directory");

    let cases = [
        CompileFailCase {
            fixture: "f11_handle_transfer_token_clone.rs",
            expected_error: "error[E0277]: the trait bound `HandleTransferToken: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "f11_handle_transfer_batch_clone.rs",
            expected_error: "error[E0277]: the trait bound `HandleTransferBatch: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "f11_handle_transfer_reservation_clone.rs",
            expected_error: "error[E0277]: the trait bound `HandleTransferReservation: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "f11_prepared_handle_move_clone.rs",
            expected_error: "error[E0277]: the trait bound `PreparedHandleMove: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "f11_prepared_handle_move_rollback_clone.rs",
            expected_error: "error[E0277]: the trait bound `PreparedHandleMoveRollback: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "f11_block_reservation_clone.rs",
            expected_error: "error[E0277]: the trait bound `BlockReservation: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "f11_block_token_clone.rs",
            expected_error: "error[E0277]: the trait bound `BlockToken: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "f11_deadline_registration_clone.rs",
            expected_error: "error[E0277]: the trait bound `DeadlineRegistration: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "f11_kernel_switch_plan_clone.rs",
            expected_error: "error[E0277]: the trait bound `KernelSwitchPlan<'_>: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "f11_initial_kernel_continuation_clone.rs",
            expected_error: "error[E0277]: the trait bound `InitialKernelContinuation: Clone` is not satisfied",
        },
    ];

    for case in cases {
        run_compile_fail_case(
            &rustc,
            &manifest_dir,
            &deps_dir,
            &abi_rlib,
            &output_dir,
            &case,
            false,
        );
    }

    let atomic_wait_operation = CompileFailCase {
        fixture: "f11_atomic_wait_operation_clone.rs",
        expected_error: "error[E0277]: the trait bound `AtomicWaitOperation<()>: Clone` is not satisfied",
    };
    run_compile_fail_case(
        &rustc,
        &manifest_dir,
        &deps_dir,
        &abi_rlib,
        &output_dir,
        &atomic_wait_operation,
        true,
    );
    for case in [
        CompileFailCase {
            fixture: "f11_wait_registration_clone.rs",
            expected_error: "error[E0277]: the trait bound `WaitRegistration: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "f11_channel_side_lease_private.rs",
            expected_error: "error[E0603]: struct `ChannelSideLease` is private",
        },
        CompileFailCase {
            fixture: "f11_channel_finalization_clone.rs",
            expected_error: "error[E0277]: the trait bound `ChannelFinalization<1, 1>: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "f11_channel_send_reservation_clone.rs",
            expected_error: "error[E0277]: the trait bound `ChannelSendReservation: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "f11_timer_payload_binding_clone.rs",
            expected_error: "error[E0277]: the trait bound `TimerPayloadBinding: Clone` is not satisfied",
        },
        CompileFailCase {
            fixture: "f13_execution_owner_move_with_switch_plan.rs",
            expected_error: "error[E0505]: cannot move out of `execution` because it is borrowed",
        },
        CompileFailCase {
            fixture: "f13_execution_owner_replace_with_switch_plan.rs",
            expected_error: "error[E0502]: cannot borrow `execution` as mutable because it is also borrowed as immutable",
        },
        CompileFailCase {
            fixture: "f13_safe_suspend_facade_requires_unsafe.rs",
            expected_error: "error[E0133]: call to unsafe function `NativeWaitControl::prepare_suspend` is unsafe and requires unsafe block",
        },
        // S2K D5 (TSV row 76): a return to userspace needs the finalizer-drain proof.
        CompileFailCase {
            fixture: "d5_return_ready_forged.rs",
            expected_error: "error[E0451]: field `result` of struct `ReturnReady` is private",
        },
        CompileFailCase {
            fixture: "d5_finalizers_drained_forged.rs",
            expected_error: "error[E0133]: call to unsafe function `FinalizersDrained::assume` is unsafe and requires unsafe block",
        },
        CompileFailCase {
            fixture: "d5_finalizers_drained_clone.rs",
            expected_error: "error[E0277]: the trait bound `FinalizersDrained: Clone` is not satisfied",
        },
        // S2K D5 (TSV row 102): an AP publishes ready only with its kernel-root entry proof.
        CompileFailCase {
            fixture: "d5_ap_root_entry_forged.rs",
            expected_error: "error[E0133]: call to unsafe function `CarrierRuntimeState::after_kernel_root_entry` is unsafe and requires unsafe block",
        },
        CompileFailCase {
            fixture: "d5_ap_root_entry_clone.rs",
            expected_error: "error[E0277]: the trait bound `CarrierRuntimeState: Clone` is not satisfied",
        },
        // D1 option B2 (design §11.2.9 item 4): held family-G releases merge only
        // on their shootdown's settlement, which cannot be forged.
        CompileFailCase {
            fixture: "d1_held_releases_merge_without_settlement.rs",
            expected_error: "error[E0061]: this method takes 2 arguments but 1 argument was supplied",
        },
        CompileFailCase {
            fixture: "d1_nothing_published_forged.rs",
            expected_error: "error[E0451]: field `_private` of struct `NothingPublished` is private",
        },
        CompileFailCase {
            fixture: "d1_reclaim_permit_forged.rs",
            expected_error: "error[E0451]: fields `request` and `target_count` of struct `ReclaimPermit` are private",
        },
    ] {
        run_compile_fail_case(
            &rustc,
            &manifest_dir,
            &deps_dir,
            &abi_rlib,
            &output_dir,
            &case,
            true,
        );
    }

    fs::remove_dir_all(&output_dir).expect("remove exact project-local F11 UI output directory");
}

fn newest_abi_rlib(deps_dir: &Path) -> PathBuf {
    let mut candidates = fs::read_dir(deps_dir)
        .expect("read Cargo dependency directory")
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("libdeepwyrm_abi-") || !name.ends_with(".rlib") {
                return None;
            }
            let modified = entry.metadata().ok()?.modified().ok()?;
            Some((entry.path(), modified))
        })
        .collect::<Vec<(PathBuf, SystemTime)>>();
    candidates.sort_by_key(|(_, modified)| *modified);
    candidates
        .pop()
        .map(|(path, _)| path)
        .expect("deepwyrm-abi rlib is built before kernel integration tests")
}

fn run_compile_fail_case(
    rustc: &std::ffi::OsStr,
    manifest_dir: &Path,
    deps_dir: &Path,
    abi_rlib: &Path,
    output_dir: &Path,
    case: &CompileFailCase<'_>,
    integrated: bool,
) {
    let fixture = manifest_dir.join("tests/ui").join(case.fixture);
    let crate_name = case.fixture.trim_end_matches(".rs").replace('-', "_");
    let extern_arg = OsString::from(format!("deepwyrm_abi={}", abi_rlib.display()));
    let dependency_arg = OsString::from(format!("dependency={}", deps_dir.display()));
    let mut command = Command::new(rustc);
    command
        .arg("--edition=2024")
        .arg("--crate-type=lib")
        .arg("--emit=metadata")
        .arg("--deny=unsafe-code")
        .arg("--crate-name")
        .arg(crate_name)
        .arg("--extern")
        .arg(extern_arg)
        .arg("-L")
        .arg(dependency_arg)
        .arg("--out-dir")
        .arg(output_dir)
        .env("TMPDIR", output_dir);
    if integrated {
        command
            .arg("--cfg")
            .arg("deepwyrm_integrated")
            .env("DEEPWYRM_E3_THREAD_STACK_COUNT", "32")
            .env("DEEPWYRM_E3_THREAD_STACK_SIZE", "524288")
            .env("DEEPWYRM_E3_THREAD_STACK_GUARD_SIZE", "4096")
            .env("DEEPWYRM_E3_THREAD_STACK_ALIGNMENT", "4096")
            .env("DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_COUNT", "1")
            .env("DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_SIZE", "65536")
            .env("DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_GUARD_SIZE", "4096")
            .env("DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_ALIGNMENT", "4096");
    }
    let output = command.arg(&fixture).output().unwrap_or_else(|error| {
        panic!("failed to execute rustc for {}: {error}", fixture.display())
    });

    assert!(
        !output.status.success(),
        "{} unexpectedly compiled; an F11 move-only authority widened",
        fixture.display()
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let first_error = stderr
        .lines()
        .find(|line| line.starts_with("error["))
        .unwrap_or_else(|| panic!("{} emitted no rustc error:\n{}", fixture.display(), stderr));
    assert_eq!(
        first_error,
        case.expected_error,
        "{} failed with unexpected first error:\n{}",
        fixture.display(),
        stderr
    );
}
