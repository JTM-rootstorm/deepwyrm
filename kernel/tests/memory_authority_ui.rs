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
fn memory_authority_compile_fail_contracts() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let deps_dir = env::current_exe()
        .expect("resolve current test executable")
        .parent()
        .expect("test executable has dependency directory")
        .to_path_buf();
    let abi_rlib = newest_abi_rlib(&deps_dir);
    let output_dir = env::temp_dir().join(format!(
        "deepwyrm-memory-authority-ui-{}",
        std::process::id()
    ));
    fs::create_dir_all(&output_dir).expect("create UI-test output directory");

    let cases = [
        CompileFailCase {
            fixture: "sibling_capture.rs",
            expected_error: "error[E0624]: method `capture` is private",
        },
        CompileFailCase {
            fixture: "sibling_prepare.rs",
            expected_error: "error[E0624]: method `prepare_replace` is private",
        },
        CompileFailCase {
            fixture: "sibling_captured_mapping_authority.rs",
            expected_error: "error[E0603]: struct `CapturedMappingAuthority` is private",
        },
        CompileFailCase {
            fixture: "sibling_lease_request.rs",
            expected_error: "error[E0603]: struct `LeaseRequest` is private",
        },
        CompileFailCase {
            fixture: "sibling_mapping_lease.rs",
            expected_error: "error[E0603]: struct `MappingLease` is private",
        },
        CompileFailCase {
            fixture: "sibling_prepared_replace.rs",
            expected_error: "error[E0603]: struct `PreparedReplace` is private",
        },
        CompileFailCase {
            fixture: "sibling_lease.rs",
            expected_error: "error[E0624]: method `lease` is private",
        },
        CompileFailCase {
            fixture: "map_authorization_move.rs",
            expected_error: "error[E0382]: use of moved value: `authorization`",
        },
        CompileFailCase {
            fixture: "map_authorization_clone.rs",
            expected_error: "error[E0277]: the trait bound `vm::object::MapAuthorization: Clone` is not satisfied",
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
        );
    }

    fs::remove_dir_all(&output_dir).expect("remove UI-test output directory");
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
) {
    let fixture = manifest_dir.join("tests/ui").join(case.fixture);
    let crate_name = case.fixture.trim_end_matches(".rs").replace('-', "_");
    let extern_arg = OsString::from(format!("deepwyrm_abi={}", abi_rlib.display()));
    let dependency_arg = OsString::from(format!("dependency={}", deps_dir.display()));
    let output = Command::new(rustc)
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
        .arg(&fixture)
        .output()
        .unwrap_or_else(|error| {
            panic!("failed to execute rustc for {}: {error}", fixture.display())
        });

    assert!(
        !output.status.success(),
        "{} unexpectedly compiled; the authority boundary widened",
        fixture.display()
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let first_error = stderr
        .lines()
        .find(|line| line.starts_with("error["))
        .unwrap_or_else(|| panic!("{} emitted no rustc error:\n{}", fixture.display(), stderr));
    assert!(
        first_error == case.expected_error,
        "{} failed with unexpected first error; expected {:?}, got {:?}:\n{}",
        fixture.display(),
        case.expected_error,
        first_error,
        stderr
    );
}
