use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

const SELECTORS: [&str; 6] = [
    "memory-mapping",
    "memory-unmapping",
    "memory-permissions",
    "memory-invalid-pointer",
    "memory-user-kernel-isolation",
    "memory-shared-memory-object",
];
const OWNED_WORKSPACE_CARGO_CONFIG: &str = ".cargo/config.toml";
const LEGACY_WORKSPACE_CARGO_CONFIG: &str = ".cargo/config";

#[test]
#[ignore = "explicit accepted-toolchain x86_64 target-artifact gate"]
fn production_and_six_memory_selector_artifacts_are_separated() {
    let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("kernel manifest has workspace parent")
        .to_path_buf();
    reject_ambient_build_overrides(&workspace);
    let cargo = required_path("DEEPWYRM_ACCEPTED_CARGO");
    let rustc = required_path("DEEPWYRM_ACCEPTED_RUSTC");
    let rust_lld = required_path("DEEPWYRM_ACCEPTED_RUST_LLD");
    let clang = required_path("DEEPWYRM_CLANG");
    let llvm_nm = required_path("DEEPWYRM_LLVM_NM");
    let llvm_objdump = required_path("DEEPWYRM_LLVM_OBJDUMP");
    let llvm_readelf = required_path("DEEPWYRM_LLVM_READELF");
    let build_tools = BuildTools {
        cargo: &cargo,
        rustc: &rustc,
        rust_lld: &rust_lld,
        clang: &clang,
    };
    let toolchain_identity = fs::read_to_string(workspace.join("tooling/rust-toolchain.toml"))
        .expect("read trusted toolchain identity");
    let build_tools_identity = fs::read_to_string(workspace.join("tooling/build-tools.toml"))
        .expect("read trusted build-tools identity");
    validate_accepted_identities(
        &toolchain_identity,
        &build_tools_identity,
        &cargo,
        &rustc,
        &rust_lld,
        &clang,
    );
    let output_root = ArtifactRoot::create();
    let build_environment = BuildEnvironment::create(output_root.path());
    let build_environment_hash = normalized_build_environment_sha256(
        &cargo,
        &rustc,
        &rust_lld,
        &clang,
        &llvm_nm,
        &llvm_objdump,
        &llvm_readelf,
        &build_tools_identity,
    );
    let build_input_before = build_input_manifest_sha256(&workspace);
    validate_one_shot_ui(
        &workspace,
        &output_root.path().join("one-shot-ui"),
        &build_environment,
        build_tools,
    );

    let production = build_kernel(
        &workspace,
        &output_root.path().join("production"),
        &build_environment,
        build_tools,
        None,
    );
    let production_symbols = symbols(&llvm_nm, &production);
    validate_ist_artifact_geometry(&production_symbols);
    let production_disassembly = disassembly(&llvm_objdump, &production);
    validate_entry_normalization(&production_disassembly);
    let production_stack_artifact = build_stack_kernel(
        &workspace,
        &output_root.path().join("production-stack-sizes"),
        &build_environment,
        build_tools,
        None,
    );
    let production_stack_disassembly = disassembly(&llvm_objdump, &production_stack_artifact);
    assert_eq!(
        text_disassembly(&production_stack_disassembly),
        text_disassembly(&production_disassembly),
        "production stack-size carrier changed the canonical production machine code"
    );
    validate_production_ist_stack_margin(
        &stack_sizes(&llvm_readelf, &production_stack_artifact),
        &production_stack_disassembly,
    );
    assert!(production_symbols.contains("activate_bootstrap_deep_paging"));
    for forbidden in [
        "test_support",
        "run_memory_foundation_test",
        "dw_test_unmapped_read",
        "dw_test_write_protected",
        "complete_known_outcome",
        "complete_pass",
        "complete_fail",
        "complete_panic",
        "EXPECTED_FAULT",
    ] {
        assert!(
            !production_symbols.contains(forbidden),
            "production artifact retained test-only symbol {forbidden}"
        );
    }
    let production_bytes = fs::read(&production).expect("read production kernel artifact");
    for forbidden in SELECTORS.into_iter().chain([
        "DWTEST1",
        "dw_test_",
        "EXPECTED_FAULT",
        "complete_known_outcome",
        "QEMU_DEBUG_EXIT_PORT",
        "isa-debug-exit",
    ]) {
        assert!(
            !contains_bytes(&production_bytes, forbidden.as_bytes()),
            "production artifact retained test marker {forbidden}"
        );
    }
    for forbidden in ["mov\tdx, 0xf4", "out\tdx, eax"] {
        assert!(
            !production_disassembly.contains(forbidden),
            "production artifact retained debug-exit instruction evidence: {forbidden}"
        );
    }

    let mut hashes = BTreeSet::new();
    let production_hash = sha256(&production);
    eprintln!("production {production_hash}");
    hashes.insert(production_hash);
    for selector in SELECTORS {
        let artifact = build_kernel(
            &workspace,
            &output_root.path().join(selector),
            &build_environment,
            build_tools,
            Some(selector),
        );
        let selector_symbols = symbols(&llvm_nm, &artifact);
        let selector_disassembly = disassembly(&llvm_objdump, &artifact);
        for required in [
            "activate_bootstrap_deep_paging",
            "run_memory_foundation_test",
            "dw_test_unmapped_read_site",
            "dw_test_write_protected_site",
        ] {
            assert!(
                selector_symbols.contains(required),
                "{selector} artifact omitted {required}"
            );
        }
        let artifact_hash = sha256(&artifact);
        eprintln!("{selector} {artifact_hash}");
        assert!(
            hashes.insert(artifact_hash),
            "{selector} artifact is byte-identical to another build identity"
        );

        let stack_artifact = build_stack_kernel(
            &workspace,
            &output_root.path().join(format!("{selector}-stack-sizes")),
            &build_environment,
            build_tools,
            Some(selector),
        );
        let stack_disassembly = disassembly(&llvm_objdump, &stack_artifact);
        assert_eq!(
            text_disassembly(&stack_disassembly),
            text_disassembly(&selector_disassembly),
            "{selector} stack-size carrier changed the plain selector machine code"
        );
        validate_selector_stack_margin(
            selector,
            &stack_sizes(&llvm_readelf, &stack_artifact),
            &stack_disassembly,
        );
    }
    let build_input_after = build_input_manifest_sha256(&workspace);
    assert_eq!(
        build_input_after, build_input_before,
        "build-relevant source/configuration changed during the isolated builds"
    );
    validate_accepted_identities(
        &toolchain_identity,
        &build_tools_identity,
        &cargo,
        &rustc,
        &rust_lld,
        &clang,
    );
    let build_environment_after = normalized_build_environment_sha256(
        &cargo,
        &rustc,
        &rust_lld,
        &clang,
        &llvm_nm,
        &llvm_objdump,
        &llvm_readelf,
        &build_tools_identity,
    );
    assert_eq!(
        build_environment_after, build_environment_hash,
        "accepted build/inspection tools changed during the isolated builds"
    );
    reject_ambient_build_overrides(&workspace);
    eprintln!("build-input-manifest {build_input_before}");
    eprintln!("normalized-build-environment {build_environment_hash}");
    output_root.cleanup();
}

fn validate_accepted_identities(
    rust_identity: &str,
    build_tools_identity: &str,
    cargo: &Path,
    rustc: &Path,
    rust_lld: &Path,
    clang: &Path,
) {
    let toolchain_root = cargo
        .parent()
        .and_then(Path::parent)
        .expect("Cargo path has a toolchain root");
    let artifact_root = toolchain_root
        .parent()
        .and_then(Path::parent)
        .expect("toolchain root has an artifact root");
    for (supplied, path_key, hash_key) in [
        (cargo, "cargo_binary", "cargo_sha256"),
        (rustc, "rustc_binary", "rustc_sha256"),
        (rust_lld, "rust_lld_binary", "rust_lld_sha256"),
    ] {
        let expected_path = toolchain_root.join(manifest_value(rust_identity, path_key));
        assert_eq!(
            fs::canonicalize(supplied).expect("canonicalize supplied tool"),
            fs::canonicalize(&expected_path).expect("canonicalize accepted tool"),
            "{path_key} is not the repository-selected toolchain path"
        );
        assert_eq!(
            sha256(supplied),
            manifest_value(rust_identity, hash_key),
            "{hash_key} does not match the repository-owned accepted identity"
        );
    }
    for (path_key, hash_key) in [
        (
            "rustc_driver_internal_library",
            "rustc_driver_internal_library_sha256",
        ),
        ("llvm_internal_library", "llvm_internal_library_sha256"),
    ] {
        assert_eq!(
            sha256(&toolchain_root.join(manifest_value(rust_identity, path_key))),
            manifest_value(rust_identity, hash_key),
            "{hash_key} drifted"
        );
    }
    for (path, hash_key) in [
        (
            artifact_root.join(manifest_value(rust_identity, "root_manifest")),
            "root_manifest_sha256",
        ),
        (artifact_root.join("bootstrap.toml"), "config_sha256"),
        (
            artifact_root.join(manifest_value(rust_identity, "sysroot_manifest")),
            "sysroot_manifest_sha256",
        ),
    ] {
        assert_eq!(
            sha256(&path),
            manifest_value(rust_identity, hash_key),
            "{hash_key} drifted"
        );
    }
    assert_eq!(
        deterministic_tree_sha256(toolchain_root),
        manifest_value(rust_identity, "toolchain_tree_sha256"),
        "accepted toolchain tree drifted"
    );
    let clang_runtime = clang_runtime_paths(build_tools_identity, clang);
    assert_eq!(
        fs::canonicalize(clang).expect("canonicalize supplied Clang"),
        fs::canonicalize(&clang_runtime.expected_clang)
            .expect("canonicalize repository-selected Clang"),
        "Clang is not the repository-selected build-tools path"
    );
    for (path, hash_key, label) in [
        (clang, "clang_sha256", "Clang"),
        (
            clang_runtime.libclang_cpp.as_path(),
            "libclang_cpp_sha256",
            "libclang-cpp",
        ),
        (
            clang_runtime.host_llvm.as_path(),
            "host_llvm_sha256",
            "host LLVM",
        ),
    ] {
        assert_eq!(
            sha256(path),
            manifest_value(build_tools_identity, hash_key),
            "{label} does not match the repository-owned accepted identity"
        );
    }
}

struct ClangRuntimePaths {
    expected_clang: PathBuf,
    libclang_cpp: PathBuf,
    host_llvm: PathBuf,
}

fn clang_runtime_paths(build_tools_identity: &str, supplied_clang: &Path) -> ClangRuntimePaths {
    let clang_relative = PathBuf::from(manifest_value(build_tools_identity, "clang_binary"));
    assert!(
        clang_relative
            .components()
            .all(|component| matches!(component, Component::Normal(_))),
        "trusted Clang path must be a normalized relative path"
    );
    let mut root = supplied_clang.to_path_buf();
    for _ in clang_relative.components() {
        assert!(
            root.pop(),
            "supplied Clang path is shallower than the trusted relative path"
        );
    }
    ClangRuntimePaths {
        expected_clang: root.join(clang_relative),
        libclang_cpp: root.join(manifest_value(build_tools_identity, "libclang_cpp")),
        host_llvm: root.join(manifest_value(build_tools_identity, "host_llvm")),
    }
}

fn deterministic_tree_sha256(root: &Path) -> String {
    let mut tar_command = helper_command("/usr/bin/tar");
    let mut tar = tar_command
        .args([
            "--sort=name",
            "--mtime=@0",
            "--owner=0",
            "--group=0",
            "--numeric-owner",
            "-cf",
            "-",
            "-C",
        ])
        .arg(root)
        .arg(".")
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn deterministic toolchain-tree archive");
    let tar_output = tar.stdout.take().expect("capture tar output");
    let mut sha_command = helper_command("/usr/bin/sha256sum");
    let digest = run_output(
        sha_command.stdin(Stdio::from(tar_output)),
        "toolchain-tree sha256sum",
    );
    assert!(
        tar.wait().expect("wait for deterministic tar").success(),
        "deterministic toolchain-tree archive failed"
    );
    digest_from_output(digest)
}

fn build_input_manifest_sha256(workspace: &Path) -> String {
    let mut files = Vec::new();
    for relative in [
        OWNED_WORKSPACE_CARGO_CONFIG,
        "Cargo.lock",
        "Cargo.toml",
        "crates/deepwyrm-abi/Cargo.toml",
        "kernel/Cargo.toml",
        "kernel/build.rs",
        "tooling/build-tools.toml",
        "tooling/guest-harness.toml",
        "tooling/rust-toolchain.toml",
    ] {
        files.push(workspace.join(relative));
    }
    for relative in [
        "abi/generated",
        "crates/deepwyrm-abi/src",
        "kernel/arch",
        "kernel/src",
    ] {
        collect_regular_files(&workspace.join(relative), &mut files);
    }
    files.sort_by(|left, right| {
        left.strip_prefix(workspace)
            .expect("build input is workspace-relative")
            .cmp(
                right
                    .strip_prefix(workspace)
                    .expect("build input is workspace-relative"),
            )
    });
    files.dedup();
    let mut manifest = Vec::new();
    for path in files {
        let relative = path
            .strip_prefix(workspace)
            .expect("build input is workspace-relative")
            .to_str()
            .expect("build input path is UTF-8");
        manifest.extend_from_slice(sha256(&path).as_bytes());
        manifest.push(b' ');
        manifest.extend_from_slice(relative.as_bytes());
        manifest.push(b'\n');
    }
    sha256_bytes(&manifest)
}

fn collect_regular_files(directory: &Path, files: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(directory)
        .unwrap_or_else(|error| {
            panic!(
                "read build-input directory {}: {error}",
                directory.display()
            )
        })
        .map(|entry| entry.expect("read build-input entry").path())
        .collect();
    entries.sort();
    for path in entries {
        let file_type = fs::symlink_metadata(&path)
            .expect("read build-input metadata")
            .file_type();
        assert!(
            !file_type.is_symlink(),
            "build input must not be a symlink: {}",
            path.display()
        );
        if file_type.is_dir() {
            collect_regular_files(&path, files);
        } else {
            assert!(
                file_type.is_file(),
                "build input must be regular: {}",
                path.display()
            );
            files.push(path);
        }
    }
}

fn sha256_bytes(bytes: &[u8]) -> String {
    let mut command = helper_command("/usr/bin/sha256sum");
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn sha256sum for build-input manifest");
    child
        .stdin
        .take()
        .expect("capture sha256sum stdin")
        .write_all(bytes)
        .expect("write build-input manifest");
    digest_from_output(child.wait_with_output().expect("wait for sha256sum"))
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

struct ArtifactRoot(Option<PathBuf>);

impl ArtifactRoot {
    fn create() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock precedes Unix epoch")
            .as_nanos();
        let path = env::temp_dir().join(format!(
            "deepwyrm-c3-target-artifacts-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&path)
            .unwrap_or_else(|error| panic!("create fresh target-artifact root: {error}"));
        Self(Some(path))
    }

    fn path(&self) -> &Path {
        self.0.as_deref().expect("artifact root remains owned")
    }

    fn cleanup(mut self) {
        let path = self.0.take().expect("artifact root remains owned");
        fs::remove_dir_all(path).expect("remove isolated target-artifact directory");
    }
}

impl Drop for ArtifactRoot {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

struct BuildEnvironment {
    cargo_home: PathBuf,
    home: PathBuf,
}

#[derive(Clone, Copy)]
struct BuildTools<'a> {
    cargo: &'a Path,
    rustc: &'a Path,
    rust_lld: &'a Path,
    clang: &'a Path,
}

impl BuildEnvironment {
    fn create(root: &Path) -> Self {
        let cargo_home = root.join("cargo-home");
        let home = root.join("home");
        fs::create_dir(&cargo_home).expect("create isolated empty CARGO_HOME");
        fs::create_dir(&home).expect("create isolated empty HOME");
        assert!(
            fs::read_dir(&cargo_home)
                .expect("inspect isolated CARGO_HOME")
                .next()
                .is_none(),
            "isolated CARGO_HOME must start empty"
        );
        Self { cargo_home, home }
    }

    fn apply(&self, command: &mut Command, tools: BuildTools<'_>, target_dir: &Path) {
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("CARGO_HOME", &self.cargo_home)
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("SOURCE_DATE_EPOCH", "0")
            .env("CARGO_NET_OFFLINE", "true")
            .env("CARGO_TERM_COLOR", "never")
            .env("RUSTC", tools.rustc)
            .env("DEEPWYRM_CLANG", tools.clang)
            .env("CARGO_TARGET_DIR", target_dir)
            .env("CARGO_TARGET_X86_64_UNKNOWN_NONE_LINKER", tools.rust_lld);
    }
}

fn reject_ambient_build_overrides(workspace: &Path) {
    const EXACT: &[&str] = &[
        "AR",
        "CARGO_CACHE_RUSTC_INFO",
        "CARGO_ENCODED_RUSTFLAGS",
        "CARGO_HOME",
        "CARGO_INCREMENTAL",
        "CARGO_TARGET_DIR",
        "CC",
        "CFLAGS",
        "CPPFLAGS",
        "LDFLAGS",
        "RANLIB",
        "RUSTC",
        "RUSTC_BOOTSTRAP",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOC",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
        "RUSTUP_TOOLCHAIN",
    ];
    const PREFIXES: &[&str] = &[
        "CARGO_BUILD_",
        "CARGO_HTTP_",
        "CARGO_NET_",
        "CARGO_PATCH_",
        "CARGO_PROFILE_",
        "CARGO_REGISTRIES_",
        "CARGO_SOURCE_",
        "CARGO_TARGET_",
    ];
    let mut rejected = Vec::new();
    for (name, _) in env::vars_os() {
        let name = name.to_string_lossy();
        if EXACT.contains(&name.as_ref()) || PREFIXES.iter().any(|prefix| name.starts_with(prefix))
        {
            rejected.push(name.into_owned());
        }
    }
    rejected.sort();
    assert!(
        rejected.is_empty(),
        "ambient Cargo/Rust build overrides are forbidden: {}",
        rejected.join(", ")
    );

    let ambient_home = env::var_os("HOME").map(PathBuf::from);
    let configs = ambient_cargo_configs(workspace, ambient_home.as_deref());
    assert!(
        configs.is_empty(),
        "ambient Cargo configuration is forbidden: {}",
        configs
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
}

fn ambient_cargo_configs(workspace: &Path, ambient_home: Option<&Path>) -> Vec<PathBuf> {
    let mut cargo_directories = BTreeSet::new();
    cargo_directories.insert(workspace.join(".cargo"));
    if let Some(home) = ambient_home {
        cargo_directories.insert(home.join(".cargo"));
    }
    if let Some(parent) = workspace.parent() {
        for ancestor in parent.ancestors() {
            cargo_directories.insert(ancestor.join(".cargo"));
        }
    }

    let mut configs = Vec::new();
    for directory in cargo_directories {
        for name in ["config", "config.toml"] {
            let config = directory.join(name);
            if config == workspace.join(OWNED_WORKSPACE_CARGO_CONFIG) {
                continue;
            }
            match fs::symlink_metadata(&config) {
                Ok(_) => configs.push(config),
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => panic!(
                    "cannot prove ambient Cargo configuration absent at {}: {error}",
                    config.display()
                ),
            }
        }
    }
    configs.sort();
    configs
}

#[test]
fn legacy_workspace_ancestor_and_home_cargo_configuration_is_rejected() {
    let root = ArtifactRoot::create();
    let ancestor = root.path().join("ancestor");
    let workspace = ancestor.join("deepwyrm");
    let ambient_home = root.path().join("operator-home");
    fs::create_dir_all(workspace.join(".cargo")).expect("create workspace Cargo directory");
    fs::create_dir_all(ancestor.join(".cargo")).expect("create ancestor Cargo directory");
    fs::create_dir_all(ambient_home.join(".cargo")).expect("create ambient Cargo directory");
    let owned_workspace_config = workspace.join(OWNED_WORKSPACE_CARGO_CONFIG);
    fs::write(&owned_workspace_config, "[build]\n").expect("write owned workspace Cargo config");

    let before = ambient_cargo_configs(&workspace, Some(&ambient_home));
    assert!(before.is_empty());

    let legacy_workspace_config = workspace.join(LEGACY_WORKSPACE_CARGO_CONFIG);
    let ancestor_config = ancestor.join(".cargo/config.toml");
    let home_config = ambient_home.join(".cargo/config");
    fs::write(&legacy_workspace_config, "[build]\n").expect("write legacy workspace Cargo config");
    fs::write(&ancestor_config, "[build]\n").expect("write ancestor Cargo config");
    fs::write(&home_config, "[build]\n").expect("write ambient-home Cargo config");
    let detected = ambient_cargo_configs(&workspace, Some(&ambient_home));
    assert!(detected.contains(&legacy_workspace_config));
    assert!(detected.contains(&ancestor_config));
    assert!(detected.contains(&home_config));
    assert!(!detected.contains(&owned_workspace_config));
    root.cleanup();
}

#[test]
fn helper_subprocess_environment_is_exactly_normalized() {
    let mut command = helper_command("/usr/bin/env");
    let output = run_output(&mut command, "normalized helper environment probe");
    let mut actual: Vec<_> = String::from_utf8(output.stdout)
        .expect("environment output is UTF-8")
        .lines()
        .map(str::to_owned)
        .collect();
    actual.sort();
    let mut expected = vec![
        "LANG=C".to_owned(),
        "LC_ALL=C".to_owned(),
        "PATH=/usr/bin:/bin".to_owned(),
        "SOURCE_DATE_EPOCH=0".to_owned(),
        "TZ=UTC".to_owned(),
    ];
    expected.sort();
    assert_eq!(actual, expected);
}

#[test]
fn clang_runtime_paths_are_derived_from_the_manifest_layout() {
    let identity = "clang_binary = \"bin/clang-22\"\n\
                    libclang_cpp = \"lib64/libclang-cpp.so.22.1\"\n\
                    host_llvm = \"lib64/libLLVM.so.22.1\"\n";
    let paths = clang_runtime_paths(identity, Path::new("/opt/llvm/bin/clang"));
    assert_eq!(paths.expected_clang, Path::new("/opt/llvm/bin/clang-22"));
    assert_eq!(
        paths.libclang_cpp,
        Path::new("/opt/llvm/lib64/libclang-cpp.so.22.1")
    );
    assert_eq!(
        paths.host_llvm,
        Path::new("/opt/llvm/lib64/libLLVM.so.22.1")
    );
}

#[allow(
    clippy::too_many_arguments,
    reason = "the evidence identity enumerates every independently supplied build and inspection tool plus the pinned Clang-library manifest"
)]
fn normalized_build_environment_sha256(
    cargo: &Path,
    rustc: &Path,
    rust_lld: &Path,
    clang: &Path,
    llvm_nm: &Path,
    llvm_objdump: &Path,
    llvm_readelf: &Path,
    build_tools_identity: &str,
) -> String {
    let mut record = String::from(
        "deepwyrm-c3-normalized-build-environment-v2\n\
         env_clear=true\n\
         PATH=/usr/bin:/bin\n\
         HOME=<owned-empty>\n\
         CARGO_HOME=<owned-empty>\n\
         CARGO_TARGET_DIR=<owned-per-build>\n\
         CARGO_NET_OFFLINE=true\n\
         CARGO_TERM_COLOR=never\n\
         LANG=C\n\
         LC_ALL=C\n\
         SOURCE_DATE_EPOCH=0\n\
         DEEPWYRM_GUEST_TEST_SELECTOR=<absent-or-exact-selector>\n\
         RUSTFLAGS=<absent-or-owned-ui-or-stack-mode>\n\
         RUSTC_BOOTSTRAP=<absent-or-owned-stack-mode>\n\
         clang_default_config=false\n\
         helper_env_clear=true\n\
         helper_PATH=/usr/bin:/bin\n\
         helper_LANG=C\n\
         helper_LC_ALL=C\n\
         helper_TZ=UTC\n\
         helper_SOURCE_DATE_EPOCH=0\n",
    );
    let clang_runtime = clang_runtime_paths(build_tools_identity, clang);
    for (name, path) in [
        ("cargo", cargo),
        ("rustc", rustc),
        ("rust-lld", rust_lld),
        ("clang", clang),
        ("libclang-cpp", clang_runtime.libclang_cpp.as_path()),
        ("host-llvm", clang_runtime.host_llvm.as_path()),
        ("llvm-nm", llvm_nm),
        ("llvm-objdump", llvm_objdump),
        ("llvm-readelf", llvm_readelf),
    ] {
        record.push_str(name);
        record.push('=');
        record.push_str(
            fs::canonicalize(path)
                .unwrap_or_else(|error| panic!("canonicalize {name}: {error}"))
                .to_str()
                .expect("tool path is UTF-8"),
        );
        record.push(' ');
        record.push_str(&sha256(path));
        record.push('\n');
    }
    sha256_bytes(record.as_bytes())
}

fn manifest_value(source: &str, key: &str) -> String {
    source
        .lines()
        .find_map(|line| {
            let (candidate, value) = line.split_once('=')?;
            (candidate.trim() == key).then(|| value.trim().trim_matches('"').to_owned())
        })
        .unwrap_or_else(|| panic!("trusted toolchain identity omitted {key}"))
}

fn required_path(name: &str) -> PathBuf {
    let path = PathBuf::from(env::var_os(name).unwrap_or_else(|| panic!("{name} is required")));
    assert!(
        path.is_absolute(),
        "{name} must be an absolute path: {}",
        path.display()
    );
    assert!(
        path.is_file(),
        "{name} does not name a file: {}",
        path.display()
    );
    path
}

fn build_kernel(
    workspace: &Path,
    target_dir: &Path,
    environment: &BuildEnvironment,
    tools: BuildTools<'_>,
    selector: Option<&str>,
) -> PathBuf {
    let mut command = Command::new(tools.cargo);
    environment.apply(&mut command, tools, target_dir);
    command.current_dir(workspace).args([
        "build",
        "--locked",
        "--package",
        "deepwyrm-kernel",
        "--bin",
        "deepwyrm-kernel",
        "--target",
        "x86_64-unknown-none",
    ]);
    if let Some(selector) = selector {
        command
            .env("DEEPWYRM_GUEST_TEST_SELECTOR", selector)
            .args(["--features", "test-support"]);
    }
    run_success(&mut command, selector.unwrap_or("production"));
    let artifact = target_dir.join("x86_64-unknown-none/debug/deepwyrm-kernel");
    assert!(
        artifact.is_file(),
        "kernel artifact is missing: {}",
        artifact.display()
    );
    artifact
}

fn validate_one_shot_ui(
    workspace: &Path,
    target_dir: &Path,
    environment: &BuildEnvironment,
    tools: BuildTools<'_>,
) {
    let mut command = Command::new(tools.cargo);
    environment.apply(&mut command, tools, target_dir);
    let output = command
        .current_dir(workspace)
        .env("RUSTFLAGS", "--cfg deepwyrm_c3_one_shot_ui")
        .env("DEEPWYRM_GUEST_TEST_SELECTOR", "memory-mapping")
        .args([
            "build",
            "--locked",
            "--package",
            "deepwyrm-kernel",
            "--bin",
            "deepwyrm-kernel",
            "--target",
            "x86_64-unknown-none",
            "--features",
            "test-support",
        ])
        .output()
        .expect("run one-shot target UI probe");
    assert!(
        !output.status.success(),
        "one-shot target UI probe unexpectedly duplicated the active session"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let first_error = stderr
        .lines()
        .find(|line| line.starts_with("error["))
        .unwrap_or_else(|| panic!("one-shot target UI probe emitted no compiler error:\n{stderr}"));
    assert_eq!(
        first_error, "error[E0382]: borrow of moved value: `active`",
        "one-shot target UI probe failed for an unexpected reason:\n{stderr}"
    );
}

fn build_stack_kernel(
    workspace: &Path,
    target_dir: &Path,
    environment: &BuildEnvironment,
    tools: BuildTools<'_>,
    selector: Option<&str>,
) -> PathBuf {
    let mut command = Command::new(tools.cargo);
    environment.apply(&mut command, tools, target_dir);
    command
        .current_dir(workspace)
        .env("RUSTFLAGS", "-Z emit-stack-sizes")
        .env("RUSTC_BOOTSTRAP", "1")
        .args([
            "build",
            "--locked",
            "--package",
            "deepwyrm-kernel",
            "--bin",
            "deepwyrm-kernel",
            "--target",
            "x86_64-unknown-none",
        ]);
    if let Some(selector) = selector {
        command
            .env("DEEPWYRM_GUEST_TEST_SELECTOR", selector)
            .args(["--features", "test-support"]);
    }
    let identity = selector.unwrap_or("production");
    run_success(&mut command, &format!("{identity} stack-size build"));
    let artifact = target_dir.join("x86_64-unknown-none/debug/deepwyrm-kernel");
    assert!(
        artifact.is_file(),
        "stack-size kernel artifact is missing: {}",
        artifact.display()
    );
    artifact
}

#[derive(Clone, Debug)]
struct StackSize {
    bytes: usize,
    symbol: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuditedStackFrame {
    name: &'static str,
    bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuditedStackPathError {
    DuplicateEntry(&'static str),
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuditedStackPath {
    bytes: usize,
    frame_count: usize,
}

fn audited_stack_path(
    segments: &[&[AuditedStackFrame]],
) -> Result<AuditedStackPath, AuditedStackPathError> {
    let mut seen = BTreeSet::new();
    let mut total = 0_usize;
    for segment in segments {
        for frame in *segment {
            if !seen.insert(frame.name) {
                return Err(AuditedStackPathError::DuplicateEntry(frame.name));
            }
            total = total
                .checked_add(frame.bytes)
                .ok_or(AuditedStackPathError::Overflow)?;
        }
    }
    Ok(AuditedStackPath {
        bytes: total,
        frame_count: seen.len(),
    })
}

fn audited_stack_path_bytes(
    segments: &[&[AuditedStackFrame]],
) -> Result<usize, AuditedStackPathError> {
    audited_stack_path(segments).map(|path| path.bytes)
}

fn audited_stack_upper_bound(paths: &[AuditedStackPath]) -> AuditedStackPath {
    paths.iter().copied().fold(
        AuditedStackPath {
            bytes: 0,
            frame_count: 0,
        },
        |bound, path| AuditedStackPath {
            bytes: bound.bytes.max(path.bytes),
            frame_count: bound.frame_count.max(path.frame_count),
        },
    )
}

fn ist_padding_branch(
    write_char: usize,
    encode_utf8_raw: usize,
    precondition_check: usize,
    is_aligned_to: usize,
) -> [AuditedStackFrame; 4] {
    [
        AuditedStackFrame {
            name: "ist-padding-write-char",
            bytes: write_char,
        },
        AuditedStackFrame {
            name: "ist-padding-encode-utf8-raw",
            bytes: encode_utf8_raw,
        },
        AuditedStackFrame {
            name: "ist-padding-precondition-check",
            bytes: precondition_check,
        },
        AuditedStackFrame {
            name: "ist-padding-is-aligned-to",
            bytes: is_aligned_to,
        },
    ]
}

#[test]
fn audited_stack_manifest_rejects_duplicate_entries_and_overflow() {
    assert_eq!(
        audited_stack_path_bytes(&[&[
            AuditedStackFrame {
                name: "caller",
                bytes: 16,
            },
            AuditedStackFrame {
                name: "callee",
                bytes: 32,
            },
            AuditedStackFrame {
                name: "caller",
                bytes: 16,
            },
        ]]),
        Err(AuditedStackPathError::DuplicateEntry("caller"))
    );
    assert_eq!(
        audited_stack_path_bytes(&[&[
            AuditedStackFrame {
                name: "caller",
                bytes: usize::MAX,
            },
            AuditedStackFrame {
                name: "callee",
                bytes: 1,
            },
        ]]),
        Err(AuditedStackPathError::Overflow)
    );
}

#[test]
fn ist_padding_branch_participates_in_the_maximum_stack_bound() {
    let ordinary = audited_stack_path(&[&[
        AuditedStackFrame {
            name: "pad-integral",
            bytes: 64,
        },
        AuditedStackFrame {
            name: "write-prefix",
            bytes: 32,
        },
    ]])
    .unwrap();
    let padding_branch = ist_padding_branch(72, 72, 120, 56);
    assert_eq!(
        padding_branch.map(|frame| frame.name),
        [
            "ist-padding-write-char",
            "ist-padding-encode-utf8-raw",
            "ist-padding-precondition-check",
            "ist-padding-is-aligned-to",
        ]
    );
    let padding_prefix = [AuditedStackFrame {
        name: "pad-integral",
        bytes: 64,
    }];
    let padding = audited_stack_path(&[&padding_prefix, &padding_branch]).unwrap();

    assert_eq!(audited_stack_upper_bound(&[ordinary, padding]), padding);
}

fn stack_sizes(llvm_readelf: &Path, artifact: &Path) -> Vec<StackSize> {
    let mut command = helper_command(llvm_readelf);
    let output = run_output(
        command.args(["--demangle", "--stack-sizes"]).arg(artifact),
        "llvm-readelf stack sizes",
    );
    let stdout = String::from_utf8(output.stdout).expect("llvm-readelf output is UTF-8");
    let mut sizes = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        let Some(separator) = trimmed.find(char::is_whitespace) else {
            continue;
        };
        let Ok(bytes) = trimmed[..separator].parse::<usize>() else {
            continue;
        };
        let symbol = trimmed[separator..].trim();
        if !symbol.is_empty() {
            sizes.push(StackSize {
                bytes,
                symbol: symbol.to_owned(),
            });
        }
    }
    assert!(
        !sizes.is_empty(),
        "target artifact omitted .stack_sizes data"
    );
    sizes
}

fn one_stack_size(
    sizes: &[StackSize],
    description: &str,
    predicate: impl Fn(&str) -> bool,
) -> usize {
    let matches: Vec<_> = sizes
        .iter()
        .filter(|entry| predicate(&entry.symbol))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected one {description} stack-size entry, found: {matches:?}"
    );
    matches[0].bytes
}

fn validate_selector_stack_margin(selector: &str, sizes: &[StackSize], disassembly: &str) {
    const BOOT_STACK_BYTES: usize = 128 * 1024;
    const REQUIRED_SPARE_BYTES: usize = 32 * 1024;
    const ARCHITECTURAL_HEADROOM_BYTES: usize = 4 * 1024;
    const RETURN_ADDRESS_COUNT: usize = 32;
    const RETURN_ADDRESS_BYTES: usize = RETURN_ADDRESS_COUNT * size_of::<u64>();
    // Page-fault hardware pushes RIP, CS, RFLAGS, and the error word. The
    // vector stub and common entry then retain 16 GPR/CR2 words and may discard
    // one alignment word before calling Rust. Function-call return addresses
    // remain covered by RETURN_ADDRESS_BYTES above.
    const PAGE_FAULT_ENTRY_BYTES: usize = (4 + 1 + 16 + 1) * size_of::<u64>();

    let exact = |name: &str| one_stack_size(sizes, name, |symbol| symbol == name);
    let contains_plain = |description: &str, needle: &str| {
        one_stack_size(sizes, description, |symbol| {
            symbol.contains(needle) && !symbol.contains("::{closure")
        })
    };
    let suffix = |description: &str, ending: &str| {
        one_stack_size(sizes, description, |symbol| symbol.ends_with(ending))
    };
    let frame = |name: &'static str, bytes: usize| AuditedStackFrame { name, bytes };

    let kernel_main = exact("deepwyrm_kernel::kernel_main");
    let memory_guest_runner = suffix(
        "memory guest runner",
        "deepwyrm_kernel::test_support::memory::run_memory_guest_test::<128, 544>",
    );
    let memory_foundation_runner =
        contains_plain("memory foundation runner", ">::run_memory_foundation_test");
    let mapped_case_runner = contains_plain("mapped-case runner", ">::run_mapped_case");
    let retained_runner = [
        AuditedStackFrame {
            name: "kernel-main",
            bytes: kernel_main,
        },
        AuditedStackFrame {
            name: "memory-guest-runner",
            bytes: memory_guest_runner,
        },
        AuditedStackFrame {
            name: "memory-foundation-runner",
            bytes: memory_foundation_runner,
        },
        AuditedStackFrame {
            name: "mapped-case-runner",
            bytes: mapped_case_runner,
        },
    ];
    let mapped_case_closure = suffix(
        "mapped-case common closure",
        ">::run_mapped_case::{closure#8}",
    );
    let mapped_case_common = [AuditedStackFrame {
        name: "mapped-case-common",
        bytes: mapped_case_closure,
    }];

    let (branch_name, branch) = match selector {
        "memory-mapping" => (
            "mapping-selector",
            suffix(
                "mapping selector closure",
                ">::run_mapped_case::{closure#8}::{closure#2}",
            ),
        ),
        "memory-unmapping" => (
            "unmapping-selector",
            suffix(
                "unmapping selector closure",
                ">::run_mapped_case::{closure#8}::{closure#3}",
            ),
        ),
        "memory-permissions" => (
            "permissions-selector",
            suffix(
                "permissions selector closure",
                ">::run_mapped_case::{closure#8}::{closure#4}",
            ),
        ),
        "memory-invalid-pointer" => (
            "invalid-pointer-selector",
            suffix(
                "invalid-pointer selector closure",
                ">::run_mapped_case::{closure#8}::{closure#5}",
            ),
        ),
        "memory-user-kernel-isolation" => (
            "isolation-selector",
            suffix(
                "isolation selector closure",
                ">::run_mapped_case::{closure#8}::{closure#6}",
            ),
        ),
        "memory-shared-memory-object" => (
            "shared-object-selector",
            suffix(
                "shared-object selector closure",
                ">::run_mapped_case::{closure#8}::{closure#7}",
            ),
        ),
        _ => panic!("unknown memory selector {selector}"),
    };
    let selector_branch = [AuditedStackFrame {
        name: branch_name,
        bytes: branch,
    }];

    let map = contains_plain("AddressRegion::map", "AddressRegion<2>>::map::<1, 2,");
    let unmap = contains_plain("AddressRegion::unmap", "AddressRegion<2>>::unmap::<1, 2,");
    let protect = contains_plain(
        "AddressRegion::protect",
        "AddressRegion<2>>::protect::<1, 2,",
    );
    let rebuild = contains_plain(
        "AddressRegion::rebuild",
        "AddressRegion<2>>::rebuild::<1, 2,",
    );
    let commit_specs = contains_plain(
        "AddressRegion::commit_specs",
        "AddressRegion<2>>::commit_specs::<1, 2,",
    );
    let prepare_replace = contains_plain(
        "MemoryObjectAuthority::prepare_replace",
        "MemoryObjectAuthority<1, 2>>::prepare_replace::<2>",
    );
    let prepare_object_slot = contains_plain(
        "MemoryObjectAuthority::object_slot",
        "MemoryObjectAuthority<1, 2>>::object_slot",
    );
    let prepare_lease_slot = contains_plain(
        "MemoryObjectAuthority::lease_slot",
        "MemoryObjectAuthority<1, 2>>::lease_slot",
    );
    let prepare_object_range = exact("deepwyrm_kernel::memory::vm::object::object_range");
    let prepare_next_generation = exact("deepwyrm_kernel::memory::vm::object::next_generation");
    let prepared_tickets = contains_plain(
        "PreparedReplace::tickets",
        "PreparedReplace<1, 2, 2>>::tickets",
    );
    let prepared_commit = contains_plain(
        "PreparedReplace::commit",
        "PreparedReplace<1, 2, 2>>::commit",
    );
    let publish_replace = suffix(
        "AddressSpacePublisher::publish_replace",
        " as deepwyrm_kernel::memory::vm::address_region::AddressSpacePublisher>::publish_replace",
    );
    let publish_pages = suffix(
        "X86AddressSpacePublisher::publish_pages",
        ">::publish_pages",
    );
    let publish_page = contains_plain("journal publish_page", "journal::publish_page::<");
    let map_page = contains_plain("PageTableRoot::map_page", "PageTableRoot>::map_page::<");
    let mm_commit = contains_plain(
        "page-table commit bridge",
        "deepwyrm_kernel::arch::x86_64::mm::commit::<",
    );
    let owned_commit = one_stack_size(sizes, "owned journal transaction commit", |symbol| {
        symbol.contains("OwnedPageTableJournal<")
            && symbol
                .ends_with(" as deepwyrm_kernel::arch::x86_64::mm::PageTableTransaction>::commit")
    });
    let validate_plan = contains_plain("owned journal validate_plan", ">::validate_plan");
    let table_reference = contains_plain("owned journal table_reference", ">::table_reference");
    let table_identity = suffix("frame-role table_identity", ">::table_identity");
    let journal_commit = one_stack_size(sizes, "page-table journal transaction commit", |symbol| {
        symbol.contains("PageTableJournal<")
            && !symbol.contains("OwnedPageTableJournal")
            && symbol
                .ends_with(" as deepwyrm_kernel::arch::x86_64::mm::PageTableTransaction>::commit")
    });
    let stage_plan = suffix("PageTableJournal::stage_plan", ">::stage_plan");
    let stage_plan_inner = suffix("PageTableJournal::stage_plan_inner", ">::stage_plan_inner");
    let stage_mutation = suffix("PageTableJournal::stage_mutation", ">::stage_mutation");
    let logical_entry = suffix("PageTableJournal::logical_entry", ">::logical_entry");
    let target_read = contains_plain(
        "active scratch read",
        "ActiveScratchTarget<deepwyrm_kernel::arch::x86_64::mm::transition::activation::LiveActiveScratchIo>>::read_location",
    );
    let target_validate = contains_plain(
        "active scratch location validation",
        "ActiveScratchTarget<deepwyrm_kernel::arch::x86_64::mm::transition::activation::LiveActiveScratchIo>>::validate_location",
    );
    let target_access = contains_plain(
        "active scratch frame access",
        "ActiveScratchTarget<deepwyrm_kernel::arch::x86_64::mm::transition::activation::LiveActiveScratchIo>>::access_frame_entry",
    );
    let target_restore = suffix("active scratch restore", ">::restore_scratch_mapping");
    let backend_load = suffix(
        "active scratch backend load",
        " as deepwyrm_kernel::arch::x86_64::mm::transition::activation::ActiveScratchIo>::load",
    );
    let backend_cas = suffix(
        "active scratch backend compare_exchange",
        " as deepwyrm_kernel::arch::x86_64::mm::transition::activation::ActiveScratchIo>::compare_exchange",
    );
    let owned_publish = one_stack_size(sizes, "owned journal publish", |symbol| {
        symbol.contains(
            "OwnedPageTableJournal<deepwyrm_kernel::arch::x86_64::mm::transition::activation::ActiveScratchTarget",
        ) && symbol.ends_with(">::publish")
    });
    let journal_publish = one_stack_size(sizes, "page-table journal publish", |symbol| {
        symbol.contains("PageTableJournal<")
            && !symbol.contains("OwnedPageTableJournal")
            && symbol.ends_with(">::publish")
    });
    let target_apply = suffix(
        "active scratch target apply",
        " as deepwyrm_kernel::arch::x86_64::mm::journal::AtomicPageTableTarget>::apply",
    );
    let target_write = contains_plain(
        "active scratch write",
        "ActiveScratchTarget<deepwyrm_kernel::arch::x86_64::mm::transition::activation::LiveActiveScratchIo>>::write_location",
    );
    let role_stage = suffix("frame-role staged commit", ">::stage_table_commit");
    let role_validate = suffix("frame-role table validation", ">::validate_table_identity");
    let role_record = suffix("frame-role record lookup", ">::record");
    let copy_from_user = contains_plain("copy_from_user", "usercopy::copy_from_user::<");
    let usercopy_preflight = contains_plain("usercopy preflight_all", "usercopy::preflight_all::<");
    let active_user_preflight = suffix(
        "active user-page preflight",
        " as deepwyrm_kernel::memory::usercopy::PinnedUserPages>::preflight",
    );
    let walk_leaf = contains_plain(
        "active-root walk_leaf",
        "ActiveRootTestAuthority<128, 544>>::walk_leaf",
    );

    let initial_map = [
        frame("address-region-map", map),
        frame("address-region-commit-specs", commit_specs),
    ];
    let unmap_operation = [
        frame("address-region-unmap", unmap),
        frame("address-region-rebuild", rebuild),
        frame("address-region-commit-specs", commit_specs),
    ];
    let protect_operation = [
        frame("address-region-protect", protect),
        frame("address-region-rebuild", rebuild),
        frame("address-region-commit-specs", commit_specs),
    ];
    let operation_paths: Vec<&[AuditedStackFrame]> = match selector {
        "memory-mapping" | "memory-user-kernel-isolation" => vec![&initial_map],
        "memory-unmapping" | "memory-shared-memory-object" => {
            vec![&initial_map, &unmap_operation]
        }
        "memory-permissions" | "memory-invalid-pointer" => {
            vec![&initial_map, &protect_operation]
        }
        _ => unreachable!("selector validated above"),
    };

    let prepare_object = [
        frame("prepare-replace", prepare_replace),
        frame("prepare-object-slot", prepare_object_slot),
    ];
    let prepare_lease = [
        frame("prepare-replace", prepare_replace),
        frame("prepare-lease-slot", prepare_lease_slot),
    ];
    let prepare_range = [
        frame("prepare-replace", prepare_replace),
        frame("prepare-object-range", prepare_object_range),
    ];
    let prepare_generation = [
        frame("prepare-replace", prepare_replace),
        frame("prepare-next-generation", prepare_next_generation),
    ];
    let inspect_prepared_tickets = [frame("prepared-tickets", prepared_tickets)];
    let publish_prefix = [
        frame("address-space-publish-replace", publish_replace),
        frame("x86-publish-pages", publish_pages),
    ];
    let validate_publication = [
        frame("journal-publish-page", publish_page),
        frame("page-table-map-page", map_page),
        frame("page-table-commit-bridge", mm_commit),
        frame("owned-journal-commit", owned_commit),
        frame("owned-journal-validate-plan", validate_plan),
        frame("owned-journal-table-reference", table_reference),
        frame("frame-role-table-identity", table_identity),
    ];
    let stage_common = [
        frame("journal-publish-page", publish_page),
        frame("page-table-map-page", map_page),
        frame("page-table-commit-bridge", mm_commit),
        frame("owned-journal-commit", owned_commit),
        frame("journal-commit", journal_commit),
        frame("journal-stage-plan", stage_plan),
        frame("journal-stage-plan-inner", stage_plan_inner),
        frame("journal-stage-mutation", stage_mutation),
        frame("journal-logical-entry", logical_entry),
        frame("active-scratch-read", target_read),
        frame("active-scratch-validate", target_validate),
        frame("active-scratch-access", target_access),
    ];
    let scratch_restore = [
        frame("active-scratch-restore", target_restore),
        frame("active-scratch-backend-cas", backend_cas),
    ];
    let scratch_load = [frame("active-scratch-backend-load", backend_load)];
    let apply_write = [
        frame("owned-journal-publish", owned_publish),
        frame("journal-publish", journal_publish),
        frame("active-target-apply", target_apply),
        frame("active-scratch-write", target_write),
        frame("active-scratch-validate", target_validate),
        frame("active-scratch-access", target_access),
        frame("active-scratch-restore", target_restore),
        frame("active-scratch-backend-cas", backend_cas),
    ];
    let apply_read = [
        frame("owned-journal-publish", owned_publish),
        frame("journal-publish", journal_publish),
        frame("active-target-apply", target_apply),
        frame("active-scratch-read", target_read),
        frame("active-scratch-validate", target_validate),
        frame("active-scratch-access", target_access),
        frame("active-scratch-restore", target_restore),
        frame("active-scratch-backend-cas", backend_cas),
    ];
    let publish_roles = [
        frame("owned-journal-publish", owned_publish),
        frame("frame-role-stage-table-commit", role_stage),
        frame("frame-role-validate-table-identity", role_validate),
        frame("frame-role-record", role_record),
    ];
    let finish_prepared = [frame("prepared-replace-commit", prepared_commit)];

    let transaction_paths: Vec<Vec<&[AuditedStackFrame]>> = vec![
        vec![&prepare_object],
        vec![&prepare_lease],
        vec![&prepare_range],
        vec![&prepare_generation],
        vec![&inspect_prepared_tickets],
        vec![&publish_prefix, &validate_publication],
        vec![&publish_prefix, &stage_common, &scratch_restore],
        vec![&publish_prefix, &stage_common, &scratch_load],
        vec![&publish_prefix, &apply_write],
        vec![&publish_prefix, &apply_read],
        vec![&publish_prefix, &publish_roles],
        vec![&finish_prepared],
    ];
    let mut publication_chain = 0;
    for operation in operation_paths {
        for descendant in &transaction_paths {
            let mut segments = vec![
                retained_runner.as_slice(),
                mapped_case_common.as_slice(),
                selector_branch.as_slice(),
                operation,
            ];
            segments.extend(descendant.iter().copied());
            let measured = audited_stack_path_bytes(&segments).unwrap_or_else(|error| {
                panic!("{selector} publication stack manifest is invalid: {error:?}")
            });
            publication_chain = publication_chain.max(measured);
        }
    }

    let usercopy_common = [
        frame("copy-from-user", copy_from_user),
        frame("usercopy-preflight-all", usercopy_preflight),
        frame("active-user-page-preflight", active_user_preflight),
        frame("active-root-walk-leaf", walk_leaf),
        frame("active-scratch-read", target_read),
        frame("active-scratch-validate", target_validate),
        frame("active-scratch-access", target_access),
    ];
    for scratch_tail in [&scratch_restore[..], &scratch_load[..]] {
        let usercopy = audited_stack_path_bytes(&[
            &retained_runner,
            &mapped_case_common,
            &selector_branch,
            &usercopy_common,
            scratch_tail,
        ])
        .unwrap_or_else(|error| panic!("{selector} usercopy stack manifest is invalid: {error:?}"));
        publication_chain = publication_chain.max(usercopy);
    }

    let complete_pass = exact("deepwyrm_kernel::test_support::x86_64::complete_pass");
    let complete_known = exact("deepwyrm_kernel::test_support::x86_64::complete_known_outcome");
    let complete = contains_plain(
        "terminal completion",
        "test_support::transport::complete::<",
    );
    let emit_completion = contains_plain(
        "completion emission",
        "test_support::transport::emit_completion::<",
    );
    let serial_record = suffix(
        "QEMU completion serial write",
        " as deepwyrm_kernel::test_support::transport::CompletionTransport>::write_serial_record",
    );
    let emit_raw = exact("deepwyrm_kernel::debug::emit_early_raw_record");
    let bounded_raw = contains_plain("bounded raw record", "debug::write_bounded_raw_record::<");
    let raw_bytes = suffix("COM1 raw bytes", ">::write_raw_bytes");
    let hardware_byte = suffix("COM1 hardware byte", ">::write_hardware_byte");
    let port_read = suffix(
        "COM1 port read",
        " as deepwyrm_kernel::debug::PortIo>::read_u8",
    );
    let completion_path = [
        frame("complete-pass", complete_pass),
        frame("complete-known-outcome", complete_known),
        frame("completion-transport", complete),
        frame("emit-completion", emit_completion),
        frame("completion-serial-record", serial_record),
        frame("emit-early-raw-record", emit_raw),
        frame("bounded-raw-record", bounded_raw),
        frame("com1-raw-bytes", raw_bytes),
        frame("com1-hardware-byte", hardware_byte),
        frame("com1-port-read", port_read),
    ];
    let normal_terminal_chain = audited_stack_path_bytes(&[&retained_runner, &completion_path])
        .unwrap_or_else(|error| {
            panic!("{selector} normal-terminal stack manifest is invalid: {error:?}")
        });

    let expect_fault = exact("deepwyrm_kernel::test_support::x86_64::expect_terminal_page_fault");
    let arm_fault = exact("deepwyrm_kernel::test_support::x86_64::arm_expected_page_fault");
    let exception_dispatch = exact("dw_x86_64_exception_dispatch");
    let report_exception = contains_plain(
        "early exception report",
        "arch::x86_64::exceptions::report_early_exception::<",
    );
    let exception_reporter = suffix(
        "serial early exception reporter",
        " as deepwyrm_kernel::arch::x86_64::exceptions::EarlyExceptionReporter>::report_and_halt",
    );
    let emit_panic = exact("deepwyrm_kernel::debug::emit_early_panic_record");
    let panic_record = contains_plain("panic record emission", "debug::emit_panic_record::<");
    let render_panic = contains_plain("panic record rendering", "debug::render_panic_record::<");
    let write_limited = contains_plain("bounded panic field", "debug::write_limited::<");
    let formatted_bytes = suffix("COM1 formatted bytes", ">::write_bytes");
    let panic_serial_path = [
        frame("emit-early-panic-record", emit_panic),
        frame("emit-panic-record", panic_record),
        frame("render-panic-record", render_panic),
        frame("write-limited", write_limited),
        frame("com1-formatted-bytes", formatted_bytes),
        frame("com1-hardware-byte", hardware_byte),
        frame("com1-port-read", port_read),
    ];
    let complete_exception = exact("deepwyrm_kernel::test_support::x86_64::complete_exception");
    let live_fault_match =
        exact("deepwyrm_kernel::test_support::x86_64::live_expected_page_fault_matches");
    let expected_fault_match =
        exact("deepwyrm_kernel::test_support::identity::expected_page_fault_matches");
    let fault_handler_prefix = [
        frame("exception-dispatch", exception_dispatch),
        frame("report-early-exception", report_exception),
        frame("serial-exception-reporter", exception_reporter),
    ];
    let expected_fault_classification = [
        frame("complete-exception", complete_exception),
        frame("live-expected-page-fault-match", live_fault_match),
        frame("expected-page-fault-match", expected_fault_match),
    ];
    let fault_entry = [frame(
        "x86-page-fault-entry-snapshot",
        PAGE_FAULT_ENTRY_BYTES,
    )];
    let fault_expectation = [frame("expect-terminal-page-fault", expect_fault)];
    let fault_arming = [frame("arm-expected-page-fault", arm_fault)];
    let fault_terminal_chain = if matches!(selector, "memory-unmapping" | "memory-permissions") {
        let arming_chain = audited_stack_path_bytes(&[
            &retained_runner,
            &mapped_case_common,
            &selector_branch,
            &fault_expectation,
            &fault_arming,
        ])
        .unwrap_or_else(|error| {
            panic!("{selector} fault-arming stack manifest is invalid: {error:?}")
        });
        let delivered_panic = audited_stack_path_bytes(&[
            &retained_runner,
            &mapped_case_common,
            &selector_branch,
            &fault_expectation,
            &fault_entry,
            &fault_handler_prefix,
            &panic_serial_path,
        ])
        .unwrap_or_else(|error| {
            panic!("{selector} #PF panic stack manifest is invalid: {error:?}")
        });
        let delivered_completion = audited_stack_path_bytes(&[
            &retained_runner,
            &mapped_case_common,
            &selector_branch,
            &fault_expectation,
            &fault_entry,
            &fault_handler_prefix,
            &expected_fault_classification,
            &completion_path,
        ])
        .unwrap_or_else(|error| {
            panic!("{selector} #PF completion stack manifest is invalid: {error:?}")
        });
        arming_chain.max(delivered_panic).max(delivered_completion)
    } else {
        0
    };

    let measured_chain = publication_chain
        .max(normal_terminal_chain)
        .max(fault_terminal_chain);
    let total = measured_chain + RETURN_ADDRESS_BYTES + ARCHITECTURAL_HEADROOM_BYTES;
    assert!(
        total <= BOOT_STACK_BYTES,
        "{selector} target stack bound exceeds the boot stack: measured chain {measured_chain}, \
         return addresses {RETURN_ADDRESS_BYTES}, required architectural headroom \
         {ARCHITECTURAL_HEADROOM_BYTES}, total {total}, boot stack {BOOT_STACK_BYTES}"
    );
    assert!(
        BOOT_STACK_BYTES - total >= REQUIRED_SPARE_BYTES,
        "{selector} target stack bound leaves less than the required {REQUIRED_SPARE_BYTES}-byte \
         spare: total {total}, boot stack {BOOT_STACK_BYTES}"
    );
    eprintln!(
        "{selector} stack publication={publication_chain} normal-terminal={normal_terminal_chain} \
         fault-terminal={fault_terminal_chain} measured={measured_chain} \
         returns={RETURN_ADDRESS_BYTES} headroom={ARCHITECTURAL_HEADROOM_BYTES} \
         total={total} spare={}",
        BOOT_STACK_BYTES - total
    );
    validate_ist_stack_margin(selector, sizes, disassembly);
}

fn validate_ist_stack_margin(selector: &str, sizes: &[StackSize], disassembly: &str) {
    const IST_STACK_BYTES: usize = 16 * 1024;
    const REQUIRED_SPARE_BYTES: usize = 4 * 1024;
    // An IST transition retains old SS/RSP, RFLAGS, CS, and RIP. Hardware or
    // the vector stub then supplies two error/vector words, the common entry
    // retains sixteen GPR/CR2 words, stack alignment may consume 15 bytes,
    // and the explicit assembly-to-Rust call pushes one return address. Rust
    // call return addresses are derived below from the deepest enumerated
    // non-inlined path rather than represented by a fixed allowance.
    const IST_ENTRY_BYTES: usize = (5 + 2 + 16) * size_of::<u64>() + 15 + size_of::<u64>();

    let exact = |name: &str| one_stack_size(sizes, name, |symbol| symbol == name);
    let contains_plain = |description: &str, needle: &str| {
        one_stack_size(sizes, description, |symbol| {
            symbol.contains(needle) && !symbol.contains("::{closure")
        })
    };
    let suffix = |description: &str, ending: &str| {
        one_stack_size(sizes, description, |symbol| symbol.ends_with(ending))
    };
    let frame = |name: &'static str, bytes: usize| AuditedStackFrame { name, bytes };

    let handler_prefix = [
        frame(
            "ist-exception-dispatch",
            exact("dw_x86_64_exception_dispatch"),
        ),
        frame(
            "ist-report-early-exception",
            contains_plain(
                "IST early exception report",
                "arch::x86_64::exceptions::report_early_exception::<",
            ),
        ),
        frame(
            "ist-serial-exception-reporter",
            suffix(
                "IST serial early exception reporter",
                " as deepwyrm_kernel::arch::x86_64::exceptions::EarlyExceptionReporter>::report_and_halt",
            ),
        ),
    ];
    let hardware_byte = suffix("IST COM1 hardware byte", ">::write_hardware_byte");
    let port_read = suffix(
        "IST COM1 port read",
        " as deepwyrm_kernel::debug::PortIo>::read_u8",
    );
    let output_guard = exact("<deepwyrm_kernel::debug::OutputGuard>::acquire");
    let panic_common = [
        frame(
            "ist-emit-early-panic-record",
            exact("deepwyrm_kernel::debug::emit_early_panic_record"),
        ),
        frame(
            "ist-emit-panic-record",
            contains_plain("IST panic record emission", "debug::emit_panic_record::<"),
        ),
        frame(
            "ist-render-panic-record",
            contains_plain(
                "IST panic record rendering",
                "debug::render_panic_record::<",
            ),
        ),
        frame("ist-panic-output-guard", output_guard),
    ];
    let panic_bounded_text = [
        frame(
            "ist-write-limited",
            contains_plain("IST bounded panic field", "debug::write_limited::<"),
        ),
        frame(
            "ist-com1-formatted-bytes",
            suffix("IST COM1 formatted bytes", ">::write_bytes"),
        ),
        frame("ist-com1-hardware-byte", hardware_byte),
        frame("ist-com1-port-read", port_read),
    ];
    let fmt_write = exact(
        "<deepwyrm_kernel::debug::Com1<deepwyrm_kernel::debug::X86PortIo> as core::fmt::Write>::write_fmt",
    );
    let fmt_spec = exact(
        "<&mut deepwyrm_kernel::debug::Com1<deepwyrm_kernel::debug::X86PortIo> as core::fmt::Write::write_fmt::SpecWriteFmt>::spec_write_fmt",
    );
    let fmt_write_str = exact(
        "<deepwyrm_kernel::debug::Com1<deepwyrm_kernel::debug::X86PortIo> as core::fmt::Write>::write_str",
    );
    let fmt_arguments = fixed_x86_64_stack_frame(
        disassembly,
        "<core::fmt::Arguments>::as_statically_known_str",
    );
    let fmt_core_write = fixed_x86_64_stack_frame(disassembly, "core::fmt::write");
    let fmt_display_u32 = fixed_x86_64_stack_frame(disassembly, "<u32 as core::fmt::Display>::fmt");
    let fmt_lower_hex_u64 =
        fixed_x86_64_stack_frame(disassembly, "<u64 as core::fmt::LowerHex>::fmt");
    let fmt_pad_integral =
        fixed_x86_64_stack_frame(disassembly, "<core::fmt::Formatter>::pad_integral");
    let fmt_write_prefix = fixed_x86_64_stack_frame(
        disassembly,
        "<core::fmt::Formatter>::pad_integral::write_prefix",
    );
    let fmt_padding_branch = ist_padding_branch(
        exact(
            "<deepwyrm_kernel::debug::Com1<deepwyrm_kernel::debug::X86PortIo> as core::fmt::Write>::write_char",
        ),
        exact("core::char::methods::encode_utf8_raw"),
        exact("core::slice::raw::from_raw_parts_mut::precondition_check"),
        exact("<*const ()>::is_aligned_to"),
    );
    let panic_optional_u32_argument = [
        frame(
            "ist-write-optional-u32-argument",
            contains_plain("IST optional u32 rendering", "debug::write_optional_u32::<"),
        ),
        frame(
            "ist-u32-display-argument",
            exact("<core::fmt::rt::Argument>::new_display::<u32>"),
        ),
    ];
    let panic_optional_u32 = [
        frame(
            "ist-write-optional-u32",
            contains_plain("IST optional u32 rendering", "debug::write_optional_u32::<"),
        ),
        frame("ist-com1-write-fmt-u32", fmt_write),
        frame("ist-com1-spec-write-fmt-u32", fmt_spec),
        frame("ist-fmt-arguments-u32", fmt_arguments),
        frame("ist-core-fmt-write-u32", fmt_core_write),
        frame("ist-u32-display", fmt_display_u32),
        frame("ist-u32-pad-integral", fmt_pad_integral),
        frame("ist-u32-write-prefix", fmt_write_prefix),
        frame("ist-com1-write-str-u32", fmt_write_str),
        frame(
            "ist-com1-formatted-u32-bytes",
            suffix("IST COM1 formatted u32 bytes", ">::write_bytes"),
        ),
        frame("ist-com1-u32-hardware-byte", hardware_byte),
        frame("ist-com1-u32-port-read", port_read),
    ];
    let panic_address_argument = [
        frame(
            "ist-write-address-argument",
            contains_plain("IST address rendering", "debug::write_address::<"),
        ),
        frame(
            "ist-u64-lower-hex-argument",
            exact("<core::fmt::rt::Argument>::new_lower_hex::<u64>"),
        ),
    ];
    let panic_address = [
        frame(
            "ist-write-address",
            contains_plain("IST address rendering", "debug::write_address::<"),
        ),
        frame("ist-com1-write-fmt-address", fmt_write),
        frame("ist-com1-spec-write-fmt-address", fmt_spec),
        frame("ist-fmt-arguments-address", fmt_arguments),
        frame("ist-core-fmt-write-address", fmt_core_write),
        frame("ist-u64-lower-hex", fmt_lower_hex_u64),
        frame("ist-address-pad-integral", fmt_pad_integral),
        frame("ist-address-write-prefix", fmt_write_prefix),
        frame("ist-com1-write-str-address", fmt_write_str),
        frame(
            "ist-com1-formatted-address-bytes",
            suffix("IST COM1 formatted address bytes", ">::write_bytes"),
        ),
        frame("ist-com1-address-hardware-byte", hardware_byte),
        frame("ist-com1-address-port-read", port_read),
    ];
    let panic_address_padding = [
        frame(
            "ist-write-address-padding",
            contains_plain("IST address rendering", "debug::write_address::<"),
        ),
        frame("ist-com1-write-fmt-address-padding", fmt_write),
        frame("ist-com1-spec-write-fmt-address-padding", fmt_spec),
        frame("ist-fmt-arguments-address-padding", fmt_arguments),
        frame("ist-core-fmt-write-address-padding", fmt_core_write),
        frame("ist-u64-lower-hex-padding", fmt_lower_hex_u64),
        frame("ist-address-pad-integral-padding", fmt_pad_integral),
    ];
    let completion_common = [
        frame(
            "ist-complete-exception",
            exact("deepwyrm_kernel::test_support::x86_64::complete_exception"),
        ),
        frame(
            "ist-exception-outcome",
            exact("deepwyrm_kernel::test_support::identity::exception_outcome"),
        ),
        frame(
            "ist-exception-outcome-for",
            exact("deepwyrm_kernel::test_support::identity::exception_outcome_for"),
        ),
        frame(
            "ist-complete-panic",
            exact("deepwyrm_kernel::test_support::x86_64::complete_panic"),
        ),
        frame(
            "ist-complete-known-outcome",
            exact("deepwyrm_kernel::test_support::x86_64::complete_known_outcome"),
        ),
        frame(
            "ist-completion-record",
            exact("deepwyrm_kernel::test_support::identity::completion_record"),
        ),
        frame(
            "ist-completion-transport",
            contains_plain(
                "IST terminal completion",
                "test_support::transport::complete::<",
            ),
        ),
        frame(
            "ist-emit-completion",
            contains_plain(
                "IST completion emission",
                "test_support::transport::emit_completion::<",
            ),
        ),
    ];
    let completion_encode_hex = [
        frame(
            "ist-completion-record-encode-hex",
            exact("<deepwyrm_kernel::test_support::protocol::CompletionRecord>::encode"),
        ),
        frame(
            "ist-completion-encode-hex",
            exact("deepwyrm_kernel::test_support::protocol::encode_hex"),
        ),
    ];
    let completion_checksum = [
        frame(
            "ist-completion-record-encode-checksum",
            exact("<deepwyrm_kernel::test_support::protocol::CompletionRecord>::encode"),
        ),
        frame(
            "ist-completion-checksum",
            exact("deepwyrm_kernel::test_support::protocol::fnv1a32"),
        ),
        frame(
            "ist-completion-checksum-fold",
            exact(
                "<core::slice::iter::Iter<u8> as core::iter::traits::iterator::Iterator>::fold::<u32, deepwyrm_kernel::test_support::protocol::fnv1a32::{closure#0}>",
            ),
        ),
        frame(
            "ist-completion-checksum-step",
            exact("deepwyrm_kernel::test_support::protocol::fnv1a32::{closure#0}"),
        ),
    ];
    let completion_serial = [
        frame(
            "ist-completion-serial-record",
            suffix(
                "IST QEMU completion serial write",
                " as deepwyrm_kernel::test_support::transport::CompletionTransport>::write_serial_record",
            ),
        ),
        frame(
            "ist-emit-early-raw-record",
            exact("deepwyrm_kernel::debug::emit_early_raw_record"),
        ),
        frame(
            "ist-bounded-raw-record",
            contains_plain(
                "IST bounded raw record",
                "debug::write_bounded_raw_record::<",
            ),
        ),
        frame("ist-completion-output-guard", output_guard),
        frame(
            "ist-com1-raw-bytes",
            suffix("IST COM1 raw bytes", ">::write_raw_bytes"),
        ),
        frame("ist-com1-hardware-byte", hardware_byte),
        frame("ist-com1-port-read", port_read),
    ];
    let completion_drain = [
        frame(
            "ist-completion-serial-record-drain",
            suffix(
                "IST QEMU completion serial write for drain",
                " as deepwyrm_kernel::test_support::transport::CompletionTransport>::write_serial_record",
            ),
        ),
        frame(
            "ist-emit-early-raw-record-drain",
            exact("deepwyrm_kernel::debug::emit_early_raw_record"),
        ),
        frame(
            "ist-bounded-raw-record-drain",
            contains_plain(
                "IST bounded raw record for drain",
                "debug::write_bounded_raw_record::<",
            ),
        ),
        frame("ist-completion-drain-output-guard", output_guard),
        frame(
            "ist-com1-drain",
            suffix(
                "IST COM1 transmitter drain",
                ">::wait_until_transmitter_drained",
            ),
        ),
        frame("ist-com1-drain-port-read", port_read),
    ];
    let completion_debug_exit = [
        frame(
            "ist-completion-debug-exit",
            suffix(
                "IST completion debug-exit branch",
                " as deepwyrm_kernel::test_support::transport::CompletionTransport>::write_debug_exit",
            ),
        ),
        frame(
            "ist-write-qemu-debug-exit",
            exact("deepwyrm_kernel::test_support::x86_64::write_qemu_debug_exit"),
        ),
    ];
    let completion_halt = [
        frame(
            "ist-completion-halt",
            suffix(
                "IST completion halt branch",
                " as deepwyrm_kernel::test_support::transport::CompletionTransport>::halt",
            ),
        ),
        frame(
            "ist-halt-after-completion",
            exact("deepwyrm_kernel::test_support::x86_64::halt_after_completion"),
        ),
    ];

    let audited = |segments: &[&[AuditedStackFrame]]| {
        audited_stack_path(segments).expect("IST terminal stack manifest is exact")
    };
    let panic_paths = [
        audited(&[&handler_prefix, &panic_common, &panic_bounded_text]),
        audited(&[&handler_prefix, &panic_common, &panic_optional_u32_argument]),
        audited(&[&handler_prefix, &panic_common, &panic_optional_u32]),
        audited(&[&handler_prefix, &panic_common, &panic_address_argument]),
        audited(&[&handler_prefix, &panic_common, &panic_address]),
        audited(&[
            &handler_prefix,
            &panic_common,
            &panic_address_padding,
            &fmt_padding_branch,
        ]),
    ];
    let completion_paths = [
        audited(&[&handler_prefix, &completion_common, &completion_encode_hex]),
        audited(&[&handler_prefix, &completion_common, &completion_checksum]),
        audited(&[&handler_prefix, &completion_common, &completion_serial]),
        audited(&[&handler_prefix, &completion_common, &completion_drain]),
        audited(&[&handler_prefix, &completion_common, &completion_debug_exit]),
        audited(&[&handler_prefix, &completion_common, &completion_halt]),
    ];
    let panic_bound = audited_stack_upper_bound(&panic_paths);
    let completion_bound = audited_stack_upper_bound(&completion_paths);
    let panic_bytes = panic_bound.bytes;
    let completion_bytes = completion_bound.bytes;
    let measured_chain = panic_bytes.max(completion_bytes);
    let max_frame_count = audited_stack_upper_bound(&[panic_bound, completion_bound]).frame_count;
    let return_address_bytes = max_frame_count * size_of::<u64>();
    let used = measured_chain + return_address_bytes + IST_ENTRY_BYTES;
    assert!(
        used + REQUIRED_SPARE_BYTES <= IST_STACK_BYTES,
        "{selector} IST stack bound exceeds 16 KiB: panic={panic_bytes} completion={completion_bytes} \
         entry={IST_ENTRY_BYTES} depth={max_frame_count} returns={return_address_bytes} \
         required-spare={REQUIRED_SPARE_BYTES}"
    );
    eprintln!(
        "{selector} IST stack panic={panic_bytes} completion={completion_bytes} \
         entry={IST_ENTRY_BYTES} depth={max_frame_count} returns={return_address_bytes} used={used} \
         required-spare={REQUIRED_SPARE_BYTES} spare={}",
        IST_STACK_BYTES - used
    );
}

fn validate_production_ist_stack_margin(sizes: &[StackSize], disassembly: &str) {
    const IST_STACK_BYTES: usize = 16 * 1024;
    const REQUIRED_SPARE_BYTES: usize = 4 * 1024;
    const IST_ENTRY_BYTES: usize = (5 + 2 + 16) * size_of::<u64>() + 15 + size_of::<u64>();

    let exact = |name: &str| one_stack_size(sizes, name, |symbol| symbol == name);
    let contains_plain = |description: &str, needle: &str| {
        one_stack_size(sizes, description, |symbol| {
            symbol.contains(needle) && !symbol.contains("::{closure")
        })
    };
    let suffix = |description: &str, ending: &str| {
        one_stack_size(sizes, description, |symbol| symbol.ends_with(ending))
    };
    let frame = |name: &'static str, bytes: usize| AuditedStackFrame { name, bytes };

    let handler_prefix = [
        frame(
            "production-ist-exception-dispatch",
            exact("dw_x86_64_exception_dispatch"),
        ),
        frame(
            "production-ist-report-early-exception",
            contains_plain(
                "production IST early exception report",
                "arch::x86_64::exceptions::report_early_exception::<",
            ),
        ),
        frame(
            "production-ist-serial-exception-reporter",
            suffix(
                "production IST serial exception reporter",
                " as deepwyrm_kernel::arch::x86_64::exceptions::EarlyExceptionReporter>::report_and_halt",
            ),
        ),
    ];
    let hardware_byte = suffix(
        "production IST COM1 hardware byte",
        ">::write_hardware_byte",
    );
    let port_read = suffix(
        "production IST COM1 port read",
        " as deepwyrm_kernel::debug::PortIo>::read_u8",
    );
    let panic_common = [
        frame(
            "production-ist-emit-early-panic-record",
            exact("deepwyrm_kernel::debug::emit_early_panic_record"),
        ),
        frame(
            "production-ist-emit-panic-record",
            contains_plain(
                "production IST panic record emission",
                "debug::emit_panic_record::<",
            ),
        ),
        frame(
            "production-ist-render-panic-record",
            contains_plain(
                "production IST panic record rendering",
                "debug::render_panic_record::<",
            ),
        ),
        frame(
            "production-ist-panic-output-guard",
            exact("<deepwyrm_kernel::debug::OutputGuard>::acquire"),
        ),
    ];
    let bounded_text = [
        frame(
            "production-ist-write-limited",
            contains_plain(
                "production IST bounded panic field",
                "debug::write_limited::<",
            ),
        ),
        frame(
            "production-ist-com1-formatted-bytes",
            suffix("production IST COM1 formatted bytes", ">::write_bytes"),
        ),
        frame("production-ist-com1-hardware-byte", hardware_byte),
        frame("production-ist-com1-port-read", port_read),
    ];
    let fmt_write = exact(
        "<deepwyrm_kernel::debug::Com1<deepwyrm_kernel::debug::X86PortIo> as core::fmt::Write>::write_fmt",
    );
    let fmt_spec = exact(
        "<&mut deepwyrm_kernel::debug::Com1<deepwyrm_kernel::debug::X86PortIo> as core::fmt::Write::write_fmt::SpecWriteFmt>::spec_write_fmt",
    );
    let fmt_write_str = exact(
        "<deepwyrm_kernel::debug::Com1<deepwyrm_kernel::debug::X86PortIo> as core::fmt::Write>::write_str",
    );
    let fmt_arguments = fixed_x86_64_stack_frame(
        disassembly,
        "<core::fmt::Arguments>::as_statically_known_str",
    );
    let fmt_core_write = fixed_x86_64_stack_frame(disassembly, "core::fmt::write");
    let fmt_pad_integral =
        fixed_x86_64_stack_frame(disassembly, "<core::fmt::Formatter>::pad_integral");
    let fmt_write_prefix = fixed_x86_64_stack_frame(
        disassembly,
        "<core::fmt::Formatter>::pad_integral::write_prefix",
    );
    let fmt_padding_branch = ist_padding_branch(
        exact(
            "<deepwyrm_kernel::debug::Com1<deepwyrm_kernel::debug::X86PortIo> as core::fmt::Write>::write_char",
        ),
        exact("core::char::methods::encode_utf8_raw"),
        exact("core::slice::raw::from_raw_parts_mut::precondition_check"),
        exact("<*const ()>::is_aligned_to"),
    );
    let optional_u32 = [
        frame(
            "production-ist-write-optional-u32",
            contains_plain(
                "production IST optional u32 rendering",
                "debug::write_optional_u32::<",
            ),
        ),
        frame("production-ist-com1-write-fmt-u32", fmt_write),
        frame("production-ist-com1-spec-write-fmt-u32", fmt_spec),
        frame("production-ist-fmt-arguments-u32", fmt_arguments),
        frame("production-ist-core-fmt-write-u32", fmt_core_write),
        frame(
            "production-ist-u32-display",
            fixed_x86_64_stack_frame(disassembly, "<u32 as core::fmt::Display>::fmt"),
        ),
        frame("production-ist-u32-pad-integral", fmt_pad_integral),
        frame("production-ist-u32-write-prefix", fmt_write_prefix),
        frame("production-ist-com1-write-str-u32", fmt_write_str),
        frame(
            "production-ist-com1-formatted-u32-bytes",
            suffix("production IST COM1 formatted u32 bytes", ">::write_bytes"),
        ),
        frame("production-ist-com1-u32-hardware-byte", hardware_byte),
        frame("production-ist-com1-u32-port-read", port_read),
    ];
    let address = [
        frame(
            "production-ist-write-address",
            contains_plain(
                "production IST address rendering",
                "debug::write_address::<",
            ),
        ),
        frame("production-ist-com1-write-fmt-address", fmt_write),
        frame("production-ist-com1-spec-write-fmt-address", fmt_spec),
        frame("production-ist-fmt-arguments-address", fmt_arguments),
        frame("production-ist-core-fmt-write-address", fmt_core_write),
        frame(
            "production-ist-u64-lower-hex",
            fixed_x86_64_stack_frame(disassembly, "<u64 as core::fmt::LowerHex>::fmt"),
        ),
        frame("production-ist-address-pad-integral", fmt_pad_integral),
        frame("production-ist-address-write-prefix", fmt_write_prefix),
        frame("production-ist-com1-write-str-address", fmt_write_str),
        frame(
            "production-ist-com1-formatted-address-bytes",
            suffix(
                "production IST COM1 formatted address bytes",
                ">::write_bytes",
            ),
        ),
        frame("production-ist-com1-address-hardware-byte", hardware_byte),
        frame("production-ist-com1-address-port-read", port_read),
    ];
    let address_padding = [
        frame(
            "production-ist-write-address-padding",
            contains_plain(
                "production IST address rendering",
                "debug::write_address::<",
            ),
        ),
        frame("production-ist-com1-write-fmt-address-padding", fmt_write),
        frame(
            "production-ist-com1-spec-write-fmt-address-padding",
            fmt_spec,
        ),
        frame(
            "production-ist-fmt-arguments-address-padding",
            fmt_arguments,
        ),
        frame(
            "production-ist-core-fmt-write-address-padding",
            fmt_core_write,
        ),
        frame(
            "production-ist-u64-lower-hex-padding",
            fixed_x86_64_stack_frame(disassembly, "<u64 as core::fmt::LowerHex>::fmt"),
        ),
        frame(
            "production-ist-address-pad-integral-padding",
            fmt_pad_integral,
        ),
    ];
    let halt = [frame(
        "production-ist-halt-forever",
        exact("deepwyrm_kernel::arch::x86_64::exceptions::halt_forever"),
    )];
    let audited = |segments: &[&[AuditedStackFrame]]| {
        audited_stack_path(segments).expect("production IST terminal stack manifest is exact")
    };
    let panic_paths = [
        audited(&[&handler_prefix, &panic_common, &bounded_text]),
        audited(&[&handler_prefix, &panic_common, &optional_u32]),
        audited(&[&handler_prefix, &panic_common, &address]),
        audited(&[
            &handler_prefix,
            &panic_common,
            &address_padding,
            &fmt_padding_branch,
        ]),
    ];
    let halt_path = audited(&[&handler_prefix, &halt]);
    let panic_bound = audited_stack_upper_bound(&panic_paths);
    let panic_bytes = panic_bound.bytes;
    let measured_chain = panic_bytes.max(halt_path.bytes);
    let max_frame_count = audited_stack_upper_bound(&[panic_bound, halt_path]).frame_count;
    let return_address_bytes = max_frame_count * size_of::<u64>();
    let used = measured_chain + return_address_bytes + IST_ENTRY_BYTES;
    assert!(
        used + REQUIRED_SPARE_BYTES <= IST_STACK_BYTES,
        "production IST stack bound exceeds 16 KiB: panic={panic_bytes} halt={} \
         entry={IST_ENTRY_BYTES} depth={max_frame_count} returns={return_address_bytes} \
         required-spare={REQUIRED_SPARE_BYTES}",
        halt_path.bytes
    );
    eprintln!(
        "production IST stack panic={panic_bytes} halt={} entry={IST_ENTRY_BYTES} \
         depth={max_frame_count} returns={return_address_bytes} used={used} \
         required-spare={REQUIRED_SPARE_BYTES} spare={}",
        halt_path.bytes,
        IST_STACK_BYTES - used
    );
}

fn validate_ist_artifact_geometry(symbols: &str) {
    let addresses = symbols
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let address = u64::from_str_radix(fields.next()?, 16).ok()?;
            let _kind = fields.next()?;
            Some((fields.next()?, address))
        })
        .collect::<BTreeMap<_, _>>();
    let address = |name: &str| {
        *addresses
            .get(name)
            .unwrap_or_else(|| panic!("production artifact omitted IST symbol {name}"))
    };
    let stacks = [
        (
            "__dw_double_fault_ist_guard",
            "__dw_double_fault_ist_bottom",
            "__dw_double_fault_ist_top",
        ),
        (
            "__dw_nmi_ist_guard",
            "__dw_nmi_ist_bottom",
            "__dw_nmi_ist_top",
        ),
        (
            "__dw_machine_check_ist_guard",
            "__dw_machine_check_ist_bottom",
            "__dw_machine_check_ist_top",
        ),
    ];
    for (guard, bottom, top) in stacks {
        assert_eq!(address(guard) & 0xfff, 0, "{guard} is not page aligned");
        assert_eq!(address(bottom) - address(guard), 4096, "{guard} size");
        assert_eq!(address(top) - address(bottom), 16 * 1024, "{top} size");
    }
    assert_eq!(
        address("__dw_ist_region_start"),
        address("__dw_double_fault_ist_guard")
    );
    assert_eq!(
        address("__dw_double_fault_ist_top"),
        address("__dw_nmi_ist_guard")
    );
    assert_eq!(
        address("__dw_nmi_ist_top"),
        address("__dw_machine_check_ist_guard")
    );
    assert_eq!(
        address("__dw_ist_region_end") - address("__dw_ist_region_start"),
        15 * 4096
    );
    assert!(
        address("__dw_data_start") <= address("__dw_ist_region_start")
            && address("__dw_ist_region_end") <= address("__dw_data_end"),
        "linked IST arena escapes the writable data PT_LOAD bounds"
    );
}

fn symbols(llvm_nm: &Path, artifact: &Path) -> String {
    let mut command = helper_command(llvm_nm);
    let output = run_output(
        command.args(["--defined-only", "--demangle"]).arg(artifact),
        "llvm-nm",
    );
    String::from_utf8(output.stdout).expect("llvm-nm output is UTF-8")
}

fn disassembly(llvm_objdump: &Path, artifact: &Path) -> String {
    let mut command = helper_command(llvm_objdump);
    let output = run_output(
        command
            .args(["--disassemble", "--demangle", "--x86-asm-syntax=intel"])
            .arg(artifact),
        "llvm-objdump",
    );
    String::from_utf8(output.stdout).expect("llvm-objdump output is UTF-8")
}

fn text_disassembly(disassembly: &str) -> &str {
    disassembly
        .split_once("Disassembly of section .text:")
        .map(|(_, text)| text)
        .unwrap_or_else(|| panic!("target artifact omitted .text disassembly"))
}

fn validate_entry_normalization(disassembly: &str) {
    let normalizer = function_body(disassembly, "normalize_dw0_c_cpu_state");
    assert_eq!(normalizer.matches("pushfq").count(), 1);
    assert_eq!(normalizer.matches("popfq").count(), 1);
    assert_eq!(normalizer.matches("cr4").count(), 2);
    assert_eq!(normalizer.matches("mov\tcr4,").count(), 1);
    assert_eq!(normalizer.matches("btr\trax, 0x15").count(), 1);
    assert_eq!(normalizer.matches("btr\tqword ptr [rsp], 0x12").count(), 1);
    assert_eq!(disassembly.matches("mov\tcr4,").count(), 1);

    let entry = function_body(disassembly, "dw_kernel_rust_entry");
    let normalize_call = entry
        .find("normalize_dw0_c_cpu_state")
        .expect("target entry calls CPU normalizer");
    let kernel_main_call = entry
        .find("deepwyrm_kernel::kernel_main")
        .expect("target entry calls kernel_main");
    assert!(normalize_call < kernel_main_call);
}

fn function_body<'a>(disassembly: &'a str, symbol: &str) -> &'a str {
    let start = disassembly
        .lines()
        .position(|line| line.contains(symbol) && line.trim_end().ends_with(" >:".trim()))
        .unwrap_or_else(|| panic!("disassembly omitted {symbol}"));
    let mut offset = 0;
    let mut lines = disassembly.lines();
    for _ in 0..=start {
        let line = lines.next().expect("symbol line exists");
        offset += line.len() + 1;
    }
    let tail = &disassembly[offset..];
    let end = tail
        .lines()
        .scan(0, |offset, line| {
            let current = *offset;
            *offset += line.len() + 1;
            Some((current, line))
        })
        .find_map(|(offset, line)| {
            (line.contains('<') && line.trim_end().ends_with(" >:".trim())).then_some(offset)
        })
        .unwrap_or(tail.len());
    &tail[..end]
}

fn fixed_x86_64_stack_frame(disassembly: &str, symbol: &str) -> usize {
    let body = function_body(disassembly, symbol);
    assert!(
        !body.contains("\tand\trsp") && !body.contains("\tlea\trsp"),
        "{symbol} uses dynamic stack adjustment"
    );
    let pushes = body
        .lines()
        .filter(|line| line.contains("\tpush\t"))
        .count();
    let adjustments = body
        .lines()
        .filter_map(|line| {
            let immediate = line.split_once("\tsub\trsp, 0x")?.1;
            let digits = immediate.bytes().take_while(u8::is_ascii_hexdigit).count();
            usize::from_str_radix(&immediate[..digits], 16).ok()
        })
        .collect::<Vec<_>>();
    assert!(
        adjustments.len() <= 1,
        "{symbol} has multiple fixed stack adjustments"
    );
    pushes * size_of::<u64>() + adjustments.first().copied().unwrap_or(0)
}

fn sha256(artifact: &Path) -> String {
    let mut command = helper_command("/usr/bin/sha256sum");
    digest_from_output(run_output(command.arg(artifact), "sha256sum"))
}

fn helper_command(program: impl AsRef<OsStr>) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("SOURCE_DATE_EPOCH", "0");
    command
}

fn digest_from_output(output: Output) -> String {
    String::from_utf8(output.stdout)
        .expect("sha256sum output is UTF-8")
        .split_ascii_whitespace()
        .next()
        .expect("sha256sum emitted a digest")
        .to_owned()
}

fn run_success(command: &mut Command, label: &str) {
    let output = run_output(command, label);
    assert!(
        output.status.success(),
        "{label} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn run_output(command: &mut Command, label: &str) -> Output {
    command
        .output()
        .unwrap_or_else(|error| panic!("failed to run {label}: {error}"))
}
