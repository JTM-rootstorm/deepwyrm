use super::*;

pub(super) fn validate_accepted_identities(
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

pub(super) struct ClangRuntimePaths {
    expected_clang: PathBuf,
    libclang_cpp: PathBuf,
    host_llvm: PathBuf,
}

pub(super) fn clang_runtime_paths(
    build_tools_identity: &str,
    supplied_clang: &Path,
) -> ClangRuntimePaths {
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

pub(super) fn deterministic_tree_sha256(root: &Path) -> String {
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

pub(super) fn build_input_manifest_sha256(workspace: &Path) -> String {
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

pub(super) fn collect_regular_files(directory: &Path, files: &mut Vec<PathBuf>) {
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

pub(super) fn sha256_bytes(bytes: &[u8]) -> String {
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

pub(super) fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

pub(super) struct ArtifactRoot(Option<PathBuf>);

impl ArtifactRoot {
    pub(super) fn create() -> Self {
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

    pub(super) fn path(&self) -> &Path {
        self.0.as_deref().expect("artifact root remains owned")
    }

    pub(super) fn cleanup(mut self) {
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

pub(super) struct BuildEnvironment {
    cargo_home: PathBuf,
    home: PathBuf,
}

#[derive(Clone, Copy)]
pub(super) struct BuildTools<'a> {
    pub(super) cargo: &'a Path,
    pub(super) rustc: &'a Path,
    pub(super) rust_lld: &'a Path,
    pub(super) clang: &'a Path,
}

impl BuildEnvironment {
    pub(super) fn create(root: &Path) -> Self {
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

    pub(super) fn apply(&self, command: &mut Command, tools: BuildTools<'_>, target_dir: &Path) {
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

pub(super) fn reject_ambient_build_overrides(workspace: &Path) {
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

pub(super) fn ambient_cargo_configs(workspace: &Path, ambient_home: Option<&Path>) -> Vec<PathBuf> {
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
pub(super) fn legacy_workspace_ancestor_and_home_cargo_configuration_is_rejected() {
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
pub(super) fn helper_subprocess_environment_is_exactly_normalized() {
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
pub(super) fn clang_runtime_paths_are_derived_from_the_manifest_layout() {
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
pub(super) fn normalized_build_environment_sha256(
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

pub(super) fn manifest_value(source: &str, key: &str) -> String {
    source
        .lines()
        .find_map(|line| {
            let (candidate, value) = line.split_once('=')?;
            (candidate.trim() == key).then(|| value.trim().trim_matches('"').to_owned())
        })
        .unwrap_or_else(|| panic!("trusted toolchain identity omitted {key}"))
}

pub(super) fn required_path(name: &str) -> PathBuf {
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
