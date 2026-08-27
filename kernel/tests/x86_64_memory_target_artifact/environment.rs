use super::*;

#[derive(Clone, Copy)]
pub(super) struct AcceptedToolPaths<'a> {
    pub(super) request: &'a Path,
    pub(super) cargo: &'a Path,
    pub(super) rustc: &'a Path,
    pub(super) rust_lld: &'a Path,
    pub(super) clang: &'a Path,
    pub(super) llvm_nm: &'a Path,
    pub(super) llvm_objdump: &'a Path,
    pub(super) llvm_readelf: &'a Path,
}

pub(super) fn validate_accepted_identities(
    workspace: &Path,
    rust_identity: &str,
    build_tools_identity: &str,
    tools: AcceptedToolPaths<'_>,
) {
    let AcceptedToolPaths {
        request,
        cargo,
        rustc,
        rust_lld,
        clang,
        llvm_nm,
        llvm_objdump,
        llvm_readelf,
    } = tools;
    let toolchain_root = cargo
        .parent()
        .and_then(Path::parent)
        .expect("Cargo path has a toolchain root");
    let artifact_root = toolchain_root
        .parent()
        .and_then(Path::parent)
        .expect("toolchain root has an artifact root");
    let request_metadata = fs::symlink_metadata(request)
        .unwrap_or_else(|error| panic!("inspect accepted request {}: {error}", request.display()));
    assert!(
        request_metadata.file_type().is_file() && !request_metadata.file_type().is_symlink(),
        "accepted request must be a regular non-symlink file: {}",
        request.display()
    );
    for (supplied, path_key, hash_key) in [
        (cargo, "cargo_binary", "cargo_sha256"),
        (rustc, "rustc_binary", "rustc_sha256"),
        (rust_lld, "rust_lld_binary", "rust_lld_sha256"),
    ] {
        let expected_path = toolchain_root.join(manifest_value(rust_identity, path_key));
        validate_selected_tool_path(
            supplied,
            &expected_path,
            &manifest_value(rust_identity, hash_key),
            path_key,
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
        (request.to_path_buf(), "config_sha256"),
        (
            workspace.join(manifest_value(rust_identity, "sysroot_manifest")),
            "sysroot_manifest_sha256",
        ),
    ] {
        assert_eq!(
            sha256(&path),
            manifest_value(rust_identity, hash_key),
            "{hash_key} drifted"
        );
    }
    let system_tar = PathBuf::from(manifest_value(build_tools_identity, "system_tar_binary"));
    let system_sha256sum = PathBuf::from(manifest_value(
        build_tools_identity,
        "system_sha256sum_binary",
    ));
    validate_root_owned_helper(
        &system_tar,
        &manifest_value(build_tools_identity, "system_tar_sha256"),
        "system tar",
    );
    validate_root_owned_helper(
        &system_sha256sum,
        &manifest_value(build_tools_identity, "system_sha256sum_sha256"),
        "system sha256sum",
    );
    assert_eq!(
        deterministic_tree_sha256(toolchain_root, &system_tar, &system_sha256sum),
        manifest_value(rust_identity, "toolchain_tree_sha256"),
        "accepted toolchain tree drifted"
    );
    let clang_runtime = clang_runtime_paths(build_tools_identity, clang);
    validate_selected_tool_path(
        clang,
        &clang_runtime.expected_clang,
        &manifest_value(build_tools_identity, "clang_sha256"),
        "Clang",
    );
    for (path, hash_key, label) in [
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
    let clang_relative = PathBuf::from(manifest_value(build_tools_identity, "clang_binary"));
    let mut clang_root = clang.to_path_buf();
    for _ in clang_relative.components() {
        assert!(
            clang_root.pop(),
            "Clang path is shallower than its manifest path"
        );
    }
    for (supplied, path_key, hash_key, label) in [
        (llvm_nm, "llvm_nm_binary", "llvm_nm_sha256", "llvm-nm"),
        (
            llvm_objdump,
            "llvm_objdump_binary",
            "llvm_objdump_sha256",
            "llvm-objdump",
        ),
        (
            llvm_readelf,
            "llvm_readelf_binary",
            "llvm_readelf_sha256",
            "llvm-readelf/readobj",
        ),
    ] {
        let expected = clang_root.join(manifest_value(build_tools_identity, path_key));
        validate_selected_tool_path(
            supplied,
            &expected,
            &manifest_value(build_tools_identity, hash_key),
            label,
        );
    }
    for (path_key, hash_key, label) in [
        ("system_tar_binary", "system_tar_sha256", "system tar"),
        (
            "system_sha256sum_binary",
            "system_sha256sum_sha256",
            "system sha256sum",
        ),
    ] {
        let path = PathBuf::from(manifest_value(build_tools_identity, path_key));
        validate_root_owned_helper(
            &path,
            &manifest_value(build_tools_identity, hash_key),
            label,
        );
    }
}

fn validate_selected_tool_path(supplied: &Path, expected: &Path, expected_hash: &str, label: &str) {
    let metadata = fs::symlink_metadata(supplied)
        .unwrap_or_else(|error| panic!("inspect selected {label}: {error}"));
    assert!(
        metadata.file_type().is_file(),
        "selected {label} must be a direct regular file"
    );
    assert_eq!(
        supplied, expected,
        "{label} is not the manifest-selected path"
    );
    assert_eq!(
        fs::canonicalize(supplied).expect("canonicalize selected tool"),
        supplied,
        "selected {label} path must already be canonical"
    );
    assert_eq!(
        sha256(supplied),
        expected_hash,
        "selected {label} hash drifted"
    );
}

fn sha256_hex_in_process(input: &[u8]) -> String {
    const INITIAL: [u32; 8] = [
        0x6A09_E667,
        0xBB67_AE85,
        0x3C6E_F372,
        0xA54F_F53A,
        0x510E_527F,
        0x9B05_688C,
        0x1F83_D9AB,
        0x5BE0_CD19,
    ];
    const K: [u32; 64] = [
        0x428A_2F98,
        0x7137_4491,
        0xB5C0_FBCF,
        0xE9B5_DBA5,
        0x3956_C25B,
        0x59F1_11F1,
        0x923F_82A4,
        0xAB1C_5ED5,
        0xD807_AA98,
        0x1283_5B01,
        0x2431_85BE,
        0x550C_7DC3,
        0x72BE_5D74,
        0x80DE_B1FE,
        0x9BDC_06A7,
        0xC19B_F174,
        0xE49B_69C1,
        0xEFBE_4786,
        0x0FC1_9DC6,
        0x240C_A1CC,
        0x2DE9_2C6F,
        0x4A74_84AA,
        0x5CB0_A9DC,
        0x76F9_88DA,
        0x983E_5152,
        0xA831_C66D,
        0xB003_27C8,
        0xBF59_7FC7,
        0xC6E0_0BF3,
        0xD5A7_9147,
        0x06CA_6351,
        0x1429_2967,
        0x27B7_0A85,
        0x2E1B_2138,
        0x4D2C_6DFC,
        0x5338_0D13,
        0x650A_7354,
        0x766A_0ABB,
        0x81C2_C92E,
        0x9272_2C85,
        0xA2BF_E8A1,
        0xA81A_664B,
        0xC24B_8B70,
        0xC76C_51A3,
        0xD192_E819,
        0xD699_0624,
        0xF40E_3585,
        0x106A_A070,
        0x19A4_C116,
        0x1E37_6C08,
        0x2748_774C,
        0x34B0_BCB5,
        0x391C_0CB3,
        0x4ED8_AA4A,
        0x5B9C_CA4F,
        0x682E_6FF3,
        0x748F_82EE,
        0x78A5_636F,
        0x84C8_7814,
        0x8CC7_0208,
        0x90BE_FFFA,
        0xA450_6CEB,
        0xBEF9_A3F7,
        0xC671_78F2,
    ];
    let bit_len = (input.len() as u64).wrapping_mul(8);
    let mut bytes = input.to_vec();
    bytes.push(0x80);
    while !(bytes.len() + 8).is_multiple_of(64) {
        bytes.push(0);
    }
    bytes.extend_from_slice(&bit_len.to_be_bytes());
    let mut state = INITIAL;
    for chunk in bytes.chunks_exact(64) {
        let mut words = [0u32; 64];
        for (index, word) in words.iter_mut().take(16).enumerate() {
            *word = u32::from_be_bytes(
                chunk[index * 4..index * 4 + 4]
                    .try_into()
                    .expect("SHA-256 chunk word"),
            );
        }
        for index in 16..64 {
            let s0 = words[index - 15].rotate_right(7)
                ^ words[index - 15].rotate_right(18)
                ^ (words[index - 15] >> 3);
            let s1 = words[index - 2].rotate_right(17)
                ^ words[index - 2].rotate_right(19)
                ^ (words[index - 2] >> 10);
            words[index] = words[index - 16]
                .wrapping_add(s0)
                .wrapping_add(words[index - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
        for index in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let choose = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(choose)
                .wrapping_add(K[index])
                .wrapping_add(words[index]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let majority = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(majority);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }
        state = [
            state[0].wrapping_add(a),
            state[1].wrapping_add(b),
            state[2].wrapping_add(c),
            state[3].wrapping_add(d),
            state[4].wrapping_add(e),
            state[5].wrapping_add(f),
            state[6].wrapping_add(g),
            state[7].wrapping_add(h),
        ];
    }
    state.iter().map(|word| format!("{word:08x}")).collect()
}

fn validate_root_owned_helper(path: &Path, expected_hash: &str, label: &str) {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let canonical =
        fs::canonicalize(path).unwrap_or_else(|error| panic!("canonicalize {label}: {error}"));
    assert_eq!(canonical, path, "{label} path must be canonical");
    let metadata = fs::metadata(&canonical).unwrap_or_else(|error| panic!("stat {label}: {error}"));
    assert_eq!(metadata.uid(), 0, "{label} must be root-owned");
    assert_eq!(metadata.gid(), 0, "{label} must be root-group-owned");
    assert_eq!(
        metadata.permissions().mode() & 0o022,
        0,
        "{label} must not be group/other writable"
    );
    let bytes = fs::read(&canonical).unwrap_or_else(|error| panic!("read {label}: {error}"));
    assert_eq!(
        sha256_hex_in_process(&bytes),
        expected_hash,
        "{label} hash drifted"
    );
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

pub(super) fn deterministic_tree_sha256(
    root: &Path,
    tar_path: &Path,
    sha256sum_path: &Path,
) -> String {
    let mut tar_command = helper_command(tar_path);
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
    let mut sha_command = helper_command(sha256sum_path);
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
        "kernel/tests/userspace/f12_ipc_blocking_smoke.S",
        "kernel/tests/userspace/f12_user.ld",
        "kernel/tests/userspace/f9_atomic_wait_wake.S",
        "kernel/tests/userspace/f9_user.ld",
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
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace = manifest_dir
            .parent()
            .expect("kernel manifest has workspace parent");
        let root = workspace.join(".tmp").join("target-artifacts");
        fs::create_dir_all(&root)
            .unwrap_or_else(|error| panic!("create project-local target-artifact root: {error}"));
        let path = root.join(format!("accepted-toolchain-{}-{nonce}", std::process::id()));
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    size: u64,
    mtime: i64,
    mtime_nsec: i64,
    ctime: i64,
    ctime_nsec: i64,
}

fn file_identity(metadata: &fs::Metadata) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        mtime: metadata.mtime(),
        mtime_nsec: metadata.mtime_nsec(),
        ctime: metadata.ctime(),
        ctime_nsec: metadata.ctime_nsec(),
    }
}

fn same_open_executable(left: FileIdentity, right: FileIdentity) -> bool {
    left.device == right.device
        && left.inode == right.inode
        && left.size == right.size
        && left.mtime == right.mtime
        && left.mtime_nsec == right.mtime_nsec
}

pub(super) struct VerifiedExecutable {
    file: fs::File,
    source_path: PathBuf,
    exec_path: PathBuf,
    expected_sha256: String,
    identity: FileIdentity,
    label: String,
}

impl VerifiedExecutable {
    pub(super) fn open(path: &Path, expected_sha256: String, label: &str) -> Self {
        use std::os::fd::AsRawFd;
        let selected = fs::symlink_metadata(path)
            .unwrap_or_else(|error| panic!("inspect accepted {label}: {error}"));
        assert!(
            selected.file_type().is_file(),
            "accepted {label} path must name a direct regular file"
        );
        let source_path =
            fs::canonicalize(path).unwrap_or_else(|error| panic!("canonicalize {label}: {error}"));
        assert_eq!(
            source_path, path,
            "accepted {label} path must already be canonical"
        );
        let file = fs::File::open(&source_path)
            .unwrap_or_else(|error| panic!("open accepted {label}: {error}"));
        let metadata = file
            .metadata()
            .unwrap_or_else(|error| panic!("stat accepted {label}: {error}"));
        assert!(metadata.is_file(), "accepted {label} is not regular");
        clear_close_on_exec(file.as_raw_fd(), label);
        let exec_path = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
        let actual = sha256(&exec_path);
        assert_eq!(
            actual, expected_sha256,
            "accepted {label} hash drifted at open"
        );
        Self {
            file,
            source_path,
            exec_path,
            expected_sha256,
            identity: file_identity(&metadata),
            label: label.to_owned(),
        }
    }

    pub(super) fn source_path(&self) -> &Path {
        &self.source_path
    }

    pub(super) fn exec_path(&self) -> &Path {
        &self.exec_path
    }

    pub(super) fn revalidate(&self) {
        let metadata = self
            .file
            .metadata()
            .unwrap_or_else(|error| panic!("stat open {}: {error}", self.label));
        assert!(
            same_open_executable(file_identity(&metadata), self.identity),
            "open accepted {} executable identity changed after verification",
            self.label
        );
        assert_eq!(
            sha256(&self.exec_path),
            self.expected_sha256,
            "open accepted {} bytes changed after verification",
            self.label
        );
    }

    pub(super) fn command(&self) -> Command {
        self.revalidate();
        Command::new(&self.exec_path)
    }

    pub(super) fn command_with_argv0(&self, argv0: &str) -> Command {
        use std::os::unix::process::CommandExt;
        self.revalidate();
        let mut command = Command::new(&self.exec_path);
        command.arg0(argv0);
        command
    }
}

fn clear_close_on_exec(fd: i32, label: &str) {
    use std::os::raw::{c_int, c_long};
    unsafe extern "C" {
        fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    }
    const F_GETFD: c_int = 1;
    const F_SETFD: c_int = 2;
    const FD_CLOEXEC: c_int = 1;
    // SAFETY: fcntl operates on the live owned File descriptor; removing CLOEXEC
    // is intentional so nested Cargo -> rustc -> linker processes can refer to
    // the exact verified inode through /proc/self/fd/N.
    let flags = unsafe { fcntl(fd, F_GETFD) };
    assert!(flags >= 0, "read CLOEXEC flags for {label}");
    let rc = unsafe { fcntl(fd, F_SETFD, (flags & !FD_CLOEXEC) as c_long) };
    assert_eq!(rc, 0, "clear CLOEXEC for {label}");
}

#[derive(Clone, Debug)]
pub(super) struct VerifiedArtifactUse {
    path: PathBuf,
    expected_sha256: String,
    identity: FileIdentity,
    label: String,
}

impl VerifiedArtifactUse {
    fn capture(path: PathBuf, expected_sha256: String, label: &str) -> Self {
        let path =
            fs::canonicalize(path).unwrap_or_else(|error| panic!("canonicalize {label}: {error}"));
        let metadata = fs::metadata(&path).unwrap_or_else(|error| panic!("stat {label}: {error}"));
        assert!(metadata.is_file(), "accepted {label} is not regular");
        assert_eq!(
            sha256(&path),
            expected_sha256,
            "accepted {label} hash drifted"
        );
        Self {
            path,
            expected_sha256,
            identity: file_identity(&metadata),
            label: label.to_owned(),
        }
    }

    fn revalidate(&self) {
        let metadata =
            fs::metadata(&self.path).unwrap_or_else(|error| panic!("stat {}: {error}", self.label));
        assert_eq!(
            file_identity(&metadata),
            self.identity,
            "{} metadata drifted",
            self.label
        );
        assert_eq!(
            sha256(&self.path),
            self.expected_sha256,
            "{} bytes drifted",
            self.label
        );
    }
}

#[derive(Clone, Copy)]
pub(super) struct BuildTools<'a> {
    pub(super) cargo: &'a VerifiedExecutable,
    pub(super) rustc: &'a VerifiedExecutable,
    pub(super) rust_lld: &'a VerifiedExecutable,
    pub(super) clang: &'a VerifiedExecutable,
    pub(super) runtime_artifacts: &'a [VerifiedArtifactUse],
}

impl BuildTools<'_> {
    pub(super) fn revalidate_for_spawn(self) {
        self.cargo.revalidate();
        self.rustc.revalidate();
        self.rust_lld.revalidate();
        self.clang.revalidate();
        for artifact in self.runtime_artifacts {
            artifact.revalidate();
        }
    }
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
        tools.revalidate_for_spawn();
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
            .env("RUSTC", tools.rustc.exec_path())
            .env("DEEPWYRM_CLANG", tools.clang.exec_path())
            .env("CARGO_TARGET_DIR", target_dir)
            .env(
                "CARGO_TARGET_X86_64_UNKNOWN_NONE_LINKER",
                tools.rust_lld.exec_path(),
            );
    }
}

pub(super) fn accepted_runtime_artifacts(
    rust_identity: &str,
    cargo_path: &Path,
) -> Vec<VerifiedArtifactUse> {
    let toolchain_root = cargo_path
        .parent()
        .and_then(Path::parent)
        .expect("Cargo path has toolchain root");
    let artifact_root = toolchain_root
        .parent()
        .and_then(Path::parent)
        .expect("toolchain root has artifact root");
    let root_manifest_path = artifact_root.join(manifest_value(rust_identity, "root_manifest"));
    let root_manifest =
        fs::read_to_string(&root_manifest_path).expect("read accepted root manifest");
    let (core_path, core_hash) =
        root_manifest_artifact(&root_manifest, "artifacts.none_core", artifact_root);
    let (builtins_path, builtins_hash) = root_manifest_artifact(
        &root_manifest,
        "artifacts.none_compiler_builtins",
        artifact_root,
    );
    vec![
        VerifiedArtifactUse::capture(
            toolchain_root.join(manifest_value(
                rust_identity,
                "rustc_driver_internal_library",
            )),
            manifest_value(rust_identity, "rustc_driver_internal_library_sha256"),
            "librustc_driver",
        ),
        VerifiedArtifactUse::capture(
            toolchain_root.join(manifest_value(rust_identity, "llvm_internal_library")),
            manifest_value(rust_identity, "llvm_internal_library_sha256"),
            "toolchain libLLVM",
        ),
        VerifiedArtifactUse::capture(core_path, core_hash, "freestanding core"),
        VerifiedArtifactUse::capture(
            builtins_path,
            builtins_hash,
            "freestanding compiler-builtins",
        ),
    ]
}

fn root_manifest_artifact(source: &str, section: &str, artifact_root: &Path) -> (PathBuf, String) {
    let wanted = format!("[{section}]");
    let mut active = false;
    let mut path = None;
    let mut hash = None;
    for raw in source.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.starts_with('[') {
            active = line == wanted;
            continue;
        }
        if !active || line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim().trim_matches('"');
            match key.trim() {
                "path" => path = Some(artifact_root.join(value)),
                "sha256" => hash = Some(value.to_owned()),
                _ => {}
            }
        }
    }
    (
        path.unwrap_or_else(|| panic!("root manifest omitted {section} path")),
        hash.unwrap_or_else(|| panic!("root manifest omitted {section} sha256")),
    )
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
    assert!(!before.contains(&owned_workspace_config));

    let legacy_workspace_config = workspace.join(LEGACY_WORKSPACE_CARGO_CONFIG);
    let ancestor_config = ancestor.join(".cargo/config.toml");
    let home_config = ambient_home.join(".cargo/config");
    fs::write(&legacy_workspace_config, "[build]\n").expect("write legacy workspace Cargo config");
    fs::write(&ancestor_config, "[build]\n").expect("write ancestor Cargo config");
    fs::write(&home_config, "[build]\n").expect("write ambient-home Cargo config");
    let detected = ambient_cargo_configs(&workspace, Some(&ambient_home));
    assert!(before.iter().all(|config| detected.contains(config)));
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

#[test]
pub(super) fn verified_executable_survives_path_rename_and_replacement() {
    let root = ArtifactRoot::create();
    let selected = root.path().join("selected-tool");
    let displaced = root.path().join("selected-tool.original");
    fs::copy("/bin/echo", &selected).expect("copy test executable");
    let hash = sha256(&selected);
    let verified = VerifiedExecutable::open(&selected, hash, "replacement-race probe");

    fs::rename(&selected, &displaced).expect("rename verified executable");
    fs::copy("/bin/false", &selected).expect("replace selected path");
    let output = verified
        .command()
        .arg("fd-bound")
        .output()
        .expect("execute verified open inode");
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "fd-bound");
    drop(verified);
    root.cleanup();
}

#[test]
pub(super) fn verified_executable_detects_same_inode_mutation_before_spawn() {
    let root = ArtifactRoot::create();
    let selected = root.path().join("mutable-tool");
    fs::copy("/bin/echo", &selected).expect("copy test executable");
    let hash = sha256(&selected);
    let verified = VerifiedExecutable::open(&selected, hash, "mutation-race probe");

    fs::write(&selected, b"mutated after verification").expect("mutate accepted inode");
    let rejected = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        verified.revalidate();
    }));
    assert!(
        rejected.is_err(),
        "same-inode mutation escaped revalidation"
    );
    drop(verified);
    root.cleanup();
}

#[test]
pub(super) fn selected_tool_identity_rejects_symlink_and_hardlink_aliases() {
    use std::os::unix::fs::symlink;

    let root = ArtifactRoot::create();
    let selected = root.path().join("selected-tool");
    let symlink_alias = root.path().join("symlink-tool");
    let hardlink_alias = root.path().join("hardlink-tool");
    fs::copy("/bin/true", &selected).expect("copy selected executable");
    symlink(&selected, &symlink_alias).expect("create symlink alias");
    fs::hard_link(&selected, &hardlink_alias).expect("create hard-link alias");
    let hash = sha256(&selected);

    for alias in [&symlink_alias, &hardlink_alias] {
        let rejected = std::panic::catch_unwind(|| {
            validate_selected_tool_path(alias, &selected, &hash, "alias probe");
        });
        assert!(
            rejected.is_err(),
            "tool alias unexpectedly became accepted identity"
        );
    }
    let symlink_open = std::panic::catch_unwind(|| {
        let _ = VerifiedExecutable::open(&symlink_alias, hash.clone(), "symlink probe");
    });
    assert!(
        symlink_open.is_err(),
        "VerifiedExecutable accepted a symlink path"
    );
    root.cleanup();
}

#[allow(
    clippy::too_many_arguments,
    reason = "the evidence identity enumerates every independently supplied build and inspection tool plus the pinned Clang-library manifest"
)]
pub(super) fn normalized_build_environment_sha256(
    cargo: &VerifiedExecutable,
    rustc: &VerifiedExecutable,
    rust_lld: &VerifiedExecutable,
    clang: &VerifiedExecutable,
    llvm_nm: &VerifiedExecutable,
    llvm_objdump: &VerifiedExecutable,
    llvm_readelf: &VerifiedExecutable,
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
    let clang_runtime = clang_runtime_paths(build_tools_identity, clang.source_path());
    let executable_paths = [
        ("cargo", cargo),
        ("rustc", rustc),
        ("rust-lld", rust_lld),
        ("clang", clang),
        ("llvm-nm", llvm_nm),
        ("llvm-objdump", llvm_objdump),
        ("llvm-readelf", llvm_readelf),
    ];
    for (name, executable) in executable_paths {
        let path = executable.source_path();
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
    for (name, path) in [
        ("libclang-cpp", clang_runtime.libclang_cpp.as_path()),
        ("host-llvm", clang_runtime.host_llvm.as_path()),
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
    record.push_str("verified_exec=/proc/self/fd/<inherited-open-inode>\n");
    record.push_str("runtime_artifacts=revalidated-before-cargo-spawn\n");
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
