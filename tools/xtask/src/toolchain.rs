use super::*;

pub(super) fn validate_toolchain_provenance(
    request: &HarnessRequest,
) -> io::Result<TrustedToolchain> {
    let mut trusted = load_trusted_toolchain(&workspace_root().join(TRUSTED_TOOLCHAIN_CONFIG))?;
    validate_request_toolchain_identity(request, &trusted)?;
    let root_manifest = read_bounded(&trusted.root_manifest_path, "root manifest", 64 * 1024)?;
    verify_artifact_bytes(
        &root_manifest,
        &trusted.root_manifest_sha256,
        "root manifest",
    )?;
    bind_freestanding_artifacts(&mut trusted, &root_manifest)?;
    verify_trusted_toolchain_artifacts(&trusted)?;
    let sysroot_manifest = read_bounded(
        &trusted.sysroot_manifest_path,
        "sysroot manifest",
        64 * 1024,
    )?;
    verify_artifact_bytes(
        &sysroot_manifest,
        &trusted.sysroot_manifest_sha256,
        "sysroot manifest",
    )?;
    validate_sysroot_manifest(&trusted, &sysroot_manifest)?;
    Ok(trusted)
}

pub(super) fn verify_build_tools(root_input: &Path, clang_config_input: &Path) -> io::Result<u8> {
    let identity = load_build_tools_identity(&workspace_root().join(BUILD_TOOLS_CONFIG))?;
    let root = canonical_operator_directory(root_input, "build-tools root")?;
    let clang_config = canonical_operator_file(clang_config_input, "Clang configuration")?;
    let clang = root.join(&identity.clang_binary);
    let libclang_cpp = root.join(&identity.libclang_cpp);
    let host_llvm = root.join(&identity.host_llvm);
    for (path, expected, label) in [
        (&clang, &identity.clang_sha256, "clang-22"),
        (&libclang_cpp, &identity.libclang_cpp_sha256, "libclang-cpp"),
        (&host_llvm, &identity.host_llvm_sha256, "host LLVM"),
        (
            &clang_config,
            &identity.clang_config_sha256,
            "Clang configuration",
        ),
    ] {
        verify_trusted_artifact(path, expected, label, 512 * 1024 * 1024)?;
    }
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "{{\"schema_version\":1,\"status\":\"VERIFIED\",\"clang_version\":\"{}\",\"root\":\"{}\",\"clang_config\":\"{}\"}}",
        identity.clang_version,
        json_string(&root.display().to_string()),
        json_string(&clang_config.display().to_string()),
    )?;
    Ok(0)
}

pub(super) fn load_build_tools_identity(path: &Path) -> io::Result<BuildToolsIdentity> {
    let values = parse_flat_toml(
        &read_bounded_utf8(path, "build-tools identity", MAX_CONFIG_BYTES)?,
        path,
    )?;
    if values.get("schema").map(String::as_str) != Some("deepwyrm-build-tools-identity-v1") {
        return invalid_input("build-tools identity has an unknown schema".into());
    }
    let clang_version = required_string(&values, "clang_version")?;
    if clang_version != "22.1.8" {
        return invalid_input("build-tools identity has an unexpected Clang version".into());
    }
    Ok(BuildToolsIdentity {
        clang_version,
        clang_binary: required_relative_path(&values, "clang_binary")?,
        clang_sha256: required_sha256(&values, "clang_sha256")?,
        libclang_cpp: required_relative_path(&values, "libclang_cpp")?,
        libclang_cpp_sha256: required_sha256(&values, "libclang_cpp_sha256")?,
        host_llvm: required_relative_path(&values, "host_llvm")?,
        host_llvm_sha256: required_sha256(&values, "host_llvm_sha256")?,
        clang_config_sha256: required_sha256(&values, "clang_config_sha256")?,
    })
}

pub(super) fn canonical_operator_directory(path: &Path, label: &str) -> io::Result<PathBuf> {
    let canonical = canonical_operator_path(path, label)?;
    if !fs::metadata(&canonical)?.is_dir() {
        return invalid_input(format!("{label} must be a directory"));
    }
    Ok(canonical)
}

pub(super) fn canonical_operator_file(path: &Path, label: &str) -> io::Result<PathBuf> {
    let canonical = canonical_operator_path(path, label)?;
    if !fs::metadata(&canonical)?.is_file() {
        return invalid_input(format!("{label} must be a regular file"));
    }
    Ok(canonical)
}

pub(super) fn canonical_operator_path(path: &Path, label: &str) -> io::Result<PathBuf> {
    if !path.is_absolute() {
        return invalid_input(format!("{label} must be an absolute canonical path"));
    }
    let canonical = fs::canonicalize(path)?;
    if canonical != path {
        return invalid_input(format!(
            "{label} must not contain symbolic links or normalization"
        ));
    }
    Ok(canonical)
}

pub(super) fn load_trusted_toolchain(path: &Path) -> io::Result<TrustedToolchain> {
    let values = parse_flat_toml(
        &read_bounded_utf8(path, "trusted toolchain config", 64 * 1024)?,
        path,
    )?;
    if values.get("schema").map(String::as_str) != Some("deepwyrm-rust-toolchain-identity-v1") {
        return invalid_input("trusted toolchain config has an unknown schema".into());
    }
    if values.get("request_id").map(String::as_str) != Some("RUST-PHASE0B-TOOLCHAIN-001") {
        return invalid_input("trusted toolchain config has an unexpected request ID".into());
    }
    if values.get("toolchain_tree_recipe").map(String::as_str)
        != Some(
            "tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -cf - -C <toolchain-root> . | sha256sum",
        )
    {
        return invalid_input(
            "trusted toolchain config has an unexpected tree digest recipe".into(),
        );
    }
    let artifact_root = workspace_root()
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "workspace lacks a parent"))?
        .join(required_relative_path(&values, "artifact_root")?);
    let toolchain_root = artifact_root.join(required_relative_path(&values, "toolchain_root")?);
    let rust_commit = required_revision(&values, "rust_commit")?;
    if rust_commit != canonical_rust_commit(&workspace_root().join("toolchain/provenance.toml"))? {
        return invalid_input(
            "trusted toolchain Rust commit disagrees with canonical provenance".into(),
        );
    }
    let target = required_string(&values, "target")?;
    if target != "x86_64-unknown-none" {
        return invalid_input("trusted toolchain target must be x86_64-unknown-none".into());
    }
    Ok(TrustedToolchain {
        request_id: required_string(&values, "request_id")?,
        rust_commit,
        target,
        config_sha256: required_sha256(&values, "config_sha256")?,
        artifact_root: artifact_root.clone(),
        toolchain_root: toolchain_root.clone(),
        toolchain_tree_sha256: required_sha256(&values, "toolchain_tree_sha256")?,
        root_manifest_path: artifact_root.join(required_relative_path(&values, "root_manifest")?),
        root_manifest_sha256: required_sha256(&values, "root_manifest_sha256")?,
        cargo_path: toolchain_root.join(required_relative_path(&values, "cargo_binary")?),
        cargo_sha256: required_sha256(&values, "cargo_sha256")?,
        rustc_path: toolchain_root.join(required_relative_path(&values, "rustc_binary")?),
        rustc_sha256: required_sha256(&values, "rustc_sha256")?,
        rust_lld_path: toolchain_root.join(required_relative_path(&values, "rust_lld_binary")?),
        rust_lld_sha256: required_sha256(&values, "rust_lld_sha256")?,
        rustc_driver_internal_library: TrustedArtifact {
            path: toolchain_root.join(required_relative_path(
                &values,
                "rustc_driver_internal_library",
            )?),
            sha256: required_sha256(&values, "rustc_driver_internal_library_sha256")?,
        },
        llvm_internal_library: TrustedArtifact {
            path: toolchain_root.join(required_relative_path(&values, "llvm_internal_library")?),
            sha256: required_sha256(&values, "llvm_internal_library_sha256")?,
        },
        sysroot_manifest_path: artifact_root
            .join(required_relative_path(&values, "sysroot_manifest")?),
        sysroot_manifest_sha256: required_sha256(&values, "sysroot_manifest_sha256")?,
        freestanding_core: None,
        freestanding_compiler_builtins: None,
    })
}

pub(super) fn validate_request_toolchain_identity(
    request: &HarnessRequest,
    trusted: &TrustedToolchain,
) -> io::Result<()> {
    let expected = [
        (
            "rust_toolchain_commit",
            request.rust_toolchain_commit.as_str(),
            trusted.rust_commit.as_str(),
        ),
        (
            "toolchain_config_sha256",
            request.toolchain_config_sha256.as_str(),
            trusted.config_sha256.as_str(),
        ),
        (
            "toolchain_root_manifest_sha256",
            request.toolchain_root_manifest_sha256.as_str(),
            trusted.root_manifest_sha256.as_str(),
        ),
        (
            "toolchain_cargo_sha256",
            request.toolchain_cargo_sha256.as_str(),
            trusted.cargo_sha256.as_str(),
        ),
        (
            "toolchain_rustc_sha256",
            request.toolchain_rustc_sha256.as_str(),
            trusted.rustc_sha256.as_str(),
        ),
        (
            "toolchain_rust_lld_sha256",
            request.toolchain_rust_lld_sha256.as_str(),
            trusted.rust_lld_sha256.as_str(),
        ),
        (
            "toolchain_sysroot_manifest_sha256",
            request.toolchain_sysroot_manifest_sha256.as_str(),
            trusted.sysroot_manifest_sha256.as_str(),
        ),
    ];
    for (name, actual, expected) in expected {
        if actual != expected {
            return invalid_input(format!(
                "request `{name}` does not match trusted toolchain identity"
            ));
        }
    }
    for (name, actual, expected) in [
        (
            "toolchain_cargo",
            Path::new(&request.toolchain_cargo),
            &trusted.cargo_path,
        ),
        (
            "toolchain_rustc",
            Path::new(&request.toolchain_rustc),
            &trusted.rustc_path,
        ),
        (
            "toolchain_rust_lld",
            Path::new(&request.toolchain_rust_lld),
            &trusted.rust_lld_path,
        ),
        (
            "toolchain_sysroot_manifest",
            Path::new(&request.toolchain_sysroot_manifest),
            &trusted.sysroot_manifest_path,
        ),
    ] {
        if actual != expected {
            return invalid_input(format!(
                "request `{name}` is not the trusted derived artifact path"
            ));
        }
    }
    Ok(())
}

pub(super) fn verify_trusted_toolchain_artifacts(trusted: &TrustedToolchain) -> io::Result<()> {
    verify_toolchain_tree(trusted)?;
    for (path, expected_hash, label, limit) in [
        (
            &trusted.cargo_path,
            &trusted.cargo_sha256,
            "cargo",
            512 * 1024 * 1024,
        ),
        (
            &trusted.rustc_path,
            &trusted.rustc_sha256,
            "rustc",
            512 * 1024 * 1024,
        ),
        (
            &trusted.rust_lld_path,
            &trusted.rust_lld_sha256,
            "rust-lld",
            512 * 1024 * 1024,
        ),
    ] {
        verify_trusted_artifact(path, expected_hash, label, limit)?;
    }
    verify_trusted_artifact(
        &trusted.rustc_driver_internal_library.path,
        &trusted.rustc_driver_internal_library.sha256,
        "librustc_driver",
        512 * 1024 * 1024,
    )?;
    verify_trusted_artifact(
        &trusted.llvm_internal_library.path,
        &trusted.llvm_internal_library.sha256,
        "toolchain libLLVM",
        512 * 1024 * 1024,
    )?;
    let core = trusted.freestanding_core.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted root manifest lacks freestanding core identity",
        )
    })?;
    verify_trusted_artifact(
        &core.path,
        &core.sha256,
        "freestanding core rlib",
        512 * 1024 * 1024,
    )?;
    let builtins = trusted
        .freestanding_compiler_builtins
        .as_ref()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "trusted root manifest lacks freestanding compiler-builtins identity",
            )
        })?;
    verify_trusted_artifact(
        &builtins.path,
        &builtins.sha256,
        "freestanding compiler-builtins rlib",
        512 * 1024 * 1024,
    )
}

pub(super) fn verify_toolchain_tree(trusted: &TrustedToolchain) -> io::Result<()> {
    // Coordinator-approved GNU tar/coreutils recipe; system-tool identity remains
    // an explicit Medium host assumption rather than a request-controlled PATH lookup.
    let mut tar = Command::new("/usr/bin/tar")
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
        .arg(&trusted.toolchain_root)
        .arg(".")
        .stdout(Stdio::piped())
        .spawn()?;
    let tar_stdout = tar
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("tar did not provide a digest stream"))?;
    let sha = Command::new("/usr/bin/sha256sum")
        .stdin(Stdio::from(tar_stdout))
        .output()?;
    let tar_status = tar.wait()?;
    if !tar_status.success() || !sha.status.success() {
        return invalid_input("canonical toolchain tree digest command failed".into());
    }
    let digest = std::str::from_utf8(&sha.stdout)
        .ok()
        .and_then(|output| output.split_ascii_whitespace().next())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "sha256sum produced no digest")
        })?;
    if digest != trusted.toolchain_tree_sha256 {
        return invalid_input("toolchain tree digest does not match trusted identity".into());
    }
    Ok(())
}

pub(super) fn verify_trusted_artifact(
    path: &Path,
    expected_hash: &str,
    label: &str,
    limit: usize,
) -> io::Result<()> {
    verify_artifact_bytes(&read_bounded(path, label, limit)?, expected_hash, label)
}

pub(super) fn verify_artifact_bytes(
    bytes: &[u8],
    expected_hash: &str,
    label: &str,
) -> io::Result<()> {
    if sha256_hex(bytes) != expected_hash {
        return invalid_input(format!("trusted {label} hash does not match its identity"));
    }
    Ok(())
}

pub(super) fn bind_freestanding_artifacts(
    trusted: &mut TrustedToolchain,
    root_manifest: &[u8],
) -> io::Result<()> {
    let text = std::str::from_utf8(root_manifest)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "root manifest is not UTF-8"))?;
    let core = extract_root_manifest_artifact(
        text,
        "artifacts.freestanding_core",
        &trusted.artifact_root,
    )?;
    let builtins = extract_root_manifest_artifact(
        text,
        "artifacts.freestanding_compiler_builtins",
        &trusted.artifact_root,
    )?;
    trusted.freestanding_core = Some(core);
    trusted.freestanding_compiler_builtins = Some(builtins);
    Ok(())
}

pub(super) fn extract_root_manifest_artifact(
    text: &str,
    section_name: &str,
    artifact_root: &Path,
) -> io::Result<TrustedArtifact> {
    let header = format!("[{section_name}]");
    let mut in_section = false;
    let mut found = false;
    let mut values = BTreeMap::new();
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if line == header {
                if found {
                    return invalid_input(format!(
                        "root manifest has duplicate [{section_name}] sections"
                    ));
                }
                found = true;
                in_section = true;
            } else {
                in_section = false;
            }
            continue;
        }
        if !in_section {
            continue;
        }
        let (key, value) = parse_toml_scalar(line)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if !matches!(key, "path" | "sha256") || values.insert(key.into(), value).is_some() {
            return invalid_input(format!(
                "root manifest [{section_name}] has an unsupported or duplicate key"
            ));
        }
    }
    if !found {
        return invalid_input(format!("root manifest lacks [{section_name}]"));
    }
    Ok(TrustedArtifact {
        path: artifact_root.join(required_relative_path(&values, "path")?),
        sha256: required_sha256(&values, "sha256")?,
    })
}

pub(super) fn canonical_rust_commit(path: &Path) -> io::Result<String> {
    let text = read_bounded_utf8(path, "canonical toolchain provenance", MAX_CONFIG_BYTES)?;
    let mut in_rust_section = false;
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line == "[rust]" {
            in_rust_section = true;
            continue;
        }
        if line.starts_with('[') {
            in_rust_section = false;
            continue;
        }
        if !in_rust_section || line.is_empty() {
            continue;
        }
        let (key, value) = parse_toml_scalar(line)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if key == "base_commit" {
            return validate_git_commit(&value, "canonical Rust base_commit");
        }
    }
    invalid_input("canonical toolchain provenance lacks [rust].base_commit".into())
}

pub(super) fn validate_sysroot_manifest(
    trusted: &TrustedToolchain,
    sysroot_manifest: &[u8],
) -> io::Result<()> {
    let core = trusted.freestanding_core.as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted root manifest lacks freestanding core identity",
        )
    })?;
    let builtins = trusted
        .freestanding_compiler_builtins
        .as_ref()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "trusted root manifest lacks freestanding compiler-builtins identity",
            )
        })?;
    let text = std::str::from_utf8(sysroot_manifest)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "sysroot manifest is not UTF-8"))?;
    let values = parse_flat_toml(text, &trusted.sysroot_manifest_path).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "sysroot manifest content contract is not yet agreed; require schema = \"deepwyrm-rust-sysroot-manifest-v1\" with Rust commit, x86_64-unknown-none target, configuration hash, and component hashes",
        )
    })?;
    let schema = values.get("schema").map(String::as_str);
    if schema != Some("deepwyrm-rust-sysroot-manifest-v1") {
        return invalid_input(
            "sysroot manifest content contract is not yet agreed; require schema = \"deepwyrm-rust-sysroot-manifest-v1\" with Rust commit, x86_64-unknown-none target, configuration hash, and component hashes".into(),
        );
    }
    let required = [
        ("rust_toolchain_commit", trusted.rust_commit.as_str()),
        ("target", trusted.target.as_str()),
        ("toolchain_config_sha256", trusted.config_sha256.as_str()),
        ("cargo_sha256", trusted.cargo_sha256.as_str()),
        ("rustc_sha256", trusted.rustc_sha256.as_str()),
        ("rust_lld_sha256", trusted.rust_lld_sha256.as_str()),
        ("core_sha256", core.sha256.as_str()),
        ("compiler_builtins_sha256", builtins.sha256.as_str()),
    ];
    for (key, expected) in required {
        if values.get(key).map(String::as_str) != Some(expected) {
            return invalid_input(format!(
                "sysroot manifest `{key}` does not match the request"
            ));
        }
    }
    Ok(())
}

pub(super) fn validate_git_commit(value: &str, label: &str) -> io::Result<String> {
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return invalid_input(format!("{label} must be a full 40-character Git revision"));
    }
    Ok(value.into())
}

pub(super) fn required_revision(
    values: &BTreeMap<String, String>,
    key: &str,
) -> io::Result<String> {
    let value = required_string(values, key)?;
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return invalid_input(format!("`{key}` must be a full 40-character Git revision"));
    }
    Ok(value)
}

pub(super) fn required_sha256(values: &BTreeMap<String, String>, key: &str) -> io::Result<String> {
    let value = required_string(values, key)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return invalid_input(format!("`{key}` must be a 64-character SHA-256 hex value"));
    }
    Ok(value)
}

pub(super) fn validate_name(value: &str, kind: &str) -> io::Result<()> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return invalid_input(format!("invalid {kind} name `{value}`"));
    }
    Ok(())
}

pub(super) fn validate_selector(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(format!("invalid guest-test selector `{value}`"));
    }
    Ok(())
}

pub(super) fn invalid_input<T>(message: String) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidInput, message))
}

pub(super) fn json_array(values: &[String]) -> String {
    let values = values
        .iter()
        .map(|value| format!("\"{}\"", json_string(value)))
        .collect::<Vec<_>>();
    format!("[{}]", values.join(","))
}

pub(super) fn json_string(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0C}' => escaped.push_str("\\f"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write as _;
                write!(escaped, "\\u{:04x}", character as u32)
                    .expect("writing to String cannot fail");
            }
            character => escaped.push(character),
        }
    }
    escaped
}

pub(super) fn print_toolchain_diagnostics() -> io::Result<u8> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "Deepwyrm host tool availability")?;
    writeln!(
        stdout,
        "This report does not assert toolchain adoption or pinning."
    )?;
    for (name, program) in [
        ("cargo", "cargo"),
        ("rustc", "rustc"),
        ("clang", "clang"),
        ("clang++", "clang++"),
        ("ld.lld", "ld.lld"),
        ("llvm-ar", "llvm-ar"),
        ("llvm-readelf", "llvm-readelf"),
        ("llvm-objdump", "llvm-objdump"),
        ("llvm-objcopy", "llvm-objcopy"),
        ("llvm-symbolizer", "llvm-symbolizer"),
        ("llvm-nm", "llvm-nm"),
        ("gdb", "gdb"),
    ] {
        write!(stdout, "{name}: ")?;
        match Command::new(program).arg("--version").output() {
            Ok(output) if output.status.success() => {
                let version_output = String::from_utf8_lossy(&output.stdout);
                writeln!(
                    stdout,
                    "{}",
                    version_output.lines().next().unwrap_or("available")
                )?;
            }
            Ok(output) => writeln!(stdout, "unavailable (exit {})", output.status)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => writeln!(stdout, "not found")?,
            Err(error) => writeln!(stdout, "unavailable ({error})")?,
        }
    }
    Ok(0)
}
