use super::*;

pub(crate) fn load_profiles(path: &Path) -> io::Result<BTreeMap<String, HarnessProfile>> {
    let text = read_bounded_utf8(path, "guest harness config", MAX_CONFIG_BYTES)?;
    let mut profiles = BTreeMap::new();
    let mut values = BTreeMap::<String, BTreeMap<String, String>>::new();
    let mut guest_tests = BTreeMap::<String, Option<u32>>::new();
    enum Section {
        Profile(String),
        GuestTest(String),
    }
    let mut current = None::<Section>;
    let mut saw_schema = false;
    for (line_number, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line == "schema_version = 1" {
            if saw_schema || current.is_some() {
                return invalid_input(format!(
                    "{}:{}: schema_version must appear once before sections",
                    path.display(),
                    line_number + 1
                ));
            }
            saw_schema = true;
            continue;
        }
        if line.starts_with("[profile.") && line.ends_with(']') {
            let name = &line[9..line.len() - 1];
            validate_name(name, "profile")?;
            if values.contains_key(name) {
                return invalid_input(format!(
                    "{}:{line_number}: duplicate profile `{name}`",
                    path.display()
                ));
            }
            values.insert(name.into(), BTreeMap::new());
            current = Some(Section::Profile(name.into()));
            continue;
        }
        if line.starts_with("[guest_test.") && line.ends_with(']') {
            let selector = &line[12..line.len() - 1];
            validate_selector(selector)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if guest_tests.insert(selector.into(), None).is_some() {
                return invalid_input(format!(
                    "{}:{}: duplicate guest-test selector `{selector}`",
                    path.display(),
                    line_number + 1
                ));
            }
            current = Some(Section::GuestTest(selector.into()));
            continue;
        }
        if line.starts_with('[') {
            return invalid_input(format!(
                "{}:{}: unsupported harness configuration section",
                path.display(),
                line_number + 1
            ));
        }
        let (key, value) = parse_toml_scalar(line).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}:{}: {error}", path.display(), line_number + 1),
            )
        })?;
        match current.as_ref() {
            Some(Section::Profile(section)) => {
                let profile_values = values
                    .get_mut(section)
                    .expect("current profile was inserted");
                if profile_values.insert(key.into(), value).is_some() {
                    return invalid_input(format!(
                        "{}:{}: duplicate key `{key}`",
                        path.display(),
                        line_number + 1
                    ));
                }
            }
            Some(Section::GuestTest(selector)) => {
                if key != "id" {
                    return invalid_input(format!(
                        "{}:{}: guest-test `{selector}` only accepts `id`",
                        path.display(),
                        line_number + 1
                    ));
                }
                let id = value.parse::<u32>().map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "{}:{}: guest-test id must be an integer",
                            path.display(),
                            line_number + 1
                        ),
                    )
                })?;
                if id == 0
                    || guest_tests
                        .insert(selector.clone(), Some(id))
                        .flatten()
                        .is_some()
                {
                    return invalid_input(format!(
                        "{}:{}: guest-test `{selector}` has an invalid or duplicate id",
                        path.display(),
                        line_number + 1
                    ));
                }
            }
            None => {
                return invalid_input(format!(
                    "{}:{}: value outside a supported section",
                    path.display(),
                    line_number + 1
                ));
            }
        }
    }
    if !saw_schema || guest_tests.values().any(Option::is_none) {
        return invalid_input(
            "guest harness configuration is missing schema or guest-test id".into(),
        );
    }
    let unique_ids = guest_tests
        .values()
        .filter_map(|id| *id)
        .collect::<BTreeSet<_>>();
    if unique_ids.len() != guest_tests.len() {
        return invalid_input("guest harness configuration has duplicate guest-test IDs".into());
    }
    for (name, values) in values {
        let profile = HarnessProfile {
            name: name.clone(),
            machine: required_string(&values, "machine")?,
            vcpu: required_number(&values, "vcpu")?,
            memory_mib: required_number(&values, "memory_mib")?,
            timeout_seconds: required_number(&values, "timeout_seconds")?,
            gdb_port: required_number(&values, "gdb_port")?,
        };
        if profile.machine != "q35"
            || profile.vcpu == 0
            || profile.memory_mib == 0
            || profile.timeout_seconds == 0
        {
            return invalid_input(format!("profile `{name}` has an invalid q35 harness value"));
        }
        profiles.insert(name, profile);
    }
    if profiles.is_empty() {
        return invalid_input("guest harness configuration contains no profiles".into());
    }
    Ok(profiles)
}

pub(crate) fn load_harness_request(path: &Path) -> io::Result<HarnessRequest> {
    let text = read_bounded_utf8(path, "guest harness request", MAX_REQUEST_BYTES)?;
    parse_harness_request(&text, path)
}

pub(crate) fn parse_harness_request(text: &str, path: &Path) -> io::Result<HarnessRequest> {
    let values = parse_flat_toml(text, path)?;
    if values.get("schema_version").map(String::as_str) != Some("1") {
        return invalid_input("guest harness request requires schema_version = 1".into());
    }
    if values.get("producer").map(String::as_str) != Some("wyrmroot") {
        return invalid_input("guest harness request producer must be `wyrmroot`".into());
    }
    let request = HarnessRequest {
        kind: required_string(&values, "kind")?,
        profile: required_string(&values, "profile")?,
        selector: required_value(&values, "selector")?,
        test_id: required_number(&values, "test_id")?,
        timeout_seconds: required_number(&values, "timeout_seconds")?,
        serial_log: required_relative_path(&values, "serial_log")?,
        result_json: required_relative_path(&values, "result_json")?,
        no_host_share: required_bool(&values, "no_host_share")?,
        deepwyrm_revision: required_revision(&values, "deepwyrm_revision")?,
        deepwyrm_dirty: required_bool(&values, "deepwyrm_dirty")?,
        wyrmroot_revision: required_revision(&values, "wyrmroot_revision")?,
        wyrmroot_dirty: required_bool(&values, "wyrmroot_dirty")?,
        esp_image: required_relative_path(&values, "esp_image")?,
        esp_sha256: required_sha256(&values, "esp_sha256")?,
        system_disk: required_relative_path(&values, "system_disk")?,
        system_disk_sha256: required_sha256(&values, "system_disk_sha256")?,
        ovmf_code: required_relative_path(&values, "ovmf_code")?,
        ovmf_code_sha256: required_sha256(&values, "ovmf_code_sha256")?,
        ovmf_vars: required_relative_path(&values, "ovmf_vars")?,
        ovmf_vars_sha256: required_sha256(&values, "ovmf_vars_sha256")?,
        deepwyrm_elf: required_relative_path(&values, "deepwyrm_elf")?,
        deepwyrm_elf_sha256: required_sha256(&values, "deepwyrm_elf_sha256")?,
        deepwyrm_symbols: required_relative_path(&values, "deepwyrm_symbols")?,
        deepwyrm_symbols_sha256: required_sha256(&values, "deepwyrm_symbols_sha256")?,
        kernel_layout_sha256: required_sha256(&values, "kernel_layout_sha256")?,
        rust_toolchain_commit: required_revision(&values, "rust_toolchain_commit")?,
        toolchain_config_sha256: required_sha256(&values, "toolchain_config_sha256")?,
        toolchain_root_manifest_sha256: required_sha256(&values, "toolchain_root_manifest_sha256")?,
        toolchain_cargo: required_absolute_path(&values, "toolchain_cargo")?,
        toolchain_cargo_sha256: required_sha256(&values, "toolchain_cargo_sha256")?,
        toolchain_rustc: required_absolute_path(&values, "toolchain_rustc")?,
        toolchain_rustc_sha256: required_sha256(&values, "toolchain_rustc_sha256")?,
        toolchain_rust_lld: required_absolute_path(&values, "toolchain_rust_lld")?,
        toolchain_rust_lld_sha256: required_sha256(&values, "toolchain_rust_lld_sha256")?,
        toolchain_sysroot_manifest: required_absolute_path(&values, "toolchain_sysroot_manifest")?,
        toolchain_sysroot_manifest_sha256: required_sha256(
            &values,
            "toolchain_sysroot_manifest_sha256",
        )?,
    };
    Ok(request)
}

pub(crate) fn validate_request(
    kind: HarnessKind,
    request: &HarnessRequest,
    expected_selector: Option<&str>,
) -> io::Result<()> {
    if request.kind != kind.request_kind() {
        return invalid_input(format!(
            "request kind `{}` cannot be used for `{}` planning",
            request.kind,
            kind.request_kind()
        ));
    }
    validate_name(&request.profile, "profile")?;
    if kind == HarnessKind::GuestTest {
        validate_selector(&request.selector)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        if request.test_id == 0 {
            return invalid_input("guest-test requests require a nonzero explicit test_id".into());
        }
        if let Some(expected_selector) = expected_selector
            && request.selector != expected_selector
        {
            return invalid_input("guest selector does not match the request".into());
        }
    } else if !request.selector.is_empty() || request.test_id != 0 {
        return invalid_input("only guest-test requests may carry a selector or test_id".into());
    }
    if request.timeout_seconds == 0 || !request.no_host_share {
        return invalid_input(
            "request must have a bounded timeout and no_host_share = true".into(),
        );
    }
    Ok(())
}

pub(crate) fn validate_guest_selector_metadata(
    path: &Path,
    request: &HarnessRequest,
) -> io::Result<()> {
    if request.kind != HarnessKind::GuestTest.request_kind() {
        return Ok(());
    }
    let text = read_bounded_utf8(path, "guest harness config", MAX_CONFIG_BYTES)?;
    let mut current = None::<String>;
    let mut mappings = BTreeMap::new();
    for raw_line in text.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.starts_with("[guest_test.") && line.ends_with(']') {
            let selector = &line[12..line.len() - 1];
            validate_selector(selector)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            current = Some(selector.into());
            continue;
        }
        if line.starts_with('[') {
            current = None;
            continue;
        }
        let Some(selector) = current.as_ref() else {
            continue;
        };
        if line.is_empty() {
            continue;
        }
        let (key, value) = parse_toml_scalar(line)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        if key == "id" {
            let id: u32 = value.parse().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "guest test id must be an integer",
                )
            })?;
            if id == 0 || mappings.insert(selector.clone(), id).is_some() {
                return invalid_input("duplicate or zero guest-test selector mapping".into());
            }
        }
    }
    let expected_id = mappings.get(&request.selector).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "guest-test selector has no centralized ID mapping",
        )
    })?;
    if mappings.values().filter(|id| **id == *expected_id).count() != 1
        || *expected_id != request.test_id
    {
        return invalid_input(
            "guest-test request ID does not match a unique centralized selector mapping".into(),
        );
    }
    Ok(())
}

pub(crate) fn parse_flat_toml(text: &str, path: &Path) -> io::Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for (line_number, raw_line) in text.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            return invalid_input(format!(
                "{}:{}: sections are not allowed",
                path.display(),
                line_number + 1
            ));
        }
        let (key, value) = parse_toml_scalar(line).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{}:{}: {error}", path.display(), line_number + 1),
            )
        })?;
        if values.insert(key.into(), value).is_some() {
            return invalid_input(format!(
                "{}:{}: duplicate key `{key}`",
                path.display(),
                line_number + 1
            ));
        }
    }
    Ok(values)
}

pub(crate) fn read_bounded(path: &Path, label: &str, limit: usize) -> io::Result<Vec<u8>> {
    let file = open_no_symlinks(path, label)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return invalid_input(format!("{label} must be a regular file"));
    }
    if metadata.len() > limit as u64 {
        return invalid_input(format!("{label} exceeds the {limit}-byte limit"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return invalid_input(format!("{label} exceeds the {limit}-byte limit"));
    }
    Ok(bytes)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(crate) fn open_no_symlinks(path: &Path, label: &str) -> io::Result<fs::File> {
    use std::ffi::CString;
    use std::os::fd::FromRawFd;
    use std::os::raw::c_long;
    use std::os::unix::ffi::OsStrExt;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    unsafe extern "C" {
        fn syscall(number: c_long, ...) -> c_long;
    }

    // Linux x86_64 constants from asm/unistd.h and linux/openat2.h. This is the
    // only unsafe boundary: openat2 atomically rejects symlinks in every component.
    const SYS_OPENAT2: c_long = 437;
    const AT_FDCWD: c_long = -100;
    const O_CLOEXEC: u64 = 0o2_000_000;
    const O_NONBLOCK: u64 = 0o4_000;
    const RESOLVE_NO_SYMLINKS: u64 = 0x04;

    let raw_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{label} path contains an interior NUL"),
        )
    })?;
    let how = OpenHow {
        flags: O_CLOEXEC | O_NONBLOCK,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS,
    };
    // SAFETY: raw_path and how remain valid for the syscall; the returned fd is
    // transferred immediately to File only when non-negative.
    let fd = unsafe {
        syscall(
            SYS_OPENAT2,
            AT_FDCWD,
            raw_path.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        let error = io::Error::last_os_error();
        return Err(io::Error::new(
            error.kind(),
            format!("cannot open {label} without traversing symbolic links: {error}"),
        ));
    }
    // SAFETY: successful openat2 returns an owned file descriptor.
    Ok(unsafe { fs::File::from_raw_fd(fd as i32) })
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
pub(crate) fn open_no_symlinks(_path: &Path, label: &str) -> io::Result<fs::File> {
    invalid_input(format!(
        "{label} cannot be read safely: atomic no-symlink open is unavailable on this host"
    ))
}

pub(crate) fn read_bounded_utf8(path: &Path, label: &str, limit: usize) -> io::Result<String> {
    String::from_utf8(read_bounded(path, label, limit)?)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, format!("{label} is not UTF-8")))
}

pub(crate) fn parse_toml_scalar(line: &str) -> Result<(&str, String), String> {
    let (key, raw_value) = line
        .split_once('=')
        .ok_or_else(|| "expected `key = value`".to_owned())?;
    let key = key.trim();
    let raw_value = raw_value.trim();
    if key.is_empty()
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err("invalid key".into());
    }
    let value = if raw_value.starts_with('"') && raw_value.ends_with('"') && raw_value.len() >= 2 {
        raw_value[1..raw_value.len() - 1].to_owned()
    } else if !raw_value.contains(char::is_whitespace) {
        raw_value.to_owned()
    } else {
        return Err("values must be one unescaped string, number, or boolean".into());
    };
    Ok((key, value))
}

pub(crate) fn required_string(values: &BTreeMap<String, String>, key: &str) -> io::Result<String> {
    values
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("missing or empty `{key}`"),
            )
        })
}

pub(crate) fn required_value(values: &BTreeMap<String, String>, key: &str) -> io::Result<String> {
    values
        .get(key)
        .cloned()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("missing `{key}`")))
}

pub(crate) fn required_number<T>(values: &BTreeMap<String, String>, key: &str) -> io::Result<T>
where
    T: std::str::FromStr,
{
    required_string(values, key)?.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("`{key}` must be an integer"),
        )
    })
}

pub(crate) fn required_bool(values: &BTreeMap<String, String>, key: &str) -> io::Result<bool> {
    match required_string(values, key)?.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => invalid_input(format!("`{key}` must be true or false")),
    }
}

pub(crate) fn required_relative_path(
    values: &BTreeMap<String, String>,
    key: &str,
) -> io::Result<String> {
    let value = required_string(values, key)?;
    let path = Path::new(&value);
    if path.is_absolute()
        || path.components().any(|component| match component {
            Component::Normal(part) => !part
                .as_encoded_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            Component::CurDir
            | Component::ParentDir
            | Component::RootDir
            | Component::Prefix(_) => true,
        })
    {
        return invalid_input(format!(
            "`{key}` must be a relative path without parent traversal"
        ));
    }
    Ok(value)
}

pub(crate) fn required_absolute_path(
    values: &BTreeMap<String, String>,
    key: &str,
) -> io::Result<String> {
    let value = required_string(values, key)?;
    let path = Path::new(&value);
    if !path.is_absolute()
        || path.components().any(|component| match component {
            Component::Normal(part) => !part
                .as_encoded_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
            Component::RootDir => false,
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => true,
        })
    {
        return invalid_input(format!(
            "`{key}` must be an absolute portable path without traversal"
        ));
    }
    Ok(value)
}
