use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const KERNEL_TARGET: &str = "x86_64-unknown-none";

fn main() {
    if let Err(error) = run() {
        panic!("x86_64 entry build failed: {error}");
    }
}

fn run() -> Result<(), String> {
    let manifest_dir = PathBuf::from(required_env("CARGO_MANIFEST_DIR")?);
    let layout_path = manifest_dir.join("arch/x86_64/layout.toml");
    let linker_path = manifest_dir.join("arch/x86_64/linker.ld");
    let entry_path = manifest_dir.join("src/arch/x86_64/entry.S");
    let exceptions_path = manifest_dir.join("src/arch/x86_64/exceptions.S");
    let guest_harness_path = manifest_dir.join("../tooling/guest-harness.toml");

    println!("cargo:rerun-if-changed={}", layout_path.display());
    println!("cargo:rerun-if-changed={}", linker_path.display());
    println!("cargo:rerun-if-changed={}", entry_path.display());
    println!("cargo:rerun-if-changed={}", exceptions_path.display());
    println!("cargo:rerun-if-changed={}", guest_harness_path.display());
    println!("cargo:rerun-if-env-changed=DEEPWYRM_CLANG");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TEST_SUPPORT");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_GUEST_TEST_SELECTOR");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_GUEST_TEST_ID");

    let layout_source = fs::read_to_string(&layout_path)
        .map_err(|error| format!("{}: {error}", layout_path.display()))?;
    let layout = Layout::parse(&layout_source)
        .map_err(|error| format!("{}: {error}", layout_path.display()))?;

    configure_guest_test(&guest_harness_path)?;

    if required_env("TARGET")? != KERNEL_TARGET {
        return Ok(());
    }

    let out_dir = PathBuf::from(required_env("OUT_DIR")?);
    let entry_object = out_dir.join("deepwyrm-x86_64-entry.o");
    let exceptions_object = out_dir.join("deepwyrm-x86_64-exceptions.o");
    assemble_source(&entry_path, &entry_object, layout)?;
    assemble_source(&exceptions_path, &exceptions_object, layout)?;

    for argument in linker_arguments(
        layout,
        &linker_path,
        &[entry_object.as_path(), exceptions_object.as_path()],
    ) {
        println!("cargo:rustc-link-arg={argument}");
    }

    Ok(())
}

fn configure_guest_test(harness_path: &Path) -> Result<(), String> {
    let feature_enabled = env::var_os("CARGO_FEATURE_TEST_SUPPORT").is_some();
    let selector = match env::var("DEEPWYRM_GUEST_TEST_SELECTOR") {
        Ok(selector) => Some(selector),
        Err(env::VarError::NotPresent) => None,
        Err(env::VarError::NotUnicode(_)) => {
            return Err("DEEPWYRM_GUEST_TEST_SELECTOR must be valid UTF-8".into());
        }
    };
    let direct_id_present = env::var_os("DEEPWYRM_GUEST_TEST_ID").is_some();
    let harness_source = if feature_enabled {
        fs::read_to_string(harness_path)
            .map_err(|error| format!("{}: {error}", harness_path.display()))?
    } else {
        String::new()
    };

    if let Some(test_id) = select_guest_test(
        feature_enabled,
        selector.as_deref(),
        direct_id_present,
        &harness_source,
    )? {
        let selector = selector.expect("validated enabled configuration has a selector");
        println!("cargo:rustc-env=DEEPWYRM_GUEST_TEST_SELECTOR={selector}");
        println!("cargo:rustc-env=DEEPWYRM_GUEST_TEST_ID={test_id}");
    }
    Ok(())
}

pub(crate) fn select_guest_test(
    feature_enabled: bool,
    selector: Option<&str>,
    direct_id_present: bool,
    harness_source: &str,
) -> Result<Option<u32>, String> {
    if direct_id_present {
        return Err(
            "DEEPWYRM_GUEST_TEST_ID is build-owned; select by DEEPWYRM_GUEST_TEST_SELECTOR".into(),
        );
    }
    if !feature_enabled {
        return match selector {
            Some(_) => {
                Err("DEEPWYRM_GUEST_TEST_SELECTOR requires the kernel test-support feature".into())
            }
            None => Ok(None),
        };
    }
    let selector = selector
        .ok_or_else(|| "test-support builds require DEEPWYRM_GUEST_TEST_SELECTOR".to_owned())?;
    validate_selector(selector)?;
    let mappings = parse_guest_test_mappings(harness_source)?;
    mappings
        .get(selector)
        .copied()
        .map(Some)
        .ok_or_else(|| format!("unknown guest-test selector `{selector}`"))
}

pub(crate) fn linker_arguments(
    layout: Layout,
    linker_path: &Path,
    objects: &[&Path],
) -> Vec<String> {
    let mut arguments = vec![
        "-static".to_owned(),
        "-no-pie".to_owned(),
        "--no-dynamic-linker".to_owned(),
        "--build-id=none".to_owned(),
        "--gc-sections".to_owned(),
        "-z".to_owned(),
        "noexecstack".to_owned(),
        "-z".to_owned(),
        format!("max-page-size={}", layout.base_page_size),
        format!("--defsym=DW_KERNEL_LINK_BASE={:#x}", layout.link_base),
        format!(
            "--defsym=DW_KERNEL_BASE_PAGE_SIZE={}",
            layout.base_page_size
        ),
        format!(
            "--defsym=DW_KERNEL_BOOT_STACK_SIZE={}",
            layout.kernel_boot_stack_size
        ),
        format!(
            "--defsym=DW_KERNEL_BOOT_STACK_ALIGNMENT={}",
            layout.kernel_boot_stack_alignment
        ),
        format!("-T{}", linker_path.display()),
    ];
    for object in objects {
        arguments.push(object.display().to_string());
    }
    arguments
}

fn parse_guest_test_mappings(source: &str) -> Result<BTreeMap<String, u32>, String> {
    enum Section {
        TopLevel,
        Profile(String),
        GuestTest(String),
    }

    const PROFILE_KEYS: &[&str] = &[
        "machine",
        "vcpu",
        "memory_mib",
        "timeout_seconds",
        "gdb_port",
    ];

    let mut section = Section::TopLevel;
    let mut schema_seen = false;
    let mut profiles = BTreeMap::<String, BTreeMap<String, String>>::new();
    let mut guest_tests = BTreeMap::<String, BTreeMap<String, String>>::new();

    for (index, raw_line) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let name = line
                .strip_prefix('[')
                .and_then(|line| line.strip_suffix(']'))
                .ok_or_else(|| format!("line {line_number}: malformed section"))?;
            if let Some(name) = name.strip_prefix("profile.") {
                validate_name(name, "profile")?;
                if profiles.insert(name.into(), BTreeMap::new()).is_some() {
                    return Err(format!("line {line_number}: duplicate profile `{name}`"));
                }
                section = Section::Profile(name.into());
            } else if let Some(selector) = name.strip_prefix("guest_test.") {
                validate_selector(selector)?;
                if guest_tests
                    .insert(selector.into(), BTreeMap::new())
                    .is_some()
                {
                    return Err(format!(
                        "line {line_number}: duplicate guest-test selector `{selector}`"
                    ));
                }
                section = Section::GuestTest(selector.into());
            } else {
                return Err(format!("line {line_number}: unknown section `{name}`"));
            }
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {line_number}: expected key = value"));
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() {
            return Err(format!("line {line_number}: malformed key or value"));
        }
        match &section {
            Section::TopLevel => {
                if key != "schema_version" || schema_seen {
                    return Err(format!(
                        "line {line_number}: unsupported or duplicate top-level key `{key}`"
                    ));
                }
                if parse_u64(value)? != 1 {
                    return Err("guest harness schema_version must be 1".into());
                }
                schema_seen = true;
            }
            Section::Profile(name) => {
                if !PROFILE_KEYS.contains(&key) {
                    return Err(format!(
                        "line {line_number}: unsupported profile key `{key}`"
                    ));
                }
                let values = profiles
                    .get_mut(name)
                    .expect("current profile was inserted at section start");
                if values.insert(key.into(), value.into()).is_some() {
                    return Err(format!(
                        "line {line_number}: duplicate key `{key}` in profile `{name}`"
                    ));
                }
            }
            Section::GuestTest(selector) => {
                if key != "id" {
                    return Err(format!(
                        "line {line_number}: unsupported guest-test key `{key}`"
                    ));
                }
                let values = guest_tests
                    .get_mut(selector)
                    .expect("current guest test was inserted at section start");
                if values.insert(key.into(), value.into()).is_some() {
                    return Err(format!(
                        "line {line_number}: duplicate id for guest-test selector `{selector}`"
                    ));
                }
            }
        }
    }

    if !schema_seen {
        return Err("guest harness omits schema_version = 1".into());
    }
    for (name, values) in &profiles {
        let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
        let expected = PROFILE_KEYS.iter().copied().collect::<BTreeSet<_>>();
        if actual != expected {
            return Err(format!(
                "profile `{name}` does not define the exact v1 key set"
            ));
        }
        parse_string(required_value(values, "machine")?)?;
        for key in ["vcpu", "memory_mib", "timeout_seconds", "gdb_port"] {
            if parse_u64(required_value(values, key)?)? == 0 {
                return Err(format!("profile `{name}` key `{key}` must be nonzero"));
            }
        }
    }

    let mut mappings = BTreeMap::new();
    let mut ids = BTreeSet::new();
    for (selector, values) in guest_tests {
        if values.len() != 1 {
            return Err(format!(
                "guest-test selector `{selector}` must define exactly one id"
            ));
        }
        let raw_id = required_value(&values, "id")?;
        let id = parse_u64(raw_id).and_then(|id| {
            u32::try_from(id).map_err(|_| format!("guest-test id `{raw_id}` exceeds u32"))
        })?;
        if id == 0 {
            return Err(format!(
                "guest-test selector `{selector}` has reserved zero id"
            ));
        }
        if !ids.insert(id) {
            return Err(format!("duplicate guest-test id {id}"));
        }
        mappings.insert(selector, id);
    }
    if mappings.is_empty() {
        return Err("guest harness defines no guest-test selectors".into());
    }
    Ok(mappings)
}

fn validate_name(value: &str, kind: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(format!("invalid {kind} name `{value}`"));
    }
    Ok(())
}

fn validate_selector(value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
    {
        return Err(format!("invalid guest-test selector `{value}`"));
    }
    Ok(())
}

pub(crate) fn assemble_source(source: &Path, output: &Path, layout: Layout) -> Result<(), String> {
    let clang = env::var_os("DEEPWYRM_CLANG").unwrap_or_else(|| "clang".into());
    let status = Command::new(&clang)
        .arg(format!("--target={KERNEL_TARGET}"))
        .args([
            "-ffreestanding",
            "-fno-pic",
            "-fno-stack-protector",
            "-mno-red-zone",
            "-mno-mmx",
            "-mno-sse",
            "-mno-sse2",
        ])
        .arg(format!(
            "-DDW_KERNEL_BOOT_STACK_SIZE={}",
            layout.kernel_boot_stack_size
        ))
        .arg(format!(
            "-DDW_KERNEL_BOOT_STACK_ALIGNMENT={}",
            layout.kernel_boot_stack_alignment
        ))
        .args(["-c"])
        .arg(source)
        .arg("-o")
        .arg(output)
        .status()
        .map_err(|error| format!("could not execute {:?}: {error}", clang))?;
    if !status.success() {
        return Err(format!(
            "{:?} failed to assemble {} with {status}",
            clang,
            source.display()
        ));
    }
    Ok(())
}

fn required_env(name: &str) -> Result<String, String> {
    env::var(name).map_err(|error| format!("missing build environment {name}: {error}"))
}

#[derive(Clone, Copy)]
pub(crate) struct Layout {
    pub(crate) link_base: u64,
    pub(crate) base_page_size: u64,
    pub(crate) kernel_boot_stack_size: u64,
    pub(crate) kernel_boot_stack_alignment: u64,
}

impl Layout {
    pub(crate) fn parse(source: &str) -> Result<Self, String> {
        const EXPECTED_KEYS: &[&str] = &[
            "schema",
            "version",
            "entry_contract",
            "elf_type",
            "entry_symbol",
            "link_base",
            "base_page_size",
            "red_zone",
            "kernel_boot_stack_size",
            "kernel_boot_stack_alignment",
            "loader_transition_stack_size",
            "loader_transition_stack_alignment",
            "p_paddr_policy",
            "allowed_program_header_types",
            "load_policy.upper_canonical",
            "load_policy.non_overlapping",
            "load_policy.writable_xor_executable",
            "load_policy.entry_in_executable_segment",
            "entry_state.transfer",
            "entry_state.returns",
            "entry_state.boot_info_register",
            "entry_state.boot_info_address",
            "entry_state.boot_info_alignment",
            "entry_state.defined_incoming_gprs",
            "entry_state.loader_stack_owner",
            "entry_state.loader_stack_rsp",
            "entry_state.loader_stack_rsp_mod_16",
            "entry_state.loader_stack_lifetime",
            "entry_state.immediate_kernel_stack_switch",
            "entry_state.kernel_stack_owner",
            "entry_state.kernel_stack_rsp_mod_16_before_call",
            "entry_state.rust_entry_rsp_mod_16",
            "entry_state.rust_entry_abi",
            "entry_state.interrupts_enabled",
            "entry_state.direction_flag_set",
            "entry_state.cr0_write_protect",
            "entry_state.execute_disable",
            "entry_state.paging_mode",
            "entry_state.initial_processor",
            "entry_state.descriptor_state",
            "entry_state.tls_state",
            "entry_state.fp_simd_state",
            "entry_state.uefi_services_available",
            "entry_state.firmware_exit",
            "handoff_mappings.kernel_load_segments",
            "handoff_mappings.physical_allocation",
            "handoff_mappings.boot_info",
            "handoff_mappings.referenced_ranges",
            "handoff_mappings.lifetime",
            "handoff_mappings.mutable",
            "handoff_mappings.page_zero_mapped",
            "handoff_mappings.framebuffer_pixels_identity_mapped",
        ];

        let values = parse_flat_toml(source)?;
        let expected = EXPECTED_KEYS.iter().copied().collect::<BTreeSet<_>>();
        let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if actual != expected {
            let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
            let unknown = actual.difference(&expected).copied().collect::<Vec<_>>();
            return Err(format!(
                "layout keys do not match contract; missing={missing:?}, unknown={unknown:?}"
            ));
        }

        expect_string(&values, "schema", "deepwyrm-x86_64-layout")?;
        expect_u64(&values, "version", 1)?;
        expect_string(&values, "entry_contract", "DW_BOOT_X86_64_ENTRY_V1")?;
        expect_string(&values, "elf_type", "ET_EXEC")?;
        expect_string(&values, "entry_symbol", "_dw_kernel_entry")?;
        expect_bool(&values, "red_zone", false)?;
        expect_u64(&values, "loader_transition_stack_size", 16_384)?;
        expect_u64(&values, "loader_transition_stack_alignment", 4_096)?;
        expect_string(&values, "p_paddr_policy", "ignored")?;
        let program_header_types =
            parse_string_array(required_value(&values, "allowed_program_header_types")?)?;
        if program_header_types != ["PT_LOAD"] {
            return Err(
                "allowed_program_header_types must contain only the canonical PT_LOAD".into(),
            );
        }
        for key in [
            "load_policy.upper_canonical",
            "load_policy.non_overlapping",
            "load_policy.writable_xor_executable",
            "load_policy.entry_in_executable_segment",
        ] {
            expect_bool(&values, key, true)?;
        }
        for (key, expected_value) in [
            ("entry_state.transfer", "jmp"),
            ("entry_state.boot_info_register", "RDI"),
            ("entry_state.boot_info_address", "identity-mapped-physical"),
            ("entry_state.loader_stack_rsp", "one-past-end"),
            ("entry_state.loader_stack_owner", "loader"),
            (
                "entry_state.loader_stack_lifetime",
                "until-kernel-page-table-replacement",
            ),
            ("entry_state.kernel_stack_owner", "kernel"),
            ("entry_state.rust_entry_abi", "sysv64"),
            ("entry_state.paging_mode", "x86_64-4-level"),
            ("entry_state.initial_processor", "BSP"),
            (
                "entry_state.descriptor_state",
                "valid-CS-SS-others-unspecified",
            ),
            ("entry_state.tls_state", "FS-GS-unspecified"),
            (
                "entry_state.fp_simd_state",
                "unavailable-until-kernel-initialization",
            ),
            ("entry_state.firmware_exit", "ExitBootServices-complete"),
            ("handoff_mappings.kernel_load_segments", "mapped-at-p_vaddr"),
            (
                "handoff_mappings.physical_allocation",
                "arbitrary-suitable-firmware-pages",
            ),
            ("handoff_mappings.boot_info", "identity-mapped"),
            ("handoff_mappings.referenced_ranges", "identity-mapped"),
            (
                "handoff_mappings.lifetime",
                "until-kernel-page-table-replacement",
            ),
        ] {
            expect_string(&values, key, expected_value)?;
        }
        expect_u64(&values, "entry_state.boot_info_alignment", 8)?;
        expect_u64(&values, "entry_state.loader_stack_rsp_mod_16", 0)?;
        expect_u64(
            &values,
            "entry_state.kernel_stack_rsp_mod_16_before_call",
            0,
        )?;
        expect_u64(&values, "entry_state.rust_entry_rsp_mod_16", 8)?;
        let incoming_gprs = parse_string_array(required_value(
            &values,
            "entry_state.defined_incoming_gprs",
        )?)?;
        if incoming_gprs != ["RDI"] {
            return Err("entry_state.defined_incoming_gprs must contain only RDI".into());
        }
        for key in [
            "entry_state.immediate_kernel_stack_switch",
            "entry_state.cr0_write_protect",
            "entry_state.execute_disable",
        ] {
            expect_bool(&values, key, true)?;
        }
        for key in [
            "entry_state.returns",
            "entry_state.interrupts_enabled",
            "entry_state.direction_flag_set",
            "entry_state.uefi_services_available",
            "handoff_mappings.mutable",
            "handoff_mappings.page_zero_mapped",
            "handoff_mappings.framebuffer_pixels_identity_mapped",
        ] {
            expect_bool(&values, key, false)?;
        }

        let link_base = parse_hex_string(required_value(&values, "link_base")?)?;
        let base_page_size = parse_u64(required_value(&values, "base_page_size")?)?;
        let kernel_boot_stack_size = parse_u64(required_value(&values, "kernel_boot_stack_size")?)?;
        let kernel_boot_stack_alignment =
            parse_u64(required_value(&values, "kernel_boot_stack_alignment")?)?;

        if link_base < 0xffff_8000_0000_0000 || link_base % base_page_size != 0 {
            return Err("link_base must be upper-canonical and base-page aligned".into());
        }
        if !base_page_size.is_power_of_two() || base_page_size != 4_096 {
            return Err("base_page_size must be 4096".into());
        }
        if !kernel_boot_stack_alignment.is_power_of_two()
            || kernel_boot_stack_alignment != base_page_size
        {
            return Err("kernel boot stack alignment must equal the base page size".into());
        }
        if kernel_boot_stack_size != 65_536
            || kernel_boot_stack_size % kernel_boot_stack_alignment != 0
        {
            return Err("kernel boot stack must be an aligned 65536-byte range".into());
        }

        Ok(Self {
            link_base,
            base_page_size,
            kernel_boot_stack_size,
            kernel_boot_stack_alignment,
        })
    }
}

fn parse_flat_toml(source: &str) -> Result<BTreeMap<String, String>, String> {
    let mut section = "";
    let mut values = BTreeMap::new();
    for (index, raw_line) in source.lines().enumerate() {
        let line_number = index + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            let Some(name) = line
                .strip_prefix('[')
                .and_then(|line| line.strip_suffix(']'))
            else {
                return Err(format!("line {line_number}: malformed section"));
            };
            if !matches!(name, "load_policy" | "entry_state" | "handoff_mappings") {
                return Err(format!("line {line_number}: unknown section `{name}`"));
            }
            section = name;
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("line {line_number}: expected key = value"));
        };
        let key = key.trim();
        let value = value.trim();
        if key.is_empty() || value.is_empty() || value.contains('#') {
            return Err(format!("line {line_number}: malformed key or value"));
        }
        let full_key = if section.is_empty() {
            key.to_owned()
        } else {
            format!("{section}.{key}")
        };
        if values.insert(full_key.clone(), value.to_owned()).is_some() {
            return Err(format!("line {line_number}: duplicate key `{full_key}`"));
        }
    }
    Ok(values)
}

fn required_value<'a>(values: &'a BTreeMap<String, String>, key: &str) -> Result<&'a str, String> {
    values
        .get(key)
        .map(String::as_str)
        .ok_or_else(|| format!("missing key `{key}`"))
}

fn expect_string(
    values: &BTreeMap<String, String>,
    key: &str,
    expected: &str,
) -> Result<(), String> {
    let actual = parse_string(required_value(values, key)?)?;
    if actual != expected {
        return Err(format!("{key} must be `{expected}`, found `{actual}`"));
    }
    Ok(())
}

fn expect_u64(values: &BTreeMap<String, String>, key: &str, expected: u64) -> Result<(), String> {
    let actual = parse_u64(required_value(values, key)?)?;
    if actual != expected {
        return Err(format!("{key} must be {expected}, found {actual}"));
    }
    Ok(())
}

fn expect_bool(values: &BTreeMap<String, String>, key: &str, expected: bool) -> Result<(), String> {
    let actual = parse_bool(required_value(values, key)?)?;
    if actual != expected {
        return Err(format!("{key} must be {expected}, found {actual}"));
    }
    Ok(())
}

fn parse_string(value: &str) -> Result<&str, String> {
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .filter(|value| !value.contains('"') && !value.contains('\\'))
        .ok_or_else(|| format!("expected a simple quoted string, found `{value}`"))
}

fn parse_hex_string(value: &str) -> Result<u64, String> {
    let value = parse_string(value)?;
    let digits = value
        .strip_prefix("0x")
        .ok_or_else(|| format!("expected a hexadecimal string, found `{value}`"))?;
    u64::from_str_radix(digits, 16).map_err(|error| format!("invalid hexadecimal value: {error}"))
}

fn parse_string_array(value: &str) -> Result<Vec<&str>, String> {
    let contents = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| format!("expected a string array, found `{value}`"))?;
    if contents.trim().is_empty() {
        return Ok(Vec::new());
    }
    contents
        .split(',')
        .map(|value| parse_string(value.trim()))
        .collect()
}

fn parse_u64(value: &str) -> Result<u64, String> {
    if value.starts_with('+') || value.starts_with('-') || value.contains('_') {
        return Err(format!(
            "expected canonical unsigned decimal, found `{value}`"
        ));
    }
    value
        .parse()
        .map_err(|error| format!("invalid unsigned decimal `{value}`: {error}"))
}

fn parse_bool(value: &str) -> Result<bool, String> {
    match value {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("invalid boolean `{value}`")),
    }
}
