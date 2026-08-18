use super::*;
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempRoot(PathBuf);

impl TempRoot {
    fn copy_schema() -> Self {
        let unique = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "deepwyrm-abi-gen-test-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("abi/schema")).unwrap();
        let source = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../abi/schema");
        for (name, _) in SCHEMA_FILES {
            fs::copy(source.join(name), root.join("abi/schema").join(name)).unwrap();
        }
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn rewrite(&self, name: &str, operation: impl FnOnce(String) -> String) {
        let path = self.0.join("abi/schema").join(name);
        let input = fs::read_to_string(&path).unwrap();
        fs::write(path, operation(input)).unwrap();
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn load_error(root: &TempRoot) -> String {
    Model::load(root.path()).unwrap_err().to_string()
}

#[test]
fn canonical_schema_renders_deterministically() {
    let root = TempRoot::copy_schema();
    let model = Model::load(root.path()).unwrap();
    let outputs = render(&model).unwrap();
    assert_eq!(outputs, render(&model).unwrap());
    let rust = &outputs["deepwyrm_abi.rs"];
    let c = &outputs["deepwyrm_abi.h"];
    assert!(rust.contains(&format!(
        "pub const DW_RIGHTS_KNOWN_MASK: DwRights = DwRights({});",
        model.known_rights_mask
    )));
    assert!(c.contains(&format!(
        "#define DW_RIGHTS_KNOWN_MASK ((DwRights)({}))",
        model.known_rights_mask
    )));
    for entry in &model.object_rights {
        assert!(rust.contains(&format!(
            "pub const DW_OBJECT_COMPATIBLE_RIGHTS_{}: DwRights = DwRights({});",
            entry.object, entry.mask
        )));
        assert!(c.contains(&format!(
            "#define DW_OBJECT_COMPATIBLE_RIGHTS_{} ((DwRights)({}))",
            entry.object, entry.mask
        )));
    }
    let documentation = &outputs["ABI.md"];
    for name in [
        "DW_BOOT_BASE_PAGE_SIZE",
        "DW_BOOT_MEMORY_RANGE_V1_VERSION",
        "DW_BOOT_MODULE_V1_VERSION",
        "DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1",
        "DW_BOOT_X86_64_PAGING_HANDOFF_V1_VERSION",
        "DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS",
        "DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT",
        "DW_BOOT_FRAMEBUFFER_V1_VERSION",
        "DW_BOOT_ENTROPY_V1_VERSION",
        "DW_BOOT_INFO_V1_VERSION",
        "DW_DEADLINE_NOW",
        "DW_DEADLINE_INFINITE",
        "DW_WAIT_MANY_MAX_ITEMS",
        "DW_HANDLE_TRANSFER_MOVE",
        "DW_CLOCK_MONOTONIC_ACTIVE",
        "DW_OBJECT_INFO_TASK_STATE_V1",
        "DW_RIGHTS_KNOWN_MASK",
        "DW_OBJECT_COMPATIBLE_RIGHTS_MEMORY_OBJECT",
    ] {
        assert!(documentation.contains(name), "ABI.md omitted {name}");
    }
    for output in outputs.values() {
        assert!(!output.contains("DEBUG_WRITE"));
        assert!(!output.contains("debug_write"));
    }
}

#[test]
fn generate_then_check_detects_and_repairs_drift() {
    let root = TempRoot::copy_schema();
    run(["generate", "--root", root.path().to_str().unwrap()]).unwrap();
    run(["check", "--root", root.path().to_str().unwrap()]).unwrap();
    fs::write(root.path().join("abi/generated/deepwyrm_abi.rs"), "stale\n").unwrap();
    let error = run(["check", "--root", root.path().to_str().unwrap()])
        .unwrap_err()
        .to_string();
    assert!(error.contains("deepwyrm_abi.rs: generated content is stale"));
    run(["generate", "--root", root.path().to_str().unwrap()]).unwrap();
    run(["check", "--root", root.path().to_str().unwrap()]).unwrap();
    assert!(!root.path().join("abi/.generated.tmp").exists());
}

#[test]
fn rejects_unknown_key_and_section() {
    let key_root = TempRoot::copy_schema();
    key_root.rewrite("abi.toml", |text| {
        text.replacen(
            "schema_version = 1",
            "schema_version = 1\nunknown_key = 7",
            1,
        )
    });
    assert!(load_error(&key_root).contains("unsupported key `unknown_key`"));

    let section_root = TempRoot::copy_schema();
    section_root.rewrite("rights.toml", |text| {
        format!("{text}\n[[unknown]]\nname = \"X\"\n")
    });
    assert!(load_error(&section_root).contains("unsupported section `[[unknown]]`"));
}

#[test]
fn type_names_allow_only_the_canonical_x86_64_architecture_token() {
    let root = TempRoot::copy_schema();
    root.rewrite("abi.toml", |text| {
        text.replacen(
            "name = \"DwBootX86_64PagingHandoffFlags\"",
            "name = \"DwBootBad_Type\"",
            1,
        )
    });
    assert!(load_error(&root).contains("`DwBootBad_Type` is not a Deepwyrm ABI type name"));
}

#[test]
fn rejects_duplicate_namespace_name_and_value() {
    let root = TempRoot::copy_schema();
    root.rewrite("status.toml", |text| {
        format!("{text}\n[[status]]\nname = \"SUCCESS\"\nvalue = -99\ndoc = \"duplicate\"\n")
    });
    assert!(load_error(&root).contains("duplicate status name `SUCCESS`"));

    let root = TempRoot::copy_schema();
    root.rewrite("status.toml", |text| {
        format!("{text}\n[[status]]\nname = \"ANOTHER_FAILURE\"\nvalue = -1\ndoc = \"duplicate\"\n")
    });
    assert!(load_error(&root).contains("duplicate status value -1"));
}

#[test]
fn rejects_composite_right_and_invalid_object_zero() {
    let root = TempRoot::copy_schema();
    root.rewrite("rights.toml", |text| {
        text.replacen(
            "value = 0x0000000000000001",
            "value = 0x0000000000000003",
            1,
        )
    });
    assert!(load_error(&root).contains("right `READ` value must be one nonzero bit"));

    let root = TempRoot::copy_schema();
    root.rewrite("objects.toml", |text| {
        text.replacen(
            "name = \"TASK_GROUP\"\nvalue = 1",
            "name = \"TASK_GROUP\"\nvalue = 0",
            1,
        )
    });
    assert!(load_error(&root).contains("duplicate object value 0"));
}

#[test]
fn rejects_invalid_object_rights_relations() {
    let root = TempRoot::copy_schema();
    root.rewrite("object_rights.toml", |text| {
        text.replacen("object = \"TASK_GROUP\"", "object = \"BOGUS\"", 1)
    });
    assert!(load_error(&root).contains("uses unknown object `BOGUS`"));

    let root = TempRoot::copy_schema();
    root.rewrite("object_rights.toml", |text| {
        text.replacen("MODIFY,DUPLICATE", "BOGUS,DUPLICATE", 1)
    });
    assert!(load_error(&root).contains("uses unknown right `BOGUS`"));

    let root = TempRoot::copy_schema();
    root.rewrite("object_rights.toml", |text| {
        text.replacen("MODIFY,DUPLICATE", "MODIFY,MODIFY", 1)
    });
    assert!(load_error(&root).contains("repeats right `MODIFY`"));

    let root = TempRoot::copy_schema();
    root.rewrite("object_rights.toml", |text| {
        text.replacen(
            "rights = \"MODIFY,DUPLICATE,TRANSFER,INSPECT\"",
            "rights = \"\"",
            1,
        )
    });
    assert!(load_error(&root).contains("compatible-rights mask must be nonempty"));

    let root = TempRoot::copy_schema();
    root.rewrite("object_rights.toml", |text| {
        format!("{text}\n[[object_rights]]\nobject = \"NONE\"\nrights = \"INSPECT\"\n")
    });
    assert!(
        load_error(&root)
            .contains("sentinel/reserved object `NONE` must not declare compatible rights")
    );

    let root = TempRoot::copy_schema();
    root.rewrite("object_rights.toml", |text| {
        format!("{text}\n[[object_rights]]\nobject = \"INTERRUPT\"\nrights = \"INSPECT\"\n")
    });
    assert!(
        load_error(&root)
            .contains("sentinel/reserved object `INTERRUPT` must not declare compatible rights")
    );

    let root = TempRoot::copy_schema();
    root.rewrite("object_rights.toml", |text| {
            text.replacen(
                "[[object_rights]]\nobject = \"TIMER\"\nrights = \"WAIT,MODIFY,DUPLICATE,TRANSFER,INSPECT\"\n",
                "",
                1,
            )
        });
    assert!(load_error(&root).contains("object-rights schema is missing live object `TIMER`"));

    let root = TempRoot::copy_schema();
    root.rewrite("object_rights.toml", |text| {
        format!("{text}\n[[object_rights]]\nobject = \"TASK_GROUP\"\nrights = \"INSPECT\"\n")
    });
    assert!(load_error(&root).contains("duplicate object-rights entry for `TASK_GROUP`"));
}

#[test]
fn rejects_syscall_rights_incompatible_with_declared_object() {
    let root = TempRoot::copy_schema();
    root.rewrite("syscalls.toml", |text| {
        text.replacen(
            "arg0 = \"process|DwHandle|in|PROCESS|MODIFY\"",
            "arg0 = \"process|DwHandle|in|PROCESS|SIGNAL\"",
            1,
        )
    });
    assert!(
        load_error(&root).contains("requires rights `SIGNAL` incompatible with object `PROCESS`")
    );
}

#[test]
fn canonical_e0_task_syscall_contract_is_typed_and_staged() {
    let root = TempRoot::copy_schema();
    let model = Model::load(root.path()).unwrap();
    let process_create = model
        .syscalls
        .iter()
        .find(|syscall| syscall.name == "process_create")
        .unwrap();
    assert_eq!(process_create.phase, "DW0-F");

    for name in [
        "task_group_terminate",
        "process_terminate",
        "thread_terminate",
    ] {
        let syscall = model
            .syscalls
            .iter()
            .find(|syscall| syscall.name == name)
            .unwrap();
        let reason = syscall
            .arguments
            .iter()
            .find(|argument| argument.name == "reason")
            .unwrap();
        assert_eq!(reason.ty, "DwTerminationReason");
    }
}

#[test]
fn rejects_zero_duplicate_and_overwide_syscall_ids() {
    let root = TempRoot::copy_schema();
    root.rewrite("syscalls.toml", |text| {
        text.replacen("number = 0x00000001", "number = 0", 1)
    });
    assert!(load_error(&root).contains("syscall ID zero is reserved"));

    let root = TempRoot::copy_schema();
    root.rewrite("syscalls.toml", |text| {
        text.replacen("number = 0x00000010", "number = 0x00000001", 1)
    });
    assert!(load_error(&root).contains("duplicate syscall ID 0x00000001"));

    let root = TempRoot::copy_schema();
    root.rewrite("syscalls.toml", |text| {
        text.replacen(
            "arg5 = \"flags|u64|in|NONE|NONE\"",
            "arg5 = \"flags|u64|in|NONE|NONE\"\narg6 = \"extra|u64|in|NONE|NONE\"",
            1,
        )
    });
    assert!(load_error(&root).contains("has 7 arguments; maximum is 6"));

    let root = TempRoot::copy_schema();
    root.rewrite("syscalls.toml", |text| {
        text.replacen("number = 0x00000001", "number = 0xffff0001", 1)
    });
    assert!(load_error(&root).contains("debug/test syscall range is forbidden"));
}

#[test]
fn rejects_missing_or_mismatched_boot_contract_constants() {
    let root = TempRoot::copy_schema();
    root.rewrite("boot.toml", |text| {
        text.replacen(
            "name = \"DW_BOOT_INFO_V1_VERSION\"\ntype = \"u32\"\nvalue = 1",
            "name = \"DW_BOOT_INFO_V1_VERSION\"\ntype = \"u32\"\nvalue = 2",
            1,
        )
    });
    assert!(load_error(&root).contains(
        "boot contract constant `DW_BOOT_INFO_V1_VERSION` must have type u32 and value 1"
    ));

    let root = TempRoot::copy_schema();
    root.rewrite("boot.toml", |text| {
        text.replacen(
            "name = \"DW_BOOT_BASE_PAGE_SIZE\"",
            "name = \"DW_BOOT_PAGE_SIZE_MISSING\"",
            1,
        )
    });
    assert!(load_error(&root).contains(
        "boot contract requires constant `DW_BOOT_BASE_PAGE_SIZE` with type u32 and value 4096"
    ));
}

#[test]
fn generated_c_header_passes_clang_when_available() {
    if Command::new("clang").arg("--version").output().is_err() {
        return;
    }
    let root = TempRoot::copy_schema();
    run(["generate", "--root", root.path().to_str().unwrap()]).unwrap();
    let probe = root.path().join("abi/generated/header_probe.c");
    fs::write(
            &probe,
            "#include \"deepwyrm_abi.h\"\n_Static_assert(DW_STATUS_BAD_ADDRESS == -16, \"status parity\");\n_Static_assert(DW_RIGHT_MODIFY == 512, \"rights parity\");\n_Static_assert(DW_RIGHTS_KNOWN_MASK == 1023, \"known-rights parity\");\n_Static_assert(DW_OBJECT_COMPATIBLE_RIGHTS_MEMORY_OBJECT == 463, \"object-rights parity\");\n_Static_assert(DW_OBJECT_TYPE_TIMER == 8, \"object parity\");\n_Static_assert(DW_SYSCALL_TIMER_CANCEL == 0x00050012, \"syscall parity\");\n_Static_assert(DW_DEADLINE_INFINITE == UINT64_MAX, \"deadline parity\");\n_Static_assert(DW_BOOT_BASE_PAGE_SIZE == UINT32_C(4096), \"boot page parity\");\n_Static_assert(DW_BOOT_INFO_V1_VERSION == UINT32_C(1), \"boot version parity\");\n_Static_assert(DW_BOOT_MODULE_KIND_DEEPWYRM_X86_64_PAGING_HANDOFF_V1 == 3, \"paging module kind parity\");\n_Static_assert(DW_BOOT_X86_64_PAGING_HANDOFF_V1_SIZE == UINT32_C(112), \"paging header size parity\");\n_Static_assert(DW_BOOT_X86_64_PAGING_HANDOFF_TEMPORARY_VIRTUAL_ADDRESS == UINT64_C(0xffffff0000000000), \"paging temporary address parity\");\n_Static_assert(DW_BOOT_X86_64_PAGING_HANDOFF_PML4_INDEX == UINT16_C(510), \"paging PML4 parity\");\n_Static_assert(DW_BOOT_X86_64_PAGING_HANDOFF_MIN_TABLE_FRAME_COUNT == UINT32_C(4), \"paging minimum frames parity\");\n_Static_assert(DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT == UINT32_C(256), \"paging maximum frames parity\");\nint main(void) {\n    DwDeadline deadline = DW_DEADLINE_INFINITE;\n    uint32_t payload = DW_CHANNEL_MAX_PAYLOAD;\n    DwStatus status = DW_STATUS_SUCCESS;\n    return (deadline == 0 || payload == 0 || status != 0 || dw_object_compatible_rights(DW_OBJECT_TYPE_MEMORY_OBJECT) != DW_OBJECT_COMPATIBLE_RIGHTS_MEMORY_OBJECT || !dw_rights_are_known(DW_RIGHTS_KNOWN_MASK) || !dw_rights_are_compatible(DW_OBJECT_TYPE_MEMORY_OBJECT, DW_RIGHT_MAP) || dw_rights_are_compatible(DW_OBJECT_TYPE_TASK_GROUP, DW_RIGHT_READ));\n}\n",
        )
        .unwrap();
    let output = Command::new("clang")
        .args(["-std=c11", "-fsyntax-only"])
        .arg(&probe)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "clang stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
