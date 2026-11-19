use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
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
    let task_layout_path = manifest_dir.join("arch/x86_64/task_layout.toml");
    let pools_path = manifest_dir.join("arch/x86_64/pools.toml");
    let linker_path = manifest_dir.join("arch/x86_64/linker.ld");
    let entry_path = manifest_dir.join("src/arch/x86_64/entry.S");
    let exceptions_path = manifest_dir.join("src/arch/x86_64/exceptions.S");
    let ipi_entry_path = manifest_dir.join("src/arch/x86_64/ipi_entry.S");
    let syscall_path = manifest_dir.join("src/arch/x86_64/syscall_entry.S");
    let kernel_context_path = manifest_dir.join("src/arch/x86_64/kernel_context.S");
    let ap_trampoline_path = manifest_dir.join("src/arch/x86_64/ap_trampoline.S");

    println!("cargo:rerun-if-changed={}", layout_path.display());
    println!("cargo:rerun-if-changed={}", task_layout_path.display());
    println!("cargo:rerun-if-changed={}", pools_path.display());
    println!("cargo:rerun-if-changed={}", linker_path.display());
    println!("cargo:rerun-if-changed={}", entry_path.display());
    println!("cargo:rerun-if-changed={}", exceptions_path.display());
    println!("cargo:rerun-if-changed={}", ipi_entry_path.display());
    println!("cargo:rerun-if-changed={}", syscall_path.display());
    println!("cargo:rerun-if-changed={}", kernel_context_path.display());
    println!("cargo:rerun-if-changed={}", ap_trampoline_path.display());
    println!("cargo:rerun-if-env-changed=DEEPWYRM_ACCEPTED_RUST_LLD");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_CLANG");
    println!("cargo:rerun-if-env-changed=DEEPWYRM_BOOTFS_MAX_PAGES");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_c3_one_shot_ui)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_dw1e_platform)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_production_product)");
    println!("cargo:rustc-check-cfg=cfg(deepwyrm_integrated)");
    println!("cargo:rustc-cfg=deepwyrm_integrated");

    // DW1-F/WYR1-F F1A.2 moved the surface itself off the guest-test selector.
    // Every freestanding kernel now brings up the q35 IOAPIC and installs the
    // COM2 external-vector dispatch, because the whole WYR1 console spine
    // depends on interrupt-driven UART delivery: a kernel built without a
    // selector used to compile that path out entirely and could not reach a
    // prompt, which made the uninstrumented artifact something other than a
    // production system.
    //
    // Host builds stay excluded. The q35 modules already compile under
    // `cfg(test)` where host tests need them, and `idt.rs`'s
    // `only_approved_early_vectors_have_gates` asserts the non-q35 IDT shape
    // under `cfg(not(deepwyrm_dw1e_platform))`; emitting the cfg for host
    // builds would silently delete that coverage.
    if required_env("TARGET")? == KERNEL_TARGET {
        println!("cargo:rustc-cfg=deepwyrm_dw1e_platform");
    }

    // DW1-F/WYR1-F F2A.2. The production product is the freestanding kernel,
    // and until F2A.1 nothing in the tree said so: every capacity arm in
    // `activation/primordial.rs` keyed off an evidence cfg, so a build without
    // one fell through to the bootstrap-era DW0 geometry of three Processes
    // and one TaskGroup and could not instantiate the frozen six-role product.
    // This marker is what the production arm selects on. Host builds are
    // excluded, so the model tests keep the bootstrap-era shape they were
    // written against.
    if required_env("TARGET")? == KERNEL_TARGET {
        println!("cargo:rustc-cfg=deepwyrm_production_product");
    }

    let layout_source = fs::read_to_string(&layout_path)
        .map_err(|error| format!("{}: {error}", layout_path.display()))?;
    let layout = Layout::parse(&layout_source)
        .map_err(|error| format!("{}: {error}", layout_path.display()))?;
    let task_layout_source = fs::read_to_string(&task_layout_path)
        .map_err(|error| format!("{}: {error}", task_layout_path.display()))?;
    let task_layout = TaskLayout::parse(&task_layout_source)
        .map_err(|error| format!("{}: {error}", task_layout_path.display()))?;
    let pools_source = fs::read_to_string(&pools_path)
        .map_err(|error| format!("{}: {error}", pools_path.display()))?;
    let pools = Pools::parse(&pools_source, task_layout)
        .map_err(|error| format!("{}: {error}", pools_path.display()))?;
    emit_task_layout_env(task_layout);
    pools.emit_env();

    // Emitted for every configuration, so `PRIMORDIAL_BOOTFS_MAX_PAGES` can
    // read it with `env!` rather than `option_env!` and a second default.
    // F3A.6y.
    println!(
        "cargo:rustc-env=DEEPWYRM_BOOTFS_MAX_PAGES={}",
        production_bootfs_pages()?
    );

    if required_env("TARGET")? != KERNEL_TARGET {
        return Ok(());
    }

    let out_dir = PathBuf::from(required_env("OUT_DIR")?);
    let entry_object = out_dir.join("deepwyrm-x86_64-entry.o");
    let exceptions_object = out_dir.join("deepwyrm-x86_64-exceptions.o");
    let ipi_entry_object = out_dir.join("deepwyrm-x86_64-ipi-entry.o");
    let syscall_object = out_dir.join("deepwyrm-x86_64-syscall.o");
    let kernel_context_object = out_dir.join("deepwyrm-x86_64-kernel-context.o");
    let ap_trampoline_object = out_dir.join("deepwyrm-x86_64-ap-trampoline.o");
    assemble_source(&entry_path, &entry_object, layout)?;
    assemble_source(&exceptions_path, &exceptions_object, layout)?;
    assemble_source(&ipi_entry_path, &ipi_entry_object, layout)?;
    assemble_source(&syscall_path, &syscall_object, layout)?;
    assemble_source(&kernel_context_path, &kernel_context_object, layout)?;
    assemble_source(&ap_trampoline_path, &ap_trampoline_object, layout)?;

    let link_objects = vec![
        entry_object.as_path(),
        exceptions_object.as_path(),
        ipi_entry_object.as_path(),
        syscall_object.as_path(),
        kernel_context_object.as_path(),
        ap_trampoline_object.as_path(),
    ];
    for argument in linker_arguments(layout, task_layout, &linker_path, &link_objects) {
        println!("cargo:rustc-link-arg={argument}");
    }

    Ok(())
}

/// The production bootfs page ceiling, measured by the producer when it is
/// available and otherwise the historical Wave 4 constant.
///
/// F3A.6y. Production held a literal 17, which is a measurement of the Wave 4
/// archive, and eleven revisions of F3A were spent discovering that the
/// WYR1-F archive is 203 pages: a guessed constant made an oversized archive
/// surface as an opaque NO_RESOURCES from the bootstrap's bootfs mapping
/// instead of a build error.
///
/// The variable is **optional**, and that is deliberate. The production
/// kernel must build standalone -- `cargo build`, the host gates, the target
/// clippy lane -- where no archive exists to measure. So an absent variable
/// keeps the historical value rather than failing, and a present one is
/// validated.
fn production_bootfs_pages() -> Result<String, String> {
    const NAME: &str = "DEEPWYRM_BOOTFS_MAX_PAGES";
    resolve_production_bootfs_pages(env::var(NAME).ok())
}

/// The production ceiling for a `DEEPWYRM_BOOTFS_MAX_PAGES` value, or for its
/// absence (`None`, which an unreadable value also is).
fn resolve_production_bootfs_pages(value: Option<String>) -> Result<String, String> {
    // The Wave 4 archive's measured size, retained so a build with no producer
    // behaves exactly as it did before this revision.
    const HISTORICAL_WAVE4_PAGES: &str = "17";
    match value {
        None => Ok(HISTORICAL_WAVE4_PAGES.to_owned()),
        Some(value) => {
            validate_production_bootfs_pages(&value)?;
            Ok(value)
        }
    }
}

fn validate_production_bootfs_pages(value: &str) -> Result<usize, String> {
    const NAME: &str = "DEEPWYRM_BOOTFS_MAX_PAGES";
    let pages = value
        .parse::<usize>()
        .map_err(|_| format!("{NAME} must be canonical decimal"))?;
    if pages == 0 || pages > 8192 || pages.to_string() != value {
        return Err(format!("{NAME} must be canonical decimal in 1..=8192"));
    }
    Ok(pages)
}

fn emit_task_layout_env(layout: TaskLayout) {
    println!(
        "cargo:rustc-env=DEEPWYRM_E3_THREAD_STACK_COUNT={}",
        layout.thread_kernel_stack_count
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_E3_THREAD_STACK_SIZE={}",
        layout.thread_kernel_stack_size
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_E3_THREAD_STACK_GUARD_SIZE={}",
        layout.thread_kernel_stack_guard_size
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_E3_THREAD_STACK_ALIGNMENT={}",
        layout.thread_kernel_stack_alignment
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_COUNT={}",
        layout.privilege_entry_stack_count
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_SIZE={}",
        layout.privilege_entry_stack_size
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_GUARD_SIZE={}",
        layout.privilege_entry_stack_guard_size
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_E4_PRIVILEGE_ENTRY_STACK_ALIGNMENT={}",
        layout.privilege_entry_stack_alignment
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_TERMINAL_REAPER_STACK_COUNT={}",
        layout.terminal_reaper_stack_count
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_TERMINAL_REAPER_STACK_SIZE={}",
        layout.terminal_reaper_stack_size
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_TERMINAL_REAPER_STACK_GUARD_SIZE={}",
        layout.terminal_reaper_stack_guard_size
    );
    println!(
        "cargo:rustc-env=DEEPWYRM_TERMINAL_REAPER_STACK_ALIGNMENT={}",
        layout.terminal_reaper_stack_alignment
    );
}

pub(crate) fn linker_arguments(
    layout: Layout,
    task_layout: TaskLayout,
    linker_path: &Path,
    objects: &[&Path],
) -> Vec<String> {
    let mut arguments = vec![
        "-static".to_owned(),
        "-no-pie".to_owned(),
        "--no-dynamic-linker".to_owned(),
        "--build-id=none".to_owned(),
        "--no-eh-frame-hdr".to_owned(),
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
        format!(
            "--defsym=DW_KERNEL_THREAD_STACK_COUNT={}",
            task_layout.thread_kernel_stack_count
        ),
        format!(
            "--defsym=DW_KERNEL_THREAD_STACK_SIZE={}",
            task_layout.thread_kernel_stack_size
        ),
        format!(
            "--defsym=DW_KERNEL_THREAD_STACK_GUARD_SIZE={}",
            task_layout.thread_kernel_stack_guard_size
        ),
        format!(
            "--defsym=DW_KERNEL_THREAD_STACK_ALIGNMENT={}",
            task_layout.thread_kernel_stack_alignment
        ),
        format!(
            "--defsym=DW_KERNEL_PRIVILEGE_ENTRY_STACK_COUNT={}",
            task_layout.privilege_entry_stack_count
        ),
        format!(
            "--defsym=DW_KERNEL_PRIVILEGE_ENTRY_STACK_SIZE={}",
            task_layout.privilege_entry_stack_size
        ),
        format!(
            "--defsym=DW_KERNEL_PRIVILEGE_ENTRY_STACK_GUARD_SIZE={}",
            task_layout.privilege_entry_stack_guard_size
        ),
        format!(
            "--defsym=DW_KERNEL_PRIVILEGE_ENTRY_STACK_ALIGNMENT={}",
            task_layout.privilege_entry_stack_alignment
        ),
        format!(
            "--defsym=DW_KERNEL_TERMINAL_REAPER_STACK_COUNT={}",
            task_layout.terminal_reaper_stack_count
        ),
        format!(
            "--defsym=DW_KERNEL_TERMINAL_REAPER_STACK_SIZE={}",
            task_layout.terminal_reaper_stack_size
        ),
        format!(
            "--defsym=DW_KERNEL_TERMINAL_REAPER_STACK_GUARD_SIZE={}",
            task_layout.terminal_reaper_stack_guard_size
        ),
        format!(
            "--defsym=DW_KERNEL_TERMINAL_REAPER_STACK_ALIGNMENT={}",
            task_layout.terminal_reaper_stack_alignment
        ),
        format!("-T{}", linker_path.display()),
    ];
    for object in objects {
        arguments.push(object.display().to_string());
    }
    arguments
}

pub(crate) fn assemble_source(source: &Path, output: &Path, layout: Layout) -> Result<(), String> {
    let clang = env::var_os("DEEPWYRM_CLANG").unwrap_or_else(|| "clang".into());
    let status = Command::new(&clang)
        .args(assembler_arguments(source, output, layout))
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

/// The kernel assembler's exact Clang argument list, in order.
fn assembler_arguments(source: &Path, output: &Path, layout: Layout) -> Vec<OsString> {
    let mut arguments: Vec<OsString> = vec![
        "--no-default-config".into(),
        format!("--target={KERNEL_TARGET}").into(),
    ];
    arguments.extend(
        [
            "-ffreestanding",
            "-fno-pic",
            "-fno-stack-protector",
            "-mno-red-zone",
            "-mno-mmx",
            "-mno-sse",
            "-mno-sse2",
        ]
        .map(OsString::from),
    );
    arguments.push(
        format!(
            "-DDW_KERNEL_BOOT_STACK_SIZE={}",
            layout.kernel_boot_stack_size
        )
        .into(),
    );
    arguments.push(
        format!(
            "-DDW_KERNEL_BOOT_STACK_ALIGNMENT={}",
            layout.kernel_boot_stack_alignment
        )
        .into(),
    );
    arguments.push("-c".into());
    arguments.push(source.into());
    arguments.push("-o".into());
    arguments.push(output.into());
    arguments
}

fn required_env(name: &str) -> Result<String, String> {
    env::var(name).map_err(|error| format!("missing build environment {name}: {error}"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TaskLayout {
    pub(crate) thread_kernel_stack_count: u64,
    pub(crate) thread_kernel_stack_size: u64,
    pub(crate) thread_kernel_stack_guard_size: u64,
    pub(crate) thread_kernel_stack_alignment: u64,
    pub(crate) privilege_entry_stack_count: u64,
    pub(crate) privilege_entry_stack_size: u64,
    pub(crate) privilege_entry_stack_guard_size: u64,
    pub(crate) privilege_entry_stack_alignment: u64,
    pub(crate) terminal_reaper_stack_count: u64,
    pub(crate) terminal_reaper_stack_size: u64,
    pub(crate) terminal_reaper_stack_guard_size: u64,
    pub(crate) terminal_reaper_stack_alignment: u64,
}

impl TaskLayout {
    pub(crate) fn parse(source: &str) -> Result<Self, String> {
        let values = parse_flat_toml(source)?;
        let expected = [
            "schema",
            "version",
            "thread_kernel_stack_count",
            "thread_kernel_stack_size",
            "thread_kernel_stack_guard_size",
            "thread_kernel_stack_alignment",
            "privilege_entry_stack_count",
            "privilege_entry_stack_size",
            "privilege_entry_stack_guard_size",
            "privilege_entry_stack_alignment",
            "terminal_reaper_stack_count",
            "terminal_reaper_stack_size",
            "terminal_reaper_stack_guard_size",
            "terminal_reaper_stack_alignment",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if actual != expected {
            let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
            let unknown = actual.difference(&expected).copied().collect::<Vec<_>>();
            return Err(format!(
                "task-layout keys do not match contract; missing={missing:?}, unknown={unknown:?}"
            ));
        }
        expect_string(&values, "schema", "deepwyrm-x86_64-task-layout")?;
        expect_u64(&values, "version", 4)?;
        let count = parse_u64(required_value(&values, "thread_kernel_stack_count")?)?;
        let size = parse_u64(required_value(&values, "thread_kernel_stack_size")?)?;
        let guard = parse_u64(required_value(&values, "thread_kernel_stack_guard_size")?)?;
        let alignment = parse_u64(required_value(&values, "thread_kernel_stack_alignment")?)?;
        let privilege_count = parse_u64(required_value(&values, "privilege_entry_stack_count")?)?;
        let privilege_size = parse_u64(required_value(&values, "privilege_entry_stack_size")?)?;
        let privilege_guard =
            parse_u64(required_value(&values, "privilege_entry_stack_guard_size")?)?;
        let privilege_alignment =
            parse_u64(required_value(&values, "privilege_entry_stack_alignment")?)?;
        let terminal_count = parse_u64(required_value(&values, "terminal_reaper_stack_count")?)?;
        let terminal_size = parse_u64(required_value(&values, "terminal_reaper_stack_size")?)?;
        let terminal_guard =
            parse_u64(required_value(&values, "terminal_reaper_stack_guard_size")?)?;
        let terminal_alignment =
            parse_u64(required_value(&values, "terminal_reaper_stack_alignment")?)?;
        // W7 (root `STORAGE_PLAN.md`): the production ledger's thirty-two
        // identities, one guarded stack each.
        if count != 32
            || size != 524_288
            || guard != 4_096
            || alignment != 4_096
            || !size.is_multiple_of(alignment)
            || !guard.is_multiple_of(alignment)
        {
            return Err(
                "DW0-E3 thread stack pool must be 32 guarded 524288-byte stacks on 4096-byte boundaries"
                    .into(),
            );
        }
        if privilege_count != 1
            || privilege_size != 262_144
            || privilege_guard != 4_096
            || privilege_alignment != 4_096
            || !privilege_size.is_multiple_of(privilege_alignment)
            || !privilege_guard.is_multiple_of(privilege_alignment)
        {
            return Err("DW0-E4 BSP privilege-entry stack must be one guarded 262144-byte stack on a 4096-byte boundary".into());
        }
        if terminal_count != 1
            || terminal_size != 262_144
            || terminal_guard != 4_096
            || terminal_alignment != 4_096
            || !terminal_size.is_multiple_of(terminal_alignment)
            || !terminal_guard.is_multiple_of(terminal_alignment)
        {
            return Err("terminal reaper carrier must be one guarded 262144-byte stack on a 4096-byte boundary".into());
        }
        Ok(Self {
            thread_kernel_stack_count: count,
            thread_kernel_stack_size: size,
            thread_kernel_stack_guard_size: guard,
            thread_kernel_stack_alignment: alignment,
            privilege_entry_stack_count: privilege_count,
            privilege_entry_stack_size: privilege_size,
            privilege_entry_stack_guard_size: privilege_guard,
            privilege_entry_stack_alignment: privilege_alignment,
            terminal_reaper_stack_count: terminal_count,
            terminal_reaper_stack_size: terminal_size,
            terminal_reaper_stack_guard_size: terminal_guard,
            terminal_reaper_stack_alignment: terminal_alignment,
        })
    }
}

/// The production kernel's pool capacities (`arch/x86_64/pools.toml`).
#[allow(
    dead_code,
    reason = "the artifact contract tests include this build script and use only its layouts"
)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Pools {
    pub(crate) values: [(&'static str, u32); POOL_KEYS.len()],
}

pub(crate) const POOL_KEYS: [&str; 11] = [
    "handles_per_process",
    "identities",
    "registry_objects",
    "memory_objects",
    "mapping_leases",
    "region_slots",
    "channel_pairs",
    "channel_depth",
    "wait_registrations",
    "timers",
    "events",
];

#[allow(
    dead_code,
    reason = "the artifact contract tests include this build script and use only its layouts"
)]
impl Pools {
    pub(crate) fn parse(source: &str, task_layout: TaskLayout) -> Result<Self, String> {
        let values = parse_flat_toml(source)?;
        let expected = ["schema", "version"]
            .into_iter()
            .chain(POOL_KEYS)
            .collect::<BTreeSet<_>>();
        let actual = values.keys().map(String::as_str).collect::<BTreeSet<_>>();
        if actual != expected {
            let missing = expected.difference(&actual).copied().collect::<Vec<_>>();
            let unknown = actual.difference(&expected).copied().collect::<Vec<_>>();
            return Err(format!(
                "pool keys do not match contract; missing={missing:?}, unknown={unknown:?}"
            ));
        }
        expect_string(&values, "schema", "deepwyrm-x86_64-pools")?;
        expect_u64(&values, "version", 1)?;
        let mut pools = Self {
            values: POOL_KEYS.map(|key| (key, 0)),
        };
        for (key, slot) in POOL_KEYS
            .iter()
            .zip(pools.values.iter_mut().map(|(_, value)| value))
        {
            let value = parse_u64(required_value(&values, key)?)?;
            let value = u32::try_from(value)
                .ok()
                .filter(|value| *value > 0)
                .ok_or_else(|| format!("`{key}` must be a nonzero 32-bit count"))?;
            *slot = value;
        }
        // Ceilings that `xtask kernel-check` measured the kernel stacks at:
        // the map path's frames scale with the region's slots, and the handle
        // tables are static storage in every Process. Raising either is a
        // reviewed edit here, with kernel-check rerun (security review
        // 2026-11-13, R1).
        for (key, ceiling) in [("region_slots", 64), ("handles_per_process", 96)] {
            if pools.get(key) > ceiling {
                return Err(format!(
                    "`{key}` ({}) exceeds the {ceiling} the kernel's stack bound was measured at",
                    pools.get(key)
                ));
            }
        }
        if u64::from(pools.get("identities")) > task_layout.thread_kernel_stack_count {
            return Err(format!(
                "`identities` ({}) exceeds the {} thread kernel stacks of task_layout.toml; \
                 every Thread needs one",
                pools.get("identities"),
                task_layout.thread_kernel_stack_count
            ));
        }
        Ok(pools)
    }

    pub(crate) fn get(&self, key: &str) -> u32 {
        self.values
            .iter()
            .find_map(|(name, value)| (*name == key).then_some(*value))
            .unwrap_or(0)
    }

    fn emit_env(&self) {
        for (key, value) in self.values {
            println!(
                "cargo:rustc-env=DEEPWYRM_POOL_{}={value}",
                key.to_ascii_uppercase()
            );
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Layout {
    pub(crate) link_base: u64,
    pub(crate) base_page_size: u64,
    pub(crate) kernel_boot_stack_size: u64,
    pub(crate) kernel_boot_stack_alignment: u64,
    #[allow(
        dead_code,
        reason = "published intake limits are consumed by contract agreement tests"
    )]
    pub(crate) max_normalized_memory_map_entries: u64,
    #[allow(
        dead_code,
        reason = "published intake limits are consumed by contract agreement tests"
    )]
    pub(crate) max_module_entries: u64,
    #[allow(
        dead_code,
        reason = "published transition-table values are consumed by contract agreement tests"
    )]
    pub(crate) temporary_virtual_address: u64,
    #[allow(
        dead_code,
        reason = "published transition-table values are consumed by contract agreement tests"
    )]
    pub(crate) temporary_indices: [u16; 4],
    #[allow(
        dead_code,
        reason = "published transition-table values are consumed by contract agreement tests"
    )]
    pub(crate) minimum_table_frame_count: u64,
    #[allow(
        dead_code,
        reason = "published transition-table values are consumed by contract agreement tests"
    )]
    pub(crate) maximum_table_frame_count: u64,
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
            "handoff_mappings.referenced_ranges_mutable",
            "handoff_mappings.page_zero_mapped",
            "handoff_mappings.framebuffer_pixels_identity_mapped",
            "early_intake.max_normalized_memory_map_entries",
            "early_intake.max_module_entries",
            "early_intake.acpi_scope",
            "early_intake.acpi_guid_preference",
            "early_intake.acpi_duplicate_selected_guid",
            "early_intake.acpi_preferred_invalid",
            "early_intake.acpi_rsdp_signature",
            "early_intake.acpi_rsdp_length_rule",
            "early_intake.acpi_rsdp_checksum",
            "early_intake.acpi_rsdp_mapping",
            "early_intake.acpi_rsdp_max_intersecting_pages",
            "early_intake.acpi_mapping_overlap",
            "early_intake.acpi_table_traversal",
            "early_intake.acpi_memory_types_identity_mapped",
            "transition_tables.contract",
            "transition_tables.layout_version",
            "transition_tables.temporary_virtual_address",
            "transition_tables.temporary_page_count",
            "transition_tables.pml4_index",
            "transition_tables.pdpt_index",
            "transition_tables.pd_index",
            "transition_tables.pt_index",
            "transition_tables.minimum_table_frame_count",
            "transition_tables.maximum_table_frame_count",
            "transition_tables.initial_leaf",
            "transition_tables.temporary_leaf_permissions",
            "transition_tables.identity_alias_permissions",
            "transition_tables.identity_alias_mutable_by_deepwyrm",
            "transition_tables.cache_selection_bits",
            "transition_tables.pat_entry_zero",
            "transition_tables.mtrr_policy",
            "transition_tables.pcide_enabled",
            "transition_tables.pge_enabled",
            "transition_tables.cr3_low_bits_zero",
            "transition_tables.ownership_transfer",
            "transition_tables.lifetime",
            "transition_tables.concurrency",
            "transition_tables.physical_role_policy",
            "transition_tables.new_root_table_access",
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
        expect_u64(&values, "version", 2)?;
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
            ("early_intake.acpi_scope", "rsdp-only"),
            (
                "early_intake.acpi_guid_preference",
                "ACPI_20_TABLE_GUID-then-ACPI_TABLE_GUID",
            ),
            ("early_intake.acpi_duplicate_selected_guid", "reject"),
            ("early_intake.acpi_preferred_invalid", "reject-no-downgrade"),
            ("early_intake.acpi_rsdp_signature", "RSD PTR "),
            (
                "early_intake.acpi_rsdp_length_rule",
                "revision-lt-2:20;revision-ge-2:declared-36..4096",
            ),
            (
                "early_intake.acpi_rsdp_checksum",
                "v1-first-20-and-v2-full-record",
            ),
            (
                "early_intake.acpi_rsdp_mapping",
                "validated-record-intersecting-base-pages-only",
            ),
            ("early_intake.acpi_mapping_overlap", "coalesce"),
            ("early_intake.acpi_table_traversal", "deferred-dw0-c"),
            (
                "transition_tables.contract",
                "DW_BOOT_X86_64_PAGING_HANDOFF_V1",
            ),
            ("transition_tables.initial_leaf", "exactly-zero-non-present"),
            (
                "transition_tables.temporary_leaf_permissions",
                "supervisor-rw-nx-base-page",
            ),
            (
                "transition_tables.identity_alias_permissions",
                "supervisor-rw-nx-base-page",
            ),
            ("transition_tables.pat_entry_zero", "observed-write-back"),
            (
                "transition_tables.mtrr_policy",
                "alias-consistent-no-effective-write-back-claim",
            ),
            (
                "transition_tables.ownership_transfer",
                "loader-to-deepwyrm-after-exit-boot-services",
            ),
            ("transition_tables.lifetime", "until-deepwyrm-cr3-switch"),
            (
                "transition_tables.concurrency",
                "bsp-aps-off-if-clear-nonreentrant",
            ),
            (
                "transition_tables.physical_role_policy",
                "exclusive-table-frames-no-kernel-module-data-alias",
            ),
            (
                "transition_tables.new_root_table_access",
                "deepwyrm-owned-before-cr3-switch",
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
            "handoff_mappings.referenced_ranges_mutable",
            "handoff_mappings.page_zero_mapped",
            "handoff_mappings.framebuffer_pixels_identity_mapped",
            "early_intake.acpi_memory_types_identity_mapped",
            "transition_tables.pcide_enabled",
            "transition_tables.pge_enabled",
        ] {
            expect_bool(&values, key, false)?;
        }
        expect_bool(
            &values,
            "transition_tables.identity_alias_mutable_by_deepwyrm",
            true,
        )?;
        expect_bool(&values, "transition_tables.cr3_low_bits_zero", true)?;

        let link_base = parse_hex_string(required_value(&values, "link_base")?)?;
        let base_page_size = parse_u64(required_value(&values, "base_page_size")?)?;
        let kernel_boot_stack_size = parse_u64(required_value(&values, "kernel_boot_stack_size")?)?;
        let kernel_boot_stack_alignment =
            parse_u64(required_value(&values, "kernel_boot_stack_alignment")?)?;
        let max_normalized_memory_map_entries = parse_u64(required_value(
            &values,
            "early_intake.max_normalized_memory_map_entries",
        )?)?;
        let max_module_entries =
            parse_u64(required_value(&values, "early_intake.max_module_entries")?)?;
        let temporary_virtual_address = parse_hex_string(required_value(
            &values,
            "transition_tables.temporary_virtual_address",
        )?)?;
        let temporary_indices = [
            parse_index(&values, "transition_tables.pml4_index")?,
            parse_index(&values, "transition_tables.pdpt_index")?,
            parse_index(&values, "transition_tables.pd_index")?,
            parse_index(&values, "transition_tables.pt_index")?,
        ];
        let minimum_table_frame_count = parse_u64(required_value(
            &values,
            "transition_tables.minimum_table_frame_count",
        )?)?;
        let maximum_table_frame_count = parse_u64(required_value(
            &values,
            "transition_tables.maximum_table_frame_count",
        )?)?;

        expect_u64(&values, "early_intake.acpi_rsdp_max_intersecting_pages", 2)?;
        expect_u64(&values, "transition_tables.layout_version", 2)?;
        expect_u64(&values, "transition_tables.temporary_page_count", 1)?;
        expect_u64(&values, "transition_tables.cache_selection_bits", 0)?;

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
        if kernel_boot_stack_size != 4_194_304
            || kernel_boot_stack_size % kernel_boot_stack_alignment != 0
        {
            return Err("kernel boot stack must be an aligned 4194304-byte range".into());
        }
        if max_normalized_memory_map_entries != 128 || max_module_entries != 16 {
            return Err("early intake limits must match the bounded BootInfo snapshots".into());
        }
        if temporary_virtual_address != 0xffff_ff00_0000_0000
            || temporary_virtual_address % base_page_size != 0
            || temporary_virtual_address < 0xffff_8000_0000_0000
        {
            return Err("temporary mapping address must be the dedicated upper-half page".into());
        }
        let derived_indices = [
            ((temporary_virtual_address >> 39) & 0x1ff) as u16,
            ((temporary_virtual_address >> 30) & 0x1ff) as u16,
            ((temporary_virtual_address >> 21) & 0x1ff) as u16,
            ((temporary_virtual_address >> 12) & 0x1ff) as u16,
        ];
        if temporary_indices != derived_indices || temporary_indices != [510, 0, 0, 0] {
            return Err("temporary mapping indices must be derived from the dedicated VA".into());
        }
        if minimum_table_frame_count != 4 || maximum_table_frame_count != 256 {
            return Err("transition table frame bounds must be 4..=256".into());
        }
        if temporary_indices[0] == ((link_base >> 39) & 0x1ff) as u16 {
            return Err("temporary mapping must not share the kernel PT_LOAD PML4 slot".into());
        }

        Ok(Self {
            link_base,
            base_page_size,
            kernel_boot_stack_size,
            kernel_boot_stack_alignment,
            max_normalized_memory_map_entries,
            max_module_entries,
            temporary_virtual_address,
            temporary_indices,
            minimum_table_frame_count,
            maximum_table_frame_count,
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
            if !matches!(
                name,
                "load_policy"
                    | "entry_state"
                    | "handoff_mappings"
                    | "early_intake"
                    | "transition_tables"
            ) {
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

fn parse_index(values: &BTreeMap<String, String>, key: &str) -> Result<u16, String> {
    let value = parse_u64(required_value(values, key)?)?;
    u16::try_from(value)
        .ok()
        .filter(|value| *value < 512)
        .ok_or_else(|| format!("{key} must be a four-level page-table index"))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// F3A.6y. Production's ceiling is now measured when a producer measured
    /// it, and the historical Wave 4 value otherwise.
    ///
    /// The default matters as much as the validation: the production kernel
    /// must build standalone, and silently changing what a plain `cargo build`
    /// admits would be a behaviour change smuggled in behind a diagnostic fix.
    #[test]
    fn the_production_bootfs_bound_is_measured_when_measured_and_historical_otherwise() {
        // 203 is the WYR1-F archive that exposed the 17-page ceiling (F3A.6x);
        // the bound must accept it and the whole range the const parser asserts.
        for (value, pages) in [("1", 1), ("17", 17), ("203", 203), ("8192", 8192)] {
            assert_eq!(validate_production_bootfs_pages(value), Ok(pages));
        }
        // Non-canonical and out-of-range values are refused rather than
        // silently clamped -- a clamped ceiling is the guess this replaced.
        for invalid in ["", "0", "01", "+1", " 17", "17 ", "8193", "not-pages"] {
            assert!(
                validate_production_bootfs_pages(invalid).is_err(),
                "{invalid:?} must be refused"
            );
        }
    }

    #[test]
    fn an_unmeasured_production_build_admits_the_historical_seventeen_pages() {
        assert_eq!(resolve_production_bootfs_pages(None), Ok("17".to_owned()));
        assert_eq!(
            resolve_production_bootfs_pages(Some("40".to_owned())),
            Ok("40".to_owned())
        );
        for invalid in ["0", "017", "8193", "", "x"] {
            assert!(
                resolve_production_bootfs_pages(Some(invalid.to_owned())).is_err(),
                "{invalid:?} was accepted as a bootfs ceiling"
            );
        }
    }

    #[test]
    fn kernel_assembler_disables_clang_default_configuration_before_target_selection() {
        let layout = Layout::parse(include_str!("arch/x86_64/layout.toml")).unwrap();
        let arguments = assembler_arguments(Path::new("entry.S"), Path::new("entry.o"), layout);
        let position = |wanted: &str| {
            let mut matches = arguments
                .iter()
                .enumerate()
                .filter(|(_, argument)| *argument == wanted);
            let (index, _) = matches
                .next()
                .unwrap_or_else(|| panic!("assembler arguments omit {wanted}"));
            assert!(matches.next().is_none(), "{wanted} is passed twice");
            index
        };
        assert!(
            position("--no-default-config") < position(&format!("--target={KERNEL_TARGET}")),
            "Clang default configuration must be disabled before target selection"
        );
    }
}
