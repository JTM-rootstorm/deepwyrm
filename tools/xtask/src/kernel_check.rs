//! `kernel-check`: the production kernel image checks, including the static
//! half of DW2 M5's lean stack check (`Plans/DW2_LARGE_MEMORY_PLAN.md` §10.2
//! item 2).
//!
//! It builds the production kernel and an analysis copy on the target lane.
//! The analysis copy adds only LLVM's stack-size section and the linker's
//! relocations; the check proves its code is byte-identical to production,
//! then bounds the direct-call chains from each kernel entry against the stack
//! that entry runs on.

use super::*;

mod elf;
#[cfg(test)]
mod tests;

use elf::{BoundError, CallGraph, Elf, deepest_path, display_name};

/// Bytes of each kernel stack a static bound may use: a quarter stays spare
/// for what a static bound cannot see (DW2 plan §10.2 item 2).
const fn usable(stack: u64) -> u64 {
    stack / 4 * 3
}

/// The assembly that enters each stack saves the interrupted state there
/// before it calls Rust; its pushes are not in any Rust frame. The largest
/// such frame (the syscall frame) is under 512 bytes.
const ENTRY_FRAME_ALLOWANCE: u64 = 1024;

const THREAD_STACK: u64 = 512 * 1024;
const PRIVILEGE_ENTRY_STACK: u64 = 256 * 1024;
const TERMINAL_REAPER_STACK: u64 = 256 * 1024;
const IST_STACK: u64 = 16 * 1024;

/// One kernel stack and the Rust entry points that run on it. `nested` are
/// entries that may run on top of any `roots` entry on the same stack (a
/// kernel-origin exception or interrupt), so their deepest path is added to
/// the deepest root's.
struct StackBudget {
    name: &'static str,
    bytes: u64,
    roots: &'static [&'static str],
    nested: &'static [&'static str],
}

/// Which stack each entry runs on comes from the entry assembly
/// (`kernel/src/arch/x86_64/{syscall_entry,exceptions}.S`): SYSCALL and
/// interrupts from user mode land on the CPU's privilege-entry stack; the
/// syscall entry, the timer's preemption gate and the exception path copy their
/// frame onto the current Thread's kernel stack before Rust can block; the two
/// reaper handoffs pivot to the CPU's reaper stack. An entry whose stack this
/// table cannot pin down is listed under both stacks it may use.
const BUDGETS: &[StackBudget] = &[
    StackBudget {
        name: "thread kernel stack",
        bytes: THREAD_STACK,
        roots: &[
            "dw_x86_64_syscall_dispatch",
            "dw_x86_64_first_run_thread_entry",
            "dw_x86_64_timer_pre_iret_gate",
            "dw_x86_64_rendezvous_pre_iret_gate",
            "dw_x86_64_user_page_fault_gate",
            "dw_x86_64_exception_dispatch",
        ],
        nested: &[
            "dw_x86_64_exception_dispatch",
            "dw_x86_64_timer_interrupt_dispatch",
            "dw_x86_64_terminal_interrupt_dispatch",
            "dw_x86_64_q35_com2_interrupt_dispatch",
            "dw_x86_64_rendezvous_ipi_dispatch",
            "dw_x86_64_tlb_shootdown_ipi_dispatch",
        ],
    },
    StackBudget {
        name: "privilege-entry stack",
        bytes: PRIVILEGE_ENTRY_STACK,
        roots: &[
            "dw_x86_64_timer_interrupt_dispatch",
            "dw_x86_64_exception_dispatch",
            "dw_x86_64_terminal_interrupt_dispatch",
            "dw_x86_64_q35_com2_interrupt_dispatch",
            "dw_x86_64_rendezvous_ipi_dispatch",
            "dw_x86_64_tlb_shootdown_ipi_dispatch",
        ],
        nested: &[],
    },
    StackBudget {
        name: "terminal reaper stack",
        bytes: TERMINAL_REAPER_STACK,
        roots: &["dw_x86_64_rendezvous_reaper", TERMINAL_REAPER],
        nested: &[],
    },
    // NMI, double fault and machine check enter the common exception path on
    // their own IST stacks.
    StackBudget {
        name: "IST stack",
        bytes: IST_STACK,
        roots: &["dw_x86_64_exception_dispatch"],
        nested: &[],
    },
];

/// `dw_x86_64_terminal_reaper_handoff` calls the reaper through a register,
/// so it is named here: every instance of the generic reaper is a root.
const TERMINAL_REAPER: &str = "30native_runtime_terminal_reaper";

/// The one indirect call the bound resolves by name: the bound runtime's jump
/// into its carrier's trampoline (`syscall/live.rs`).
const RESOLVED_INDIRECT: &[(&str, &str)] =
    &[("22dispatch_bound_runtime", "25native_runtime_trampoline")];

/// Functions that call themselves to a depth their arguments bound, and that
/// depth. Any other recursion fails the check.
const BOUNDED_RECURSION: &[(&str, u64)] = &[
    // `vtd/tables.rs`: one call per page-table level, entered at level 4.
    ("10free_level", 4),
];

/// A panic or formatting path is terminal: the kernel halts, and an overflow
/// on the way becomes a double fault on its own IST stack, which halts too.
fn terminal(name: &str) -> bool {
    ["panic", "4core3fmt", "13expect_failed", "13unwrap_failed"]
        .iter()
        .any(|marker| name.contains(marker))
        || name == "rust_begin_unwind"
}

/// Symbols and byte strings that only test and selector builds may contain.
const TEST_ONLY_SYMBOLS: &[&str] = &[
    "test_support",
    "run_memory_foundation_test",
    "dw_test_",
    "complete_known_outcome",
    "EXPECTED_FAULT",
    "run_task_userspace_test",
    "E7SmokeRuntime",
];
const TEST_ONLY_BYTES: &[&str] = &[
    "DWTEST1",
    "dw_test_",
    "EXPECTED_FAULT",
    "complete_known_outcome",
    "isa-debug-exit",
];

fn root_indices(graph: &CallGraph, root: &str) -> Vec<usize> {
    if root.starts_with("dw_") {
        graph.matching(|name| name == root)
    } else {
        graph.matching(|name| name.contains(root) && !name.starts_with("_RNC"))
    }
}

struct Bound {
    bytes: u64,
    path: Vec<usize>,
}

fn deepest(graph: &CallGraph, roots: &[&str]) -> Result<Option<Bound>, String> {
    let mut best: Option<Bound> = None;
    for root in roots {
        let indices = root_indices(graph, root);
        if indices.is_empty() {
            return Err(format!("the kernel has no entry {root}"));
        }
        for index in indices {
            let (bytes, path) = deepest_path(graph, index, &terminal).map_err(|error| {
                let (what, path) = match error {
                    BoundError::Recursion(path) => ("recursion", path),
                    BoundError::NoFrame(path) => ("a function with no frame size", path),
                };
                let mut message = format!("{} reaches {what}:", display_name(root));
                for node in path {
                    message.push_str("\n    ");
                    message.push_str(&display_name(&graph.functions[node].name));
                }
                message
            })?;
            if best.as_ref().is_none_or(|b| bytes > b.bytes) {
                best = Some(Bound { bytes, path });
            }
        }
    }
    Ok(best)
}

fn print_path(out: &mut impl Write, graph: &CallGraph, path: &[usize]) -> io::Result<()> {
    for node in path {
        let frame = match (graph.frames[*node], graph.decoded.contains(node)) {
            (Some(frame), false) => frame.to_string(),
            (Some(frame), true) => format!("~{frame}"),
            (None, _) => "?".into(),
        };
        let name = display_name(&graph.functions[*node].name);
        let short: String = name.chars().take(140).collect();
        writeln!(out, "    {frame:>7}  {short}")?;
    }
    Ok(())
}

/// Checks one analysis image's stack bounds; returns the failures.
fn check_stacks(elf: &Elf<'_>, out: &mut impl Write) -> Result<Vec<String>, String> {
    let mut graph = CallGraph::build(elf.functions()?, &elf.stack_sizes()?, &elf.branches()?)?;
    for index in 0..graph.functions.len() {
        if graph.frames[index].is_none() {
            graph.frames[index] = Some(elf.prologue_frame(&graph.functions[index])?);
            graph.decoded.insert(index);
        }
    }
    for (from, to) in RESOLVED_INDIRECT {
        let sources = graph.matching(|name| name.contains(from));
        let targets = graph.matching(|name| name.contains(to) && !name.starts_with("_RNC"));
        if sources.is_empty() || targets.is_empty() {
            return Err(format!("the named indirect call {from} -> {to} is gone"));
        }
        for source in &sources {
            for target in &targets {
                graph.add_edge(*source, *target);
            }
        }
    }
    for (name, depth) in BOUNDED_RECURSION {
        let matches = graph.matching(|symbol| symbol.contains(name));
        if matches.is_empty() {
            return Err(format!("the bounded recursion {name} is gone"));
        }
        for index in matches {
            graph.unroll_self_recursion(index, *depth);
        }
    }
    let mut failures = Vec::new();
    for budget in BUDGETS {
        let root = deepest(&graph, budget.roots)?.ok_or("a budget has no roots")?;
        let nested = deepest(&graph, budget.nested)?;
        let nested_bytes = nested
            .as_ref()
            .map_or(0, |n| n.bytes + ENTRY_FRAME_ALLOWANCE);
        let total = root.bytes + ENTRY_FRAME_ALLOWANCE + nested_bytes;
        let limit = usable(budget.bytes);
        let verdict = if total <= limit { "ok" } else { "OVER" };
        writeln!(
            out,
            "{}: {} of {} usable bytes ({} KiB stack) [{verdict}]",
            budget.name,
            total,
            limit,
            budget.bytes / 1024
        )
        .map_err(|e| e.to_string())?;
        writeln!(out, "  deepest entry, {} bytes:", root.bytes).map_err(|e| e.to_string())?;
        print_path(out, &graph, &root.path).map_err(|e| e.to_string())?;
        if let Some(nested) = nested {
            writeln!(out, "  deepest nested entry, {} bytes:", nested.bytes)
                .map_err(|e| e.to_string())?;
            print_path(out, &graph, &nested.path).map_err(|e| e.to_string())?;
        }
        if total > limit {
            failures.push(format!(
                "the {} needs {total} bytes, over the {limit} a quarter spare allows",
                budget.name
            ));
        }
    }
    Ok(failures)
}

/// The production image's own checks: freestanding, and free of test code.
fn check_production(
    elf: &Elf<'_>,
    bytes: &[u8],
    selectors: &[String],
) -> Result<Vec<String>, String> {
    let mut failures = Vec::new();
    if let Some(problem) = elf.freestanding_problem() {
        failures.push(problem.to_owned());
    }
    for function in elf.functions()? {
        if let Some(marker) = TEST_ONLY_SYMBOLS
            .iter()
            .find(|m| function.name.contains(*m))
        {
            failures.push(format!(
                "production retains test-only symbol {} ({marker})",
                display_name(&function.name)
            ));
        }
    }
    let markers = TEST_ONLY_BYTES
        .iter()
        .map(|m| m.as_bytes())
        .chain(selectors.iter().map(|s| s.as_bytes()));
    for marker in markers {
        if bytes.windows(marker.len()).any(|window| window == marker) {
            failures.push(format!(
                "production retains test marker {}",
                String::from_utf8_lossy(marker)
            ));
        }
    }
    Ok(failures)
}

fn build_kernel(
    workspace: &Path,
    target_dir: &Path,
    analysis: bool,
) -> io::Result<Option<PathBuf>> {
    fs::create_dir_all(target_dir)?;
    let mut command = Command::new(workspace.join("tools/pinned-cargo"));
    command
        .current_dir(workspace)
        .env_remove("CARGO_HOME")
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("DEEPWYRM_GUEST_TEST_SELECTOR")
        .env_remove("DEEPWYRM_GUEST_TEST_ID")
        .env_remove("DEEPWYRM_EMIT_STACK_SIZES")
        .env("DEEPWYRM_PINNED_TARGET_DIR", target_dir)
        .stdin(Stdio::null())
        .args([
            "target",
            "build",
            "--locked",
            "--offline",
            "--release",
            "--target",
            "x86_64-unknown-none",
            "--package",
            "deepwyrm-kernel",
            "--bin",
            "deepwyrm-kernel",
        ]);
    if analysis {
        command.env("DEEPWYRM_EMIT_STACK_SIZES", "1");
    }
    if !command.status()?.success() {
        return Ok(None);
    }
    Ok(Some(
        target_dir.join("x86_64-unknown-none/release/deepwyrm-kernel"),
    ))
}

pub(super) fn run_kernel_check() -> io::Result<u8> {
    let workspace = workspace_root();
    let Some(selectors) = read_implemented_guest_selectors()? else {
        return Ok(EXIT_NOT_IMPLEMENTED);
    };
    let mut stderr = io::stderr().lock();
    let mut stdout = io::stdout().lock();
    let state = workspace.join(".tmp");
    let Some(production) = build_kernel(&workspace, &state.join("kernel-check"), false)? else {
        writeln!(stderr, "error: the production kernel did not build")?;
        return Ok(EXIT_NOT_IMPLEMENTED);
    };
    let Some(analysis) = build_kernel(&workspace, &state.join("stack-check"), true)? else {
        writeln!(stderr, "error: the stack analysis kernel did not build")?;
        return Ok(EXIT_NOT_IMPLEMENTED);
    };
    let production_bytes = fs::read(&production)?;
    let analysis_bytes = fs::read(&analysis)?;
    let result = (|| -> Result<Vec<String>, String> {
        let production_elf = Elf::parse(&production_bytes)?;
        let analysis_elf = Elf::parse(&analysis_bytes)?;
        let mut failures = check_production(&production_elf, &production_bytes, &selectors)?;
        if production_elf.section_bytes(".text")? != analysis_elf.section_bytes(".text")?
            || production_elf.section_bytes(".rodata")? != analysis_elf.section_bytes(".rodata")?
        {
            failures.push("the analysis kernel's code differs from production".into());
        }
        failures.extend(check_stacks(&analysis_elf, &mut stdout)?);
        Ok(failures)
    })();
    match result {
        Ok(failures) if failures.is_empty() => {
            writeln!(stdout, "kernel-check: passed")?;
            Ok(0)
        }
        Ok(failures) => {
            for failure in failures {
                writeln!(stderr, "error: {failure}")?;
            }
            Ok(EXIT_NOT_IMPLEMENTED)
        }
        Err(error) => {
            writeln!(stderr, "error: {error}")?;
            Ok(EXIT_NOT_IMPLEMENTED)
        }
    }
}
