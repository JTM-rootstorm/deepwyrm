use super::*;

pub(super) fn symbols(llvm_nm: &VerifiedExecutable, artifact: &Path) -> String {
    let mut command = verified_helper_command(llvm_nm);
    let output = run_output(
        command.args(["--defined-only", "--demangle"]).arg(artifact),
        "llvm-nm",
    );
    String::from_utf8(output.stdout).expect("llvm-nm output is UTF-8")
}

pub(super) fn disassembly(llvm_objdump: &VerifiedExecutable, artifact: &Path) -> String {
    let mut command = verified_helper_command(llvm_objdump);
    let output = run_output(
        command
            .args(["--disassemble", "--demangle", "--x86-asm-syntax=intel"])
            .arg(artifact),
        "llvm-objdump",
    );
    String::from_utf8(output.stdout).expect("llvm-objdump output is UTF-8")
}

pub(super) fn resolved_read_only_indirect_disassembly(
    llvm_objdump: &VerifiedExecutable,
    llvm_nm: &VerifiedExecutable,
    artifact: &Path,
) -> String {
    let disassembly = disassembly(llvm_objdump, artifact);
    let bytes = fs::read(artifact).expect("read target ELF for indirect-call resolution");
    let named_addresses = named_symbol_addresses(&symbols(llvm_nm, artifact));
    resolve_read_only_indirect_disassembly(&disassembly, |slot| {
        let target = read_nonwritable_elf_pointer(&bytes, slot)
            .unwrap_or_else(|| panic!("indirect control-transfer slot {slot:#x} is not immutable"));
        let symbol = named_addresses.get(&target).unwrap_or_else(|| {
            panic!("immutable control-transfer slot names unresolved target {target:#x}")
        });
        (target, symbol.clone())
    })
}

fn resolve_read_only_indirect_disassembly(
    disassembly: &str,
    mut resolve_slot: impl FnMut(u64) -> (u64, String),
) -> String {
    let mut pending_slot = None;
    let mut spilled_slots = BTreeMap::<String, u64>::new();
    let mut resolved = String::with_capacity(disassembly.len());

    for line in disassembly.lines() {
        if line.ends_with(">:") && line.contains('<') {
            pending_slot = None;
            spilled_slots.clear();
        }
        if line.contains("\tmov\trax, qword ptr [rip + ") {
            pending_slot = line
                .split_once(" # 0x")
                .and_then(|(_, address)| address.split_whitespace().next())
                .and_then(|address| u64::from_str_radix(address, 16).ok());
            resolved.push_str(line);
            resolved.push('\n');
            continue;
        }
        if let Some(stack_slot) = stack_slot_loaded_into_rax(line) {
            pending_slot = spilled_slots.get(stack_slot).copied();
            resolved.push_str(line);
            resolved.push('\n');
            continue;
        }
        if let Some(stack_slot) = stack_slot_stored_from_rax(line) {
            if let Some(slot) = pending_slot {
                spilled_slots.insert(stack_slot.to_owned(), slot);
            } else {
                spilled_slots.remove(stack_slot);
            }
            resolved.push_str(line);
            resolved.push('\n');
            continue;
        }
        spilled_slots.retain(|stack_slot, _| !line.contains(stack_slot.as_str()));
        if line.contains("\tcall\tqword ptr [rip + ") || line.contains("\tjmp\tqword ptr [rip + ") {
            let slot = line
                .split_once(" # 0x")
                .and_then(|(_, address)| address.split_whitespace().next())
                .and_then(|address| u64::from_str_radix(address, 16).ok())
                .expect("RIP-memory control transfer names its pointer slot");
            let (target, symbol) = resolve_slot(slot);
            let (prefix, kind) = if let Some((prefix, _)) = line.split_once("\tcall\t") {
                (prefix, "call")
            } else {
                (
                    line.split_once("\tjmp\t")
                        .map(|(prefix, _)| prefix)
                        .expect("matched RIP-memory jump"),
                    "jmp",
                )
            };
            resolved.push_str(prefix);
            resolved.push('\t');
            resolved.push_str(kind);
            resolved.push_str("\t0x");
            resolved.push_str(&format!("{target:x} <{symbol}>\n"));
            pending_slot = None;
            continue;
        }
        if line.contains("\tcall\trax")
            && let Some(slot) = pending_slot.take()
        {
            let (target, symbol) = resolve_slot(slot);
            let prefix = line
                .split_once("\tcall\trax")
                .map(|(prefix, _)| prefix)
                .expect("matched indirect call");
            resolved.push_str(prefix);
            resolved.push_str("\tcall\t0x");
            resolved.push_str(&format!("{target:x} <{symbol}>\n"));
            continue;
        }
        if pending_slot.is_some() && preserves_rax_slot_through_argument_setup(line) {
            resolved.push_str(line);
            resolved.push('\n');
            continue;
        }
        // Only the exact adjacent immutable-slot load/call idiom is eligible.
        // A closed set of argument-register setup instructions may intervene;
        // every other instruction may replace or transform RAX and must leave
        // a later indirect transfer unresolved for the graph to reject.
        if !line.trim().is_empty() {
            pending_slot = None;
        }
        resolved.push_str(line);
        resolved.push('\n');
    }
    resolved
}

fn stack_slot_loaded_into_rax(line: &str) -> Option<&str> {
    let (_, operands) = line.split_once("\tmov\t")?;
    let (destination, source) = operands.split_once(',')?;
    (destination.trim() == "rax" && is_rsp_stack_slot(source.trim())).then_some(source.trim())
}

fn stack_slot_stored_from_rax(line: &str) -> Option<&str> {
    let (_, operands) = line.split_once("\tmov\t")?;
    let (destination, source) = operands.split_once(',')?;
    (source.trim() == "rax" && is_rsp_stack_slot(destination.trim())).then_some(destination.trim())
}

fn is_rsp_stack_slot(operand: &str) -> bool {
    operand.ends_with(" ptr [rsp]") || operand.contains(" ptr [rsp + ")
}

fn preserves_rax_slot_through_argument_setup(line: &str) -> bool {
    let operands = ["\tlea\t", "\tmov\t", "\tmovabs\t", "\txor\t"]
        .into_iter()
        .find_map(|mnemonic| line.split_once(mnemonic).map(|(_, operands)| operands));
    let Some(destination) = operands.and_then(|operands| operands.split_once(',').map(|v| v.0))
    else {
        return false;
    };
    let destination = destination.trim();
    matches!(
        destination,
        "rdi"
            | "edi"
            | "di"
            | "dil"
            | "rsi"
            | "esi"
            | "si"
            | "sil"
            | "rdx"
            | "edx"
            | "dx"
            | "dl"
            | "rcx"
            | "ecx"
            | "cx"
            | "cl"
            | "r8"
            | "r8d"
            | "r8w"
            | "r8b"
            | "r9"
            | "r9d"
            | "r9w"
            | "r9b"
    ) || destination.ends_with(" ptr [rsp]")
        || destination.contains(" ptr [rsp + ")
}

fn named_symbol_addresses(symbols: &str) -> BTreeMap<u64, String> {
    symbols
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(3, char::is_whitespace);
            let address = u64::from_str_radix(fields.next()?, 16).ok()?;
            let _kind = fields.next()?;
            let name = fields.next()?.trim();
            (!name.is_empty()).then(|| (address, name.to_owned()))
        })
        .collect()
}

fn read_nonwritable_elf_pointer(bytes: &[u8], address: u64) -> Option<u64> {
    assert_eq!(&bytes[..4], b"\x7fELF", "target artifact is not ELF");
    assert_eq!(bytes[4], 2, "target artifact is not ELF64");
    assert_eq!(bytes[5], 1, "target artifact is not little-endian ELF");
    let program_offset = elf_u64(bytes, 32) as usize;
    let entry_size = elf_u16(bytes, 54) as usize;
    let entry_count = elf_u16(bytes, 56) as usize;
    assert!(entry_size >= 56, "ELF64 program header is truncated");
    for index in 0..entry_count {
        let header = program_offset + index * entry_size;
        assert!(
            header + entry_size <= bytes.len(),
            "ELF program header is out of range"
        );
        if elf_u32(bytes, header) != 1 {
            continue;
        }
        let flags = elf_u32(bytes, header + 4);
        let file_offset = elf_u64(bytes, header + 8);
        let virtual_address = elf_u64(bytes, header + 16);
        let file_size = elf_u64(bytes, header + 32);
        if flags & 2 != 0
            || address < virtual_address
            || address.checked_add(8)? > virtual_address.checked_add(file_size)?
        {
            continue;
        }
        let offset = file_offset.checked_add(address - virtual_address)? as usize;
        return Some(elf_u64(bytes, offset));
    }
    None
}

fn elf_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("ELF u16 field"))
}

fn elf_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("ELF u32 field"))
}

fn elf_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("ELF u64 field"))
}

#[test]
fn immutable_elf_pointer_resolution_rejects_writable_segments() {
    let mut elf = vec![0_u8; 512];
    elf[..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[32..40].copy_from_slice(&64_u64.to_le_bytes());
    elf[54..56].copy_from_slice(&56_u16.to_le_bytes());
    elf[56..58].copy_from_slice(&1_u16.to_le_bytes());
    elf[64..68].copy_from_slice(&1_u32.to_le_bytes());
    elf[68..72].copy_from_slice(&4_u32.to_le_bytes());
    elf[72..80].copy_from_slice(&256_u64.to_le_bytes());
    elf[80..88].copy_from_slice(&0x1000_u64.to_le_bytes());
    elf[96..104].copy_from_slice(&64_u64.to_le_bytes());
    elf[264..272].copy_from_slice(&0x1234_5678_9abc_def0_u64.to_le_bytes());
    assert_eq!(
        read_nonwritable_elf_pointer(&elf, 0x1008),
        Some(0x1234_5678_9abc_def0)
    );
    elf[68..72].copy_from_slice(&6_u32.to_le_bytes());
    assert_eq!(read_nonwritable_elf_pointer(&elf, 0x1008), None);
}

#[test]
fn immutable_indirect_resolution_rejects_an_intervening_rax_overwrite() {
    let disassembly = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tmov\trax, qword ptr [rip + 0x10] # 0x1000\n  7:\tmov\trax, rdi\n  a:\tcall\trax\n";
    let resolved = resolve_read_only_indirect_disassembly(disassembly, |slot| {
        assert_eq!(slot, 0x1000);
        (0x2000, "typed_target".to_owned())
    });
    assert!(resolved.contains("\tcall\trax"));
    assert!(!resolved.contains("<typed_target>"));
}

#[test]
fn immutable_indirect_resolution_allows_only_rax_preserving_argument_setup() {
    let accepted = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tmov\trax, qword ptr [rip + 0x10] # 0x1000\n  7:\tlea\trdi, [rsp + 0x20]\n  c:\tmov\tqword ptr [rsp + 0x8], rdi\n 11:\tmov\tesi, 0x51\n 16:\tmovabs\trdx, 0x800000000000\n 20:\txor\tedx, edx\n 22:\tcall\trax\n";
    let resolved = resolve_read_only_indirect_disassembly(accepted, |slot| {
        assert_eq!(slot, 0x1000);
        (0x2000, "typed_target".to_owned())
    });
    assert!(resolved.contains("\tcall\t0x2000 <typed_target>"));

    let rejected = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tmov\trax, qword ptr [rip + 0x10] # 0x1000\n  7:\tcmp\trdi, 0x1\n  b:\tcall\trax\n";
    let unresolved = resolve_read_only_indirect_disassembly(rejected, |_| {
        panic!("unknown intervening instruction must clear the slot")
    });
    assert!(unresolved.contains("\tcall\trax"));
}

#[test]
fn immutable_indirect_resolution_tracks_exact_caller_local_spills() {
    let accepted = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tmov\trax, qword ptr [rip + 0x10] # 0x1000\n  7:\tmov\tqword ptr [rsp + 0x28], rax\n  c:\tcall\trax\n  e:\tmov\trdi, qword ptr [rsp + 0x40]\n 13:\tmov\trax, qword ptr [rsp + 0x28]\n 18:\tmov\tcl, byte ptr [rsp + 0x48]\n 1c:\tmov\tbyte ptr [rsp + 0x49], cl\n 20:\tcall\trax\n";
    let resolved = resolve_read_only_indirect_disassembly(accepted, |slot| {
        assert_eq!(slot, 0x1000);
        (0x2000, "memcpy".to_owned())
    });
    assert_eq!(resolved.matches("\tcall\t0x2000 <memcpy>").count(), 2);

    let overwritten = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tmov\trax, qword ptr [rip + 0x10] # 0x1000\n  7:\tmov\tqword ptr [rsp + 0x28], rax\n  c:\tcall\trax\n  e:\tmov\tqword ptr [rsp + 0x28], rdi\n 13:\tmov\trax, qword ptr [rsp + 0x28]\n 18:\tcall\trax\n";
    let unresolved = resolve_read_only_indirect_disassembly(overwritten, |slot| {
        assert_eq!(slot, 0x1000);
        (0x2000, "memcpy".to_owned())
    });
    assert_eq!(unresolved.matches("\tcall\t0x2000 <memcpy>").count(), 1);
    assert!(unresolved.contains("\tcall\trax"));
}

#[test]
fn fixed_x86_64_stack_frame_counts_flags_and_gpr_pushes() {
    let disassembly = "Disassembly of section .text:\n\n0000 <switch>:\n  0:\tpushfq\n  1:\tpush\trbx\n  2:\tpush\trbp\n  3:\tpush\tr12\n  5:\tpush\tr13\n  7:\tpush\tr14\n  9:\tpush\tr15\n";
    assert_eq!(fixed_x86_64_stack_frame(disassembly, "switch"), 56);
}

pub(super) fn text_disassembly(disassembly: &str) -> &str {
    disassembly
        .split_once("Disassembly of section .text:")
        .map(|(_, text)| text)
        .unwrap_or_else(|| panic!("target artifact omitted .text disassembly"))
}

pub(super) fn validate_static_kernel_elf(
    llvm_readelf: &VerifiedExecutable,
    artifact: &Path,
    label: &str,
) {
    let mut readelf = verified_helper_command_as(llvm_readelf, "llvm-readelf");
    let headers = run_output(
        readelf.args(["-h", "-l", "-S", "-d"]).arg(artifact),
        &format!("{label} ELF headers"),
    );
    let headers = String::from_utf8(headers.stdout).expect("llvm-readelf output is UTF-8");
    for forbidden in ["INTERP", "DYNAMIC", "NEEDED"] {
        assert!(
            !headers.contains(forbidden),
            "{label} kernel gained dynamic runtime evidence {forbidden}"
        );
    }
    assert!(
        !headers.contains(".eh_frame_hdr"),
        "{label} kernel gained a synthetic unwind header outside the canonical segment bounds"
    );
}

pub(super) fn validate_static_native_user_elf(
    llvm_nm: &VerifiedExecutable,
    llvm_objdump: &VerifiedExecutable,
    llvm_readelf: &VerifiedExecutable,
    user: &Path,
    label: &str,
) {
    let user_symbols = symbols(llvm_nm, user);
    for required in ["_start", "dw_syscall6"] {
        assert!(
            user_symbols.contains(required),
            "{label} userspace ELF omitted {required}"
        );
    }

    let mut readelf = verified_helper_command_as(llvm_readelf, "llvm-readelf");
    let headers = run_output(
        readelf.args(["-h", "-l", "-d"]).arg(user),
        &format!("{label} userspace ELF headers"),
    );
    let headers = String::from_utf8(headers.stdout).expect("llvm-readelf output is UTF-8");
    assert!(
        headers.contains("Type:                              EXEC"),
        "{label} userspace ELF is not executable"
    );
    for forbidden in ["INTERP", "DYNAMIC", "NEEDED"] {
        assert!(
            !headers.contains(forbidden),
            "{label} userspace ELF gained dynamic runtime evidence {forbidden}"
        );
    }
    let loads: Vec<_> = headers
        .lines()
        .filter(|line| line.trim_start().starts_with("LOAD"))
        .collect();
    assert_eq!(
        loads.len(),
        1,
        "{label} userspace ELF must have one PT_LOAD: {loads:?}"
    );
    assert!(
        loads[0].contains(" R E "),
        "{label} PT_LOAD is not RX: {}",
        loads[0]
    );
    assert!(!loads[0].contains(" RWE "), "{label} PT_LOAD became W+X");
    let bytes = fs::read(user).expect("read userspace ELF");
    for forbidden in [b"libc.so".as_slice(), b"GLIBC_", b"musl", b"newlib"] {
        assert!(
            !contains_bytes(&bytes, forbidden),
            "{label} userspace ELF retained libc marker {}",
            String::from_utf8_lossy(forbidden)
        );
    }

    let user_disassembly = disassembly(llvm_objdump, user);
    let syscall_count = user_disassembly
        .lines()
        .filter(|line| line.split_whitespace().last() == Some("syscall"))
        .count();
    assert_eq!(
        syscall_count, 1,
        "generated {label} veneer must own the sole SYSCALL"
    );
    let start_syscalls = function_body(&user_disassembly, "_start")
        .lines()
        .filter(|line| line.split_whitespace().last() == Some("syscall"))
        .count();
    let veneer_syscalls = function_body(&user_disassembly, "dw_syscall6")
        .lines()
        .filter(|line| line.split_whitespace().last() == Some("syscall"))
        .count();
    assert_eq!(
        start_syscalls, 0,
        "{label} _start must call the generated veneer"
    );
    assert_eq!(
        veneer_syscalls, 1,
        "generated {label} dw_syscall6 must own SYSCALL"
    );
}

pub(super) fn validate_user_stack_consumption(
    llvm_objdump: &VerifiedExecutable,
    user: &Path,
    label: &str,
    user_stack_slice_bytes: usize,
) {
    let disassembly = disassembly(llvm_objdump, user);
    let entry = function_body(&disassembly, "_start");
    let mut maximum_outgoing_bytes = 0_usize;
    for line in entry.lines() {
        let Some(immediate) = line.split_once("\tsub\trsp, 0x").map(|(_, value)| value) else {
            continue;
        };
        let digits = immediate.bytes().take_while(u8::is_ascii_hexdigit).count();
        let bytes = usize::from_str_radix(&immediate[..digits], 16)
            .unwrap_or_else(|error| panic!("parse {label} user stack adjustment: {error}"));
        maximum_outgoing_bytes = maximum_outgoing_bytes.max(bytes);
    }
    assert!(
        !entry.contains("\tpush\t"),
        "{label} user entry added an unbudgeted push frame"
    );
    assert!(
        maximum_outgoing_bytes > 0,
        "{label} user entry omitted the generated-veneer outgoing-call frame"
    );
    let maximum_consumption = maximum_outgoing_bytes
        .checked_add(size_of::<u64>())
        .expect("user stack consumption fits usize");
    assert!(
        maximum_consumption <= user_stack_slice_bytes,
        "{label} user entry outgoing frame plus call return {maximum_consumption} exceeds its {user_stack_slice_bytes}-byte slice"
    );
    let veneer = function_body(&disassembly, "dw_syscall6");
    assert!(
        !veneer.contains("\tpush\t") && !veneer.contains("\tsub\trsp"),
        "generated {label} veneer consumes unbudgeted user stack"
    );
    eprintln!(
        "{label} user-stack outgoing-frame={maximum_outgoing_bytes} call-return={} total={maximum_consumption} slice={user_stack_slice_bytes}",
        size_of::<u64>(),
    );
}

pub(super) fn validate_entry_normalization(disassembly: &str) {
    let normalizer = function_body(disassembly, "normalize_dw0_c_cpu_state");
    assert_eq!(normalizer.matches("pushfq").count(), 1);
    assert_eq!(normalizer.matches("popfq").count(), 1);
    assert_eq!(normalizer.matches("cr4").count(), 2);
    assert_eq!(normalizer.matches("mov\tcr4,").count(), 1);
    assert_eq!(normalizer.matches("btr\trax, 0x15").count(), 1);
    assert_eq!(normalizer.matches("btr\tqword ptr [rsp], 0x12").count(), 1);

    let e5_fp_policy = function_body(disassembly, "normalize_cr0_for_e5");
    assert_eq!(e5_fp_policy.matches("or\trax, 0x8").count(), 1);
    let e5_fp_live = function_body(disassembly, "enforce_live_fp_simd_unavailable");
    assert_eq!(e5_fp_live.matches(", cr0").count(), 2);
    assert_eq!(e5_fp_live.matches("mov\tcr0,").count(), 1);
    assert_eq!(e5_fp_live.matches("normalize_cr0_for_e5").count(), 1);

    let e4_policy = function_body(disassembly, "normalize_cr4_for_e4");
    assert_eq!(e4_policy.matches("and\trax, -0x10001").count(), 1);
    let e4_live = function_body(disassembly, "normalize_live_cr4");
    assert_eq!(e4_live.matches("mov\trax, cr4").count(), 2);
    assert_eq!(e4_live.matches("mov\tcr4, rax").count(), 1);
    assert_eq!(e4_live.matches("normalize_cr4_for_e4").count(), 1);
    assert_eq!(e4_live.matches("and\trax, 0x10000").count(), 1);
    assert_eq!(disassembly.matches("mov\tcr4,").count(), 2);

    let entry = function_body(disassembly, "dw_kernel_rust_entry");
    let normalize_call = entry
        .find("normalize_dw0_c_cpu_state")
        .expect("target entry calls CPU normalizer");
    let kernel_main_call = entry
        .find("deepwyrm_kernel::kernel_main")
        .expect("target entry calls kernel_main");
    assert!(normalize_call < kernel_main_call);
}

pub(super) fn validate_f2_kernel_context_object(
    clang: &VerifiedExecutable,
    llvm_nm: &VerifiedExecutable,
    llvm_objdump: &VerifiedExecutable,
    workspace: &Path,
    output: &Path,
) {
    let mut command = verified_helper_command(clang);
    run_success(
        command
            .args([
                "--no-default-config",
                "--target=x86_64-unknown-none",
                "-ffreestanding",
                "-fno-pic",
                "-mno-red-zone",
                "-c",
            ])
            .arg(workspace.join("kernel/src/arch/x86_64/kernel_context.S"))
            .arg("-o")
            .arg(output),
        "F2 kernel-context assembly",
    );
    let object_symbols = symbols(llvm_nm, output);
    assert!(object_symbols.contains("dw_x86_64_switch_kernel_context"));
    validate_f2_kernel_context_switch(&disassembly(llvm_objdump, output));
}

pub(super) fn validate_f2_kernel_context_switch(disassembly: &str) {
    let body = function_body(disassembly, "dw_x86_64_switch_kernel_context");
    let required = [
        "pushfq",
        "push\trbx",
        "push\trbp",
        "push\tr12",
        "push\tr13",
        "push\tr14",
        "push\tr15",
        "mov\tqword ptr [rdi], rsp",
        "mov\trsp, rsi",
        "pop\tr15",
        "pop\tr14",
        "pop\tr13",
        "pop\tr12",
        "pop\trbp",
        "pop\trbx",
        "popfq",
        "ret",
    ];
    let mut cursor = 0;
    for marker in required {
        let offset = body[cursor..]
            .find(marker)
            .unwrap_or_else(|| panic!("F2 kernel switch omitted `{marker}`: {body}"));
        cursor += offset + marker.len();
    }
    for forbidden in ["iret", "sysret", "swapgs", "wrmsr", "rdmsr"] {
        assert!(
            !body.contains(forbidden),
            "F2 kernel switch contains user/privilege transition instruction `{forbidden}`"
        );
    }
}

pub(super) fn validate_fp_simd_unavailable(disassembly: &str) {
    const FORBIDDEN_MNEMONICS: &[&str] = &[
        "emms", "f2xm1", "fabs", "fadd", "fbld", "fbstp", "fchs", "fclex", "fcmov", "fcom", "fcos",
        "fdecstp", "fdiv", "ffree", "fiadd", "ficom", "fidiv", "fild", "fimul", "fincstp", "finit",
        "fist", "fisub", "fld", "fmul", "fnclex", "fninit", "fnop", "fnsave", "fnst", "fpatan",
        "fprem", "fptan", "frndint", "frstor", "fsave", "fscale", "fsin", "fsincos", "fsqrt",
        "fst", "fsub", "ftst", "fucom", "fwait", "fxam", "fxch", "fxrstor", "fxsave", "fxtract",
        "fyl2x", "ldmxcsr", "stmxcsr", "xrstor", "xsave",
    ];
    for line in text_disassembly(disassembly).lines() {
        let instruction = line
            .rsplit('\t')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        let mnemonic = instruction.split_whitespace().next().unwrap_or("");
        assert!(
            !["xmm", "ymm", "zmm"]
                .iter()
                .any(|register| instruction.contains(register)),
            "E5 kernel text uses FP/SIMD register state while policy is unavailable: {line}"
        );
        assert!(
            !(0..8).any(|index| instruction.contains(&format!("mm{index}"))),
            "E5 kernel text uses MMX register state while policy is unavailable: {line}"
        );
        assert!(
            !FORBIDDEN_MNEMONICS
                .iter()
                .any(|prefix| mnemonic.starts_with(prefix)),
            "E5 kernel text uses FP/SIMD state while policy is unavailable: {line}"
        );
    }
}

pub(super) fn function_body<'a>(disassembly: &'a str, symbol: &str) -> &'a str {
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

pub(super) fn fixed_x86_64_stack_frame(disassembly: &str, symbol: &str) -> usize {
    let body = function_body(disassembly, symbol);
    assert!(
        !body.contains("\tand\trsp") && !body.contains("\tlea\trsp"),
        "{symbol} uses dynamic stack adjustment"
    );
    let pushes = body
        .lines()
        .filter(|line| line.contains("\tpush\t") || line.contains("\tpushfq"))
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

pub(super) fn sha256(artifact: &Path) -> String {
    let mut command = helper_command("/usr/bin/sha256sum");
    digest_from_output(run_output(command.arg(artifact), "sha256sum"))
}

pub(super) fn verified_helper_command(program: &VerifiedExecutable) -> Command {
    let mut command = program.command();
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("SOURCE_DATE_EPOCH", "0");
    command
}

pub(super) fn verified_helper_command_as(program: &VerifiedExecutable, argv0: &str) -> Command {
    let mut command = program.command_with_argv0(argv0);
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("SOURCE_DATE_EPOCH", "0");
    command
}

pub(super) fn helper_command(program: impl AsRef<OsStr>) -> Command {
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

pub(super) fn digest_from_output(output: Output) -> String {
    String::from_utf8(output.stdout)
        .expect("sha256sum output is UTF-8")
        .split_ascii_whitespace()
        .next()
        .expect("sha256sum emitted a digest")
        .to_owned()
}

pub(super) fn run_success(command: &mut Command, label: &str) {
    let output = run_output(command, label);
    assert!(
        output.status.success(),
        "{label} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

pub(super) fn run_output(command: &mut Command, label: &str) -> Output {
    command
        .output()
        .unwrap_or_else(|error| panic!("failed to run {label}: {error}"))
}
