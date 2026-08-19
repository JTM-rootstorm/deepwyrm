use super::*;

pub(super) fn symbols(llvm_nm: &Path, artifact: &Path) -> String {
    let mut command = helper_command(llvm_nm);
    let output = run_output(
        command.args(["--defined-only", "--demangle"]).arg(artifact),
        "llvm-nm",
    );
    String::from_utf8(output.stdout).expect("llvm-nm output is UTF-8")
}

pub(super) fn disassembly(llvm_objdump: &Path, artifact: &Path) -> String {
    let mut command = helper_command(llvm_objdump);
    let output = run_output(
        command
            .args(["--disassemble", "--demangle", "--x86-asm-syntax=intel"])
            .arg(artifact),
        "llvm-objdump",
    );
    String::from_utf8(output.stdout).expect("llvm-objdump output is UTF-8")
}

pub(super) fn text_disassembly(disassembly: &str) -> &str {
    disassembly
        .split_once("Disassembly of section .text:")
        .map(|(_, text)| text)
        .unwrap_or_else(|| panic!("target artifact omitted .text disassembly"))
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
    clang: &Path,
    llvm_nm: &Path,
    llvm_objdump: &Path,
    workspace: &Path,
    output: &Path,
) {
    let mut command = helper_command(clang);
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

pub(super) fn sha256(artifact: &Path) -> String {
    let mut command = helper_command("/usr/bin/sha256sum");
    digest_from_output(run_output(command.arg(artifact), "sha256sum"))
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
