use super::elf::{
    BoundError, Branch, BranchKind, CallGraph, Elf, Function, classify, deepest_path, display_name,
    parse_stack_sizes, prologue_frame,
};
use std::collections::BTreeMap;

fn function(name: &str, addr: u64, size: u64) -> Function {
    Function {
        name: name.into(),
        addr,
        size,
    }
}

fn call(site: u64, target: u64) -> Branch {
    Branch {
        site,
        kind: BranchKind::Call,
        target,
    }
}

fn jump(site: u64, target: u64) -> Branch {
    Branch {
        site,
        kind: BranchKind::Jump,
        target,
    }
}

fn no_cut(_: &str) -> bool {
    false
}

/// `a` (0x100) calls `b` and tail-jumps to `c`; `b` calls `d`; `c` calls
/// `panic`; `d` is a leaf.
fn graph() -> CallGraph {
    let functions = vec![
        function("a", 0x100, 0x40),
        function("b", 0x200, 0x40),
        function("c", 0x300, 0x40),
        function("d", 0x400, 0x40),
        function("panic", 0x500, 0x40),
    ];
    let sizes = BTreeMap::from([
        (0x100, 100),
        (0x200, 200),
        (0x300, 1000),
        (0x400, 50),
        (0x500, 5000),
    ]);
    let branches = [
        call(0x110, 0x200),
        jump(0x120, 0x300),
        call(0x210, 0x400),
        call(0x310, 0x500),
    ];
    CallGraph::build(functions, &sizes, &branches).unwrap()
}

#[test]
fn deepest_path_charges_frames_and_return_addresses_along_the_deepest_branch() {
    let graph = graph();
    // a's call chain: 100 + 8 + 200 + 8 + 50 = 366; its tail jump: 100 + 1000
    // + 8 + 5000. The jump is charged without a return address, and on top of
    // a's frame.
    assert_eq!(
        deepest_path(&graph, 0, &no_cut).unwrap(),
        (6108, vec![0, 2, 4])
    );
}

#[test]
fn deepest_path_does_not_follow_cut_callees() {
    let graph = graph();
    let cut = |name: &str| name == "panic";
    assert_eq!(deepest_path(&graph, 0, &cut).unwrap(), (1100, vec![0, 2]));
}

#[test]
fn deepest_path_rejects_recursion_through_any_cycle() {
    let functions = vec![function("a", 0x100, 0x40), function("b", 0x200, 0x40)];
    let sizes = BTreeMap::from([(0x100, 8), (0x200, 8)]);
    let graph =
        CallGraph::build(functions, &sizes, &[call(0x110, 0x200), call(0x210, 0x100)]).unwrap();
    assert_eq!(
        deepest_path(&graph, 0, &no_cut),
        Err(BoundError::Recursion(vec![0, 1, 0]))
    );
}

#[test]
fn self_recursion_fails_until_unrolled_to_its_bounded_depth() {
    let functions = vec![function("walk", 0x100, 0x40), function("leaf", 0x200, 0x40)];
    let sizes = BTreeMap::from([(0x100, 100), (0x200, 10)]);
    let mut graph =
        CallGraph::build(functions, &sizes, &[call(0x110, 0x100), call(0x120, 0x200)]).unwrap();
    assert_eq!(
        deepest_path(&graph, 0, &no_cut),
        Err(BoundError::Recursion(vec![0, 0]))
    );
    graph.unroll_self_recursion(0, 4);
    // Four nested frames with three return addresses between them, then the
    // leaf's call from the innermost.
    assert_eq!(
        deepest_path(&graph, 0, &no_cut).unwrap(),
        (424 + 18, vec![0, 1])
    );
}

#[test]
fn deepest_path_rejects_a_function_without_a_frame() {
    let functions = vec![function("a", 0x100, 0x40), function("b", 0x200, 0x40)];
    let sizes = BTreeMap::from([(0x100, 8)]);
    let graph = CallGraph::build(functions, &sizes, &[call(0x110, 0x200)]).unwrap();
    assert_eq!(
        deepest_path(&graph, 0, &no_cut),
        Err(BoundError::NoFrame(vec![0, 1]))
    );
}

#[test]
fn the_graph_rejects_a_branch_into_the_middle_of_another_function() {
    let functions = vec![function("a", 0x100, 0x40), function("b", 0x200, 0x40)];
    let sizes = BTreeMap::new();
    let error = CallGraph::build(functions, &sizes, &[call(0x110, 0x210)])
        .err()
        .unwrap();
    assert_eq!(error, "a branches into the middle of b");
}

#[test]
fn the_graph_rejects_a_branch_to_no_function_and_ignores_local_jumps() {
    let functions = vec![function("a", 0x100, 0x40)];
    let sizes = BTreeMap::new();
    assert!(CallGraph::build(functions.clone(), &sizes, &[call(0x110, 0x900)]).is_err());
    let graph = CallGraph::build(functions, &sizes, &[jump(0x110, 0x120)]).unwrap();
    assert!(graph.edges[0].is_empty());
}

fn code_with(prefix: &[u8], field: i32) -> Vec<u8> {
    let mut code = vec![0x90; 8];
    code.extend_from_slice(prefix);
    code.extend_from_slice(&field.to_le_bytes());
    code.extend_from_slice(&[0x90; 4]);
    code
}

fn classify_at(prefix: &[u8], field: i32, slot: Option<u64>) -> Option<Branch> {
    let code = code_with(prefix, field);
    let at = 8 + prefix.len();
    let place = 0x1000 + at as u64;
    classify(&code, at, place, |_| Ok(slot)).unwrap()
}

#[test]
fn classify_reads_direct_calls_and_jumps_from_their_opcodes() {
    // place = 0x1009; destination = place + 4 + 0x100.
    assert_eq!(
        classify_at(&[0xe8], 0x100, None),
        Some(call(0x1009, 0x110d))
    );
    assert_eq!(
        classify_at(&[0xe9], -0x10, None),
        Some(jump(0x1009, 0x0ffd))
    );
    assert_eq!(
        classify_at(&[0x0f, 0x85], 0x20, None),
        Some(jump(0x100a, 0x102e))
    );
}

#[test]
fn classify_resolves_a_constant_slot_and_leaves_a_writable_one_out() {
    assert_eq!(
        classify_at(&[0xff, 0x15], 0x40, Some(0x7000)),
        Some(call(0x100a, 0x7000))
    );
    assert_eq!(
        classify_at(&[0xff, 0x25], 0x40, Some(0x7000)),
        Some(jump(0x100a, 0x7000))
    );
    assert_eq!(classify_at(&[0xff, 0x15], 0x40, None), None);
}

#[test]
fn classify_ignores_memory_operands_that_are_not_branches() {
    // lea rax, [rip+disp32] and mov rax, [rip+disp32].
    assert_eq!(classify_at(&[0x48, 0x8d, 0x05], 0x40, Some(1)), None);
    assert_eq!(classify_at(&[0x48, 0x8b, 0x05], 0x40, Some(1)), None);
    // adc edx, [rip+disp32] has the ModRM byte 0x15 without FF before it.
    assert_eq!(classify_at(&[0x13, 0x15], 0x40, Some(1)), None);
}

#[test]
fn stack_sizes_decode_uleb_frames_and_keep_the_larger_duplicate() {
    let mut section = Vec::new();
    section.extend_from_slice(&0x100u64.to_le_bytes());
    section.push(0x10);
    section.extend_from_slice(&0x200u64.to_le_bytes());
    section.extend_from_slice(&[0xe5, 0x8e, 0x26]); // 624485
    section.extend_from_slice(&0x100u64.to_le_bytes());
    section.push(0x20);
    assert_eq!(
        parse_stack_sizes(&section).unwrap(),
        BTreeMap::from([(0x100, 0x20), (0x200, 624_485)])
    );
    assert!(parse_stack_sizes(&section[..10]).is_err());
}

#[test]
fn prologue_frame_counts_pushes_and_the_stack_adjustment() {
    // endbr64; push rbp; mov rbp, rsp; push r15; push rbx; sub rsp, 0x28; ret
    let code = [
        0xf3, 0x0f, 0x1e, 0xfa, 0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x53, 0x48, 0x83, 0xec, 0x28,
        0xc3,
    ];
    assert_eq!(prologue_frame(&code), 24 + 0x28);
    // sub rsp, 0x1234 with a 32-bit immediate, then code.
    assert_eq!(
        prologue_frame(&[0x48, 0x81, 0xec, 0x34, 0x12, 0, 0, 0x31, 0xc0]),
        0x1234
    );
    assert_eq!(prologue_frame(&[0xc3]), 0);
}

#[test]
fn display_name_joins_a_v0_path_and_keeps_other_names() {
    assert_eq!(
        display_name(
            "_RNvNtNtNtCs7JyPvz0AJPX_15deepwyrm_kernel4arch6x86_643ipi9TRANSPORT.llvm.146758"
        ),
        "deepwyrm_kernel::arch::x86_64::ipi::TRANSPORT"
    );
    assert_eq!(
        display_name(
            "_RINvNtNtNtNtNtNtCs7JyPvz0AJPX_15deepwyrm_kernel4arch6x86_642mm10transition10activation5build14map_owned_leafKj1197_Kj1000_EBe_"
        ),
        "deepwyrm_kernel::arch::x86_64::mm::transition::activation::build::map_owned_leaf"
    );
    assert_eq!(
        display_name("dw_x86_64_syscall_dispatch"),
        "dw_x86_64_syscall_dispatch"
    );
}

#[test]
fn the_reader_refuses_files_that_are_not_little_endian_elf64() {
    assert!(Elf::parse(b"not an elf file at all, but long enough").is_err());
    let mut header = vec![0u8; 64];
    header[..4].copy_from_slice(b"\x7fELF");
    header[4] = 1; // ELFCLASS32
    header[5] = 1;
    assert!(Elf::parse(&header).is_err());
}
