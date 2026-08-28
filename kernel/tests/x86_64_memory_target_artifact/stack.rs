use super::*;

#[derive(Clone, Debug)]
pub(super) struct StackSize {
    bytes: usize,
    symbol: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct DirectCallStackBound {
    pub(super) bytes: usize,
    pub(super) call_count: usize,
    pub(super) terminal: String,
}

pub(super) struct DirectCallGraph<'a> {
    frames: BTreeMap<String, usize>,
    calls: BTreeMap<String, Vec<String>>,
    indirect_calls: BTreeMap<String, Vec<String>>,
    known_symbols: BTreeSet<String>,
    disassembly: &'a str,
}

pub(super) struct ResolvedDirectCallGraph<'graph, 'artifact, 'resolutions> {
    graph: &'graph DirectCallGraph<'artifact>,
    indirect_resolutions: &'resolutions BTreeMap<String, Vec<String>>,
    memo: BTreeMap<String, DirectCallStackBound>,
    validated_edges: usize,
}

const MAX_DIRECT_CALL_GRAPH_STATES: usize = 65_536;
const MAX_DIRECT_CALL_GRAPH_EDGES: usize = 524_288;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AuditedStackFrame {
    name: &'static str,
    bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuditedStackPathError {
    DuplicateEntry(&'static str),
    Overflow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AuditedStackPath {
    bytes: usize,
    frame_count: usize,
}

pub(super) fn audited_stack_path(
    segments: &[&[AuditedStackFrame]],
) -> Result<AuditedStackPath, AuditedStackPathError> {
    let mut seen = BTreeSet::new();
    let mut total = 0_usize;
    for segment in segments {
        for frame in *segment {
            if !seen.insert(frame.name) {
                return Err(AuditedStackPathError::DuplicateEntry(frame.name));
            }
            total = total
                .checked_add(frame.bytes)
                .ok_or(AuditedStackPathError::Overflow)?;
        }
    }
    Ok(AuditedStackPath {
        bytes: total,
        frame_count: seen.len(),
    })
}

pub(super) fn audited_stack_path_bytes(
    segments: &[&[AuditedStackFrame]],
) -> Result<usize, AuditedStackPathError> {
    audited_stack_path(segments).map(|path| path.bytes)
}

pub(super) fn audited_stack_upper_bound(paths: &[AuditedStackPath]) -> AuditedStackPath {
    paths.iter().copied().fold(
        AuditedStackPath {
            bytes: 0,
            frame_count: 0,
        },
        |bound, path| AuditedStackPath {
            bytes: bound.bytes.max(path.bytes),
            frame_count: bound.frame_count.max(path.frame_count),
        },
    )
}

pub(super) fn ist_padding_branch(
    write_char: usize,
    encode_utf8_raw: usize,
    precondition_check: usize,
    is_aligned_to: usize,
) -> [AuditedStackFrame; 4] {
    [
        AuditedStackFrame {
            name: "ist-padding-write-char",
            bytes: write_char,
        },
        AuditedStackFrame {
            name: "ist-padding-encode-utf8-raw",
            bytes: encode_utf8_raw,
        },
        AuditedStackFrame {
            name: "ist-padding-precondition-check",
            bytes: precondition_check,
        },
        AuditedStackFrame {
            name: "ist-padding-is-aligned-to",
            bytes: is_aligned_to,
        },
    ]
}

#[test]
pub(super) fn audited_stack_manifest_rejects_duplicate_entries_and_overflow() {
    assert_eq!(
        audited_stack_path_bytes(&[&[
            AuditedStackFrame {
                name: "caller",
                bytes: 16,
            },
            AuditedStackFrame {
                name: "callee",
                bytes: 32,
            },
            AuditedStackFrame {
                name: "caller",
                bytes: 16,
            },
        ]]),
        Err(AuditedStackPathError::DuplicateEntry("caller"))
    );
    assert_eq!(
        audited_stack_path_bytes(&[&[
            AuditedStackFrame {
                name: "caller",
                bytes: usize::MAX,
            },
            AuditedStackFrame {
                name: "callee",
                bytes: 1,
            },
        ]]),
        Err(AuditedStackPathError::Overflow)
    );
}

#[test]
pub(super) fn ist_padding_branch_participates_in_the_maximum_stack_bound() {
    let ordinary = audited_stack_path(&[&[
        AuditedStackFrame {
            name: "pad-integral",
            bytes: 64,
        },
        AuditedStackFrame {
            name: "write-prefix",
            bytes: 32,
        },
    ]])
    .unwrap();
    let padding_branch = ist_padding_branch(72, 72, 120, 56);
    assert_eq!(
        padding_branch.map(|frame| frame.name),
        [
            "ist-padding-write-char",
            "ist-padding-encode-utf8-raw",
            "ist-padding-precondition-check",
            "ist-padding-is-aligned-to",
        ]
    );
    let padding_prefix = [AuditedStackFrame {
        name: "pad-integral",
        bytes: 64,
    }];
    let padding = audited_stack_path(&[&padding_prefix, &padding_branch]).unwrap();

    assert_eq!(audited_stack_upper_bound(&[ordinary, padding]), padding);
}

pub(super) fn stack_sizes(llvm_readelf: &VerifiedExecutable, artifact: &Path) -> Vec<StackSize> {
    let mut command = verified_helper_command_as(llvm_readelf, "llvm-readelf");
    let output = run_output(
        command.args(["--demangle", "--stack-sizes"]).arg(artifact),
        "llvm-readelf stack sizes",
    );
    let stdout = String::from_utf8(output.stdout).expect("llvm-readelf output is UTF-8");
    let mut sizes = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        let Some(separator) = trimmed.find(char::is_whitespace) else {
            continue;
        };
        let Ok(bytes) = trimmed[..separator].parse::<usize>() else {
            continue;
        };
        let symbol = trimmed[separator..].trim();
        if !symbol.is_empty() {
            sizes.push(StackSize {
                bytes,
                symbol: symbol.to_owned(),
            });
        }
    }
    assert!(
        !sizes.is_empty(),
        "target artifact omitted .stack_sizes data"
    );
    sizes
}

pub(super) fn one_stack_size(
    sizes: &[StackSize],
    description: &str,
    predicate: impl Fn(&str) -> bool,
) -> usize {
    let matches: Vec<_> = sizes
        .iter()
        .filter(|entry| predicate(&entry.symbol))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected one {description} stack-size entry, found: {matches:?}"
    );
    matches[0].bytes
}

pub(super) fn one_stack_symbol(
    sizes: &[StackSize],
    description: &str,
    predicate: impl Fn(&str) -> bool,
) -> String {
    let matches: Vec<_> = sizes
        .iter()
        .filter(|entry| predicate(&entry.symbol))
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected one {description} stack symbol, found: {matches:?}"
    );
    matches[0].symbol.clone()
}

/// Bounds a concrete direct-call tree from accepted objdump and accepted
/// `.stack_sizes` metadata.  Indirect control transfers are intentionally not
/// guessed here; the selector oracles add their architectural trampoline and
/// saved-context words explicitly.
pub(super) fn direct_call_stack_bound(
    sizes: &[StackSize],
    disassembly: &str,
    description: &str,
    root_predicate: impl Fn(&str) -> bool,
) -> DirectCallStackBound {
    let graph = DirectCallGraph::new(sizes, disassembly);
    graph.stack_bound(description, root_predicate)
}

pub(super) fn direct_call_stack_bound_with_resolutions(
    sizes: &[StackSize],
    disassembly: &str,
    description: &str,
    root_predicate: impl Fn(&str) -> bool,
    indirect_resolutions: &BTreeMap<String, Vec<String>>,
) -> DirectCallStackBound {
    let graph = DirectCallGraph::new(sizes, disassembly);
    graph
        .with_resolutions(indirect_resolutions)
        .stack_bound(description, root_predicate)
}

impl<'artifact> DirectCallGraph<'artifact> {
    pub(super) fn new(sizes: &[StackSize], disassembly: &'artifact str) -> Self {
        let mut frames = BTreeMap::new();
        for entry in sizes {
            assert!(
                frames.insert(entry.symbol.clone(), entry.bytes).is_none(),
                "duplicate .stack_sizes entry for {}",
                entry.symbol
            );
        }
        let (calls, indirect_calls) = parsed_calls(disassembly);
        let known_symbols = text_disassembly(disassembly)
            .lines()
            .filter_map(disassembly_header_symbol)
            .map(str::to_owned)
            .collect();
        Self {
            frames,
            calls,
            indirect_calls,
            known_symbols,
            disassembly,
        }
    }

    pub(super) fn stack_bound(
        &self,
        description: &str,
        root_predicate: impl Fn(&str) -> bool,
    ) -> DirectCallStackBound {
        self.with_resolutions(&BTreeMap::new())
            .stack_bound(description, root_predicate)
    }

    pub(super) fn with_resolutions<'graph, 'resolutions>(
        &'graph self,
        indirect_resolutions: &'resolutions BTreeMap<String, Vec<String>>,
    ) -> ResolvedDirectCallGraph<'graph, 'artifact, 'resolutions> {
        ResolvedDirectCallGraph {
            graph: self,
            indirect_resolutions,
            memo: BTreeMap::new(),
            validated_edges: 0,
        }
    }

    pub(super) fn reaches(
        &self,
        description: &str,
        root_predicate: impl Fn(&str) -> bool,
        target_predicate: impl Fn(&str) -> bool,
    ) -> bool {
        let root = self.one_root(description, "reachability", root_predicate);
        let mut pending = vec![root.as_str()];
        let mut visited = BTreeSet::new();
        while let Some(symbol) = pending.pop() {
            if !visited.insert(symbol) {
                continue;
            }
            assert!(
                visited.len() <= self.known_symbols.len(),
                "direct-call reachability exceeded accepted artifact symbol state"
            );
            if target_predicate(symbol) {
                return true;
            }
            for callee in self.calls.get(symbol).into_iter().flatten() {
                assert!(
                    self.known_symbols.contains(callee),
                    "direct-call graph from {symbol} reaches unresolved callee {callee}"
                );
                pending.push(callee);
            }
        }
        false
    }

    fn one_root(
        &self,
        description: &str,
        graph_kind: &str,
        root_predicate: impl Fn(&str) -> bool,
    ) -> String {
        let roots: Vec<_> = self
            .frames
            .keys()
            .filter(|symbol| root_predicate(symbol))
            .cloned()
            .collect();
        assert_eq!(
            roots.len(),
            1,
            "expected one {description} {graph_kind} root, found: {roots:?}"
        );
        roots[0].clone()
    }
}

impl ResolvedDirectCallGraph<'_, '_, '_> {
    pub(super) fn stack_bound(
        &mut self,
        description: &str,
        root_predicate: impl Fn(&str) -> bool,
    ) -> DirectCallStackBound {
        let root = self
            .graph
            .one_root(description, "direct-call", root_predicate);
        longest_direct_call_path(
            &root,
            self.graph,
            self.indirect_resolutions,
            &mut self.memo,
            &mut self.validated_edges,
        )
    }

    #[cfg(test)]
    fn memoized_symbol_count(&self) -> usize {
        self.memo.len()
    }
}

fn parsed_calls(
    disassembly: &str,
) -> (BTreeMap<String, Vec<String>>, BTreeMap<String, Vec<String>>) {
    let mut calls = BTreeMap::<String, Vec<String>>::new();
    let mut indirect_calls = BTreeMap::<String, Vec<String>>::new();
    let mut current = None::<String>;
    let mut recent_instructions = Vec::<String>::new();
    for line in text_disassembly(disassembly).lines() {
        if let Some(symbol) = disassembly_header_symbol(line) {
            current = Some(symbol.to_owned());
            calls.entry(symbol.to_owned()).or_default();
            recent_instructions.clear();
            continue;
        }
        let Some(caller) = current.as_ref() else {
            continue;
        };
        let (kind, target) = if let Some((_, target)) = line.split_once("\tcall\t") {
            ("call", target)
        } else if let Some((_, target)) = line.split_once("\tjmp\t") {
            if target.trim() == "rax"
                && recent_instructions.ends_with(&[
                    "lea-rax-relative-table".to_owned(),
                    "load-signed-relative-offset".to_owned(),
                    "add-relative-offset".to_owned(),
                ])
            {
                recent_instructions.clear();
                continue;
            }
            ("tail jump", target)
        } else {
            let instruction = if line.contains("\tlea\trax, [rip + ") {
                Some("lea-rax-relative-table")
            } else if line.contains("\tmovsxd\trcx, dword ptr [rax + 4*rcx]") {
                Some("load-signed-relative-offset")
            } else if line.contains("\tadd\trax, rcx") {
                Some("add-relative-offset")
            } else {
                None
            };
            if let Some(instruction) = instruction {
                recent_instructions.push(instruction.to_owned());
                if recent_instructions.len() > 3 {
                    recent_instructions.remove(0);
                }
            } else if !line.trim().is_empty() {
                recent_instructions.clear();
            }
            continue;
        };
        recent_instructions.clear();
        let Some((_, target)) = target.split_once(" <") else {
            indirect_calls
                .entry(caller.clone())
                .or_default()
                .push(format!("{kind} {target} at {}", line.trim()));
            continue;
        };
        let Some(target) = target.strip_suffix('>') else {
            continue;
        };
        // Jumps within the current function are control flow, not tail calls.
        if target.rsplit_once("+0x").is_some() {
            continue;
        }
        let target = target.to_owned();
        calls.entry(caller.clone()).or_default().push(target);
    }
    (calls, indirect_calls)
}

fn disassembly_header_symbol(line: &str) -> Option<&str> {
    let (_, symbol) = line.split_once('<')?;
    symbol.strip_suffix(">:")
}

fn longest_direct_call_path(
    symbol: &str,
    graph: &DirectCallGraph<'_>,
    indirect_resolutions: &BTreeMap<String, Vec<String>>,
    memo: &mut BTreeMap<String, DirectCallStackBound>,
    validated_edges: &mut usize,
) -> DirectCallStackBound {
    if let Some(bound) = memo.get(symbol) {
        return bound.clone();
    }
    assert!(
        graph.known_symbols.contains(symbol),
        "direct-call stack graph reaches unknown accepted-artifact symbol {symbol}"
    );
    let mut adjacency = BTreeMap::<String, Vec<String>>::new();
    let mut pending = vec![symbol.to_owned()];
    while let Some(current) = pending.pop() {
        if memo.contains_key(&current) || adjacency.contains_key(&current) {
            continue;
        }
        let total_states = memo
            .len()
            .checked_add(adjacency.len())
            .expect("direct-call state count fits usize");
        assert!(
            total_states < MAX_DIRECT_CALL_GRAPH_STATES,
            "direct-call stack graph exceeded {MAX_DIRECT_CALL_GRAPH_STATES} accepted-artifact states"
        );
        let callees = normalized_callees(&current, graph, indirect_resolutions);
        *validated_edges = validated_edges
            .checked_add(callees.len())
            .expect("direct-call edge count fits usize");
        assert!(
            *validated_edges <= MAX_DIRECT_CALL_GRAPH_EDGES,
            "direct-call stack graph exceeded {MAX_DIRECT_CALL_GRAPH_EDGES} accepted-artifact edges"
        );
        for callee in &callees {
            if !memo.contains_key(callee) && !adjacency.contains_key(callee) {
                pending.push(callee.clone());
            }
        }
        adjacency.insert(current, callees);
    }

    let mut indegree = adjacency
        .keys()
        .map(|state| (state.clone(), 0_usize))
        .collect::<BTreeMap<_, _>>();
    for callees in adjacency.values() {
        for callee in callees {
            if let Some(degree) = indegree.get_mut(callee) {
                *degree = degree
                    .checked_add(1)
                    .expect("direct-call indegree fits usize");
            }
        }
    }
    let mut ready = indegree
        .iter()
        .filter_map(|(state, degree)| (*degree == 0).then_some(state.clone()))
        .collect::<Vec<_>>();
    let mut topological = Vec::with_capacity(adjacency.len());
    while let Some(current) = ready.pop() {
        topological.push(current.clone());
        for callee in adjacency.get(&current).into_iter().flatten() {
            let Some(degree) = indegree.get_mut(callee) else {
                continue;
            };
            *degree = degree
                .checked_sub(1)
                .expect("direct-call indegree is nonzero");
            if *degree == 0 {
                ready.push(callee.clone());
            }
        }
    }
    if topological.len() != adjacency.len() {
        panic!("direct-call stack graph contains a cycle through {symbol}");
    }

    for current in topological.into_iter().rev() {
        let bound = if let Some(cut) = terminal_graph_cut(&current, graph.disassembly) {
            cut
        } else {
            let frame = graph
                .frames
                .get(&current)
                .copied()
                .unwrap_or_else(|| fixed_x86_64_stack_frame(graph.disassembly, &current));
            let mut deepest = None::<DirectCallStackBound>;
            for callee in adjacency.get(&current).into_iter().flatten() {
                let candidate = memo
                    .get(callee)
                    .unwrap_or_else(|| panic!("direct-call DP omitted callee {callee}"));
                let candidate_total = candidate
                    .call_count
                    .checked_add(1)
                    .and_then(|count| count.checked_mul(size_of::<u64>()))
                    .and_then(|returns| candidate.bytes.checked_add(returns))
                    .expect("direct-call candidate bound fits usize");
                let deepest_total = deepest.as_ref().map(|bound| {
                    bound
                        .call_count
                        .checked_add(1)
                        .and_then(|count| count.checked_mul(size_of::<u64>()))
                        .and_then(|returns| bound.bytes.checked_add(returns))
                        .expect("direct-call deepest bound fits usize")
                });
                if deepest_total.is_none_or(|total| candidate_total > total) {
                    deepest = Some(candidate.clone());
                }
            }
            let (deepest_bytes, call_count, terminal) = match deepest {
                Some(deepest) => (
                    deepest.bytes,
                    deepest
                        .call_count
                        .checked_add(1)
                        .expect("direct-call count fits usize"),
                    deepest.terminal,
                ),
                None => (0, 0, current.clone()),
            };
            DirectCallStackBound {
                bytes: frame
                    .checked_add(deepest_bytes)
                    .expect("direct-call stack path fits usize"),
                call_count,
                terminal,
            }
        };
        memo.insert(current, bound);
    }
    memo.get(symbol)
        .cloned()
        .expect("direct-call root receives a memoized bound")
}

fn normalized_callees(
    symbol: &str,
    graph: &DirectCallGraph<'_>,
    indirect_resolutions: &BTreeMap<String, Vec<String>>,
) -> Vec<String> {
    if terminal_graph_cut(symbol, graph.disassembly).is_some() {
        return Vec::new();
    }
    let indirect = graph
        .indirect_calls
        .get(symbol)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let resolved = indirect_resolutions
        .get(symbol)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    assert_eq!(
        indirect.len(),
        resolved.len(),
        "direct-call stack graph from {symbol} reaches unbounded indirect control transfer {indirect:?}"
    );
    let callees = graph
        .calls
        .get(symbol)
        .into_iter()
        .flatten()
        .chain(resolved.iter())
        .cloned()
        .collect::<Vec<_>>();
    for callee in &callees {
        assert!(
            graph.known_symbols.contains(callee),
            "direct-call stack graph from {symbol} reaches unresolved callee {callee}"
        );
    }
    callees
}

fn terminal_graph_cut(symbol: &str, disassembly: &str) -> Option<DirectCallStackBound> {
    if symbol == "dw_x86_64_iret_to_user" {
        validate_iret_to_user_handoff(disassembly);
        return Some(DirectCallStackBound {
            bytes: 0,
            call_count: 0,
            terminal: "audited Thread-stack IRET pivot".to_owned(),
        });
    }
    if symbol == "dw_x86_64_terminal_reaper_handoff" {
        validate_terminal_reaper_handoff(disassembly);
        return Some(DirectCallStackBound {
            bytes: 0,
            call_count: 0,
            terminal: "audited terminal-reaper stack pivot".to_owned(),
        });
    }
    if symbol == "dw_x86_64_rendezvous_reaper_handoff" {
        validate_rendezvous_reaper_handoff(disassembly);
        return Some(DirectCallStackBound {
            bytes: 0,
            call_count: 0,
            terminal: "audited rendezvous-reaper stack pivot".to_owned(),
        });
    }
    if matches!(
        symbol,
        "core::panicking::panic_fmt" | "core::panicking::panic_nounwind_fmt"
    ) {
        return Some(DirectCallStackBound {
            bytes: 16 * 1024,
            call_count: 0,
            terminal: "bounded terminal kernel panic path".to_owned(),
        });
    }
    None
}

fn validate_iret_to_user_handoff(disassembly: &str) {
    let body = function_body(disassembly, "dw_x86_64_iret_to_user");
    let required = [
        "\tmov\tr12, rdi",
        "\tmov\trsp, qword ptr gs:[0x8]",
        "\ttest\trsp, rsp",
        "\tpush\t0x2b",
        "\tpush\tqword ptr [r12 + 0x88]",
        "\tpush\tqword ptr [r12 + 0x80]",
        "\tpush\t0x33",
        "\tpush\tqword ptr [r12 + 0x78]",
        "\tswapgs",
        "\tiretq",
    ];
    let mut offset = 0;
    for needle in required {
        let next = body[offset..]
            .find(needle)
            .unwrap_or_else(|| panic!("IRET handoff omitted `{needle}`"));
        offset += next + needle.len();
    }
    let stack_switch = body
        .find("\tmov\trsp, qword ptr gs:[0x8]")
        .expect("IRET handoff installs its Thread stack");
    let first_push = body
        .find("\tpush\t")
        .expect("IRET handoff constructs its return frame");
    assert!(
        stack_switch < first_push,
        "IRET handoff wrote a return frame before installing the Thread stack"
    );
    assert!(
        !body
            .lines()
            .any(|line| line.contains("\tcall\t") || line.contains("\tret")),
        "IRET handoff must not call or return on the retired boot stack"
    );
}

fn validate_terminal_reaper_handoff(disassembly: &str) {
    let body = function_body(disassembly, "dw_x86_64_terminal_reaper_handoff");
    let required = [
        "\tcli",
        "\tmov\tecx, 0xc0000101",
        "\trdmsr",
        "\tmov\tecx, 0xc0000102",
        "\trdmsr",
        "\tmov\trsp, qword ptr [rax + 0x30]",
        "\tand\trsp, -0x10",
        "\txor\trbp, rbp",
        "\tcall\tr9",
        "\tud2",
    ];
    let mut offset = 0;
    for needle in required {
        let next = body[offset..]
            .find(needle)
            .unwrap_or_else(|| panic!("terminal-reaper handoff omitted `{needle}`"));
        offset += next + needle.len();
    }
    assert_eq!(
        body.lines()
            .filter(|line| line.contains("\tcall\t"))
            .count(),
        1,
        "terminal-reaper handoff must make exactly one callback call"
    );
    assert!(
        !body.lines().any(|line| line.contains("\tret")),
        "terminal-reaper handoff must not return to the retired Thread stack"
    );
}

fn validate_rendezvous_reaper_handoff(disassembly: &str) {
    let body = function_body(disassembly, "dw_x86_64_rendezvous_reaper_handoff");
    let required = [
        "\tcli",
        "\tmov\tecx, 0xc0000101",
        "\trdmsr",
        "\tmov\tecx, 0xc0000102",
        "\trdmsr",
        "\tmov\trsp, qword ptr [rax + 0x30]",
        "\tand\trsp, -0x10",
        "\txor\trbp, rbp",
        "\tcall\t0x",
        " <dw_x86_64_rendezvous_reaper>",
        "\tud2",
    ];
    let mut offset = 0;
    for needle in required {
        let next = body[offset..]
            .find(needle)
            .unwrap_or_else(|| panic!("rendezvous-reaper handoff omitted `{needle}`"));
        offset += next + needle.len();
    }
    assert_eq!(
        body.lines()
            .filter(|line| line.contains("\tcall\t"))
            .count(),
        1,
        "rendezvous-reaper handoff must make exactly one fixed callback call"
    );
    assert!(
        !body.lines().any(|line| line.contains("\tret")),
        "rendezvous-reaper handoff must not return to the interrupted stack"
    );
}

#[test]
fn direct_call_stack_path_uses_the_deepest_accepted_objdump_branch() {
    let sizes = [
        StackSize {
            bytes: 16,
            symbol: "root".to_owned(),
        },
        StackSize {
            bytes: 32,
            symbol: "left".to_owned(),
        },
        StackSize {
            bytes: 8,
            symbol: "leaf".to_owned(),
        },
        StackSize {
            bytes: 24,
            symbol: "right".to_owned(),
        },
    ];
    let disassembly = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tcall\t0x1 <left>\n  5:\tcall\t0x2 <right>\n\n0010 <left>:\n 10:\tcall\t0x3 <leaf>\n\n0020 <leaf>:\n\n0030 <right>:\n";
    assert_eq!(
        direct_call_stack_bound(&sizes, disassembly, "test root", |symbol| symbol == "root"),
        DirectCallStackBound {
            bytes: 56,
            call_count: 2,
            terminal: "leaf".to_owned(),
        }
    );
}

#[test]
#[should_panic(expected = "duplicate .stack_sizes entry for root")]
fn direct_call_graph_rejects_conflicting_duplicate_frame_authority() {
    let sizes = [
        StackSize {
            bytes: 16,
            symbol: "root".to_owned(),
        },
        StackSize {
            bytes: 8,
            symbol: "root".to_owned(),
        },
    ];
    let disassembly = "Disassembly of section .text:\n\n0000 <root>:\n";
    let _ = DirectCallGraph::new(&sizes, disassembly);
}

#[test]
#[should_panic(expected = "reaches unresolved callee missing")]
fn direct_call_stack_path_rejects_unresolved_callees() {
    let sizes = [StackSize {
        bytes: 16,
        symbol: "root".to_owned(),
    }];
    let disassembly = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tcall\t0x1 <missing>\n";
    let _ = direct_call_stack_bound(&sizes, disassembly, "test root", |symbol| symbol == "root");
}

#[test]
#[should_panic(expected = "contains a cycle through root")]
fn direct_call_stack_path_rejects_cycles() {
    let sizes = [
        StackSize {
            bytes: 16,
            symbol: "root".to_owned(),
        },
        StackSize {
            bytes: 8,
            symbol: "child".to_owned(),
        },
    ];
    let disassembly = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tcall\t0x1 <child>\n\n0010 <child>:\n 10:\tcall\t0x2 <root>\n";
    let _ = direct_call_stack_bound(&sizes, disassembly, "test root", |symbol| symbol == "root");
}

#[test]
fn direct_call_stack_path_includes_direct_tail_jumps_but_not_local_jumps() {
    let sizes = [
        StackSize {
            bytes: 16,
            symbol: "root".to_owned(),
        },
        StackSize {
            bytes: 32,
            symbol: "tail".to_owned(),
        },
    ];
    let disassembly = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tjmp\t0x1 <root+0x4>\n  4:\tjmp\t0x2 <tail>\n\n0010 <tail>:\n";
    assert_eq!(
        direct_call_stack_bound(&sizes, disassembly, "test root", |symbol| symbol == "root"),
        DirectCallStackBound {
            bytes: 48,
            call_count: 1,
            terminal: "tail".to_owned(),
        }
    );
}

#[test]
fn terminal_reaper_handoff_ends_the_retired_stack_graph() {
    let sizes = [StackSize {
        bytes: 16,
        symbol: "root".to_owned(),
    }];
    let disassembly = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tcall\t0x10 <dw_x86_64_terminal_reaper_handoff>\n\n0010 <dw_x86_64_terminal_reaper_handoff>:\n 10:\tcli\n 11:\tmov\tecx, 0xc0000101\n 16:\trdmsr\n 18:\tmov\tecx, 0xc0000102\n 1d:\trdmsr\n 1f:\tmov\trsp, qword ptr [rax + 0x30]\n 24:\tand\trsp, -0x10\n 28:\txor\trbp, rbp\n 2b:\tcall\tr9\n 2e:\tud2\n";
    assert_eq!(
        direct_call_stack_bound(&sizes, disassembly, "terminal pivot", |symbol| {
            symbol == "root"
        }),
        DirectCallStackBound {
            bytes: 16,
            call_count: 1,
            terminal: "audited terminal-reaper stack pivot".to_owned(),
        }
    );
}

#[test]
fn iret_handoff_ends_the_boot_stack_graph() {
    let sizes = [StackSize {
        bytes: 16,
        symbol: "root".to_owned(),
    }];
    let disassembly = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tcall\t0x10 <dw_x86_64_iret_to_user>\n\n0010 <dw_x86_64_iret_to_user>:\n 10:\tmov\tr12, rdi\n 13:\tmov\trsp, qword ptr gs:[0x8]\n 1c:\ttest\trsp, rsp\n 1f:\tje\t0x30 <halt>\n 21:\tpush\t0x2b\n 23:\tpush\tqword ptr [r12 + 0x88]\n 2b:\tpush\tqword ptr [r12 + 0x80]\n 33:\tpush\t0x33\n 35:\tpush\tqword ptr [r12 + 0x78]\n 3d:\tswapgs\n 40:\tiretq\n";
    assert_eq!(
        direct_call_stack_bound(sizes.as_slice(), disassembly, "IRET pivot", |symbol| {
            symbol == "root"
        }),
        DirectCallStackBound {
            bytes: 16,
            call_count: 1,
            terminal: "audited Thread-stack IRET pivot".to_owned(),
        }
    );
}

#[test]
fn rendezvous_reaper_handoff_ends_the_interrupted_stack_graph() {
    let sizes = [StackSize {
        bytes: 16,
        symbol: "root".to_owned(),
    }];
    let disassembly = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tcall\t0x10 <dw_x86_64_rendezvous_reaper_handoff>\n\n0010 <dw_x86_64_rendezvous_reaper_handoff>:\n 10:\tcli\n 11:\tmov\tecx, 0xc0000101\n 16:\trdmsr\n 18:\tmov\tecx, 0xc0000102\n 1d:\trdmsr\n 1f:\tmov\trsp, qword ptr [rax + 0x30]\n 24:\tand\trsp, -0x10\n 28:\txor\trbp, rbp\n 2b:\tcall\t0x30 <dw_x86_64_rendezvous_reaper>\n 2e:\tud2\n";
    assert_eq!(
        direct_call_stack_bound(
            sizes.as_slice(),
            disassembly,
            "rendezvous pivot",
            |symbol| { symbol == "root" }
        ),
        DirectCallStackBound {
            bytes: 16,
            call_count: 1,
            terminal: "audited rendezvous-reaper stack pivot".to_owned(),
        }
    );
}

#[test]
fn direct_call_stack_path_selects_by_frames_and_return_addresses() {
    let sizes = [
        StackSize {
            bytes: 0,
            symbol: "root".to_owned(),
        },
        StackSize {
            bytes: 64,
            symbol: "wide".to_owned(),
        },
        StackSize {
            bytes: 50,
            symbol: "deep".to_owned(),
        },
        StackSize {
            bytes: 8,
            symbol: "leaf".to_owned(),
        },
    ];
    let disassembly = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tcall\t0x1 <wide>\n  5:\tcall\t0x2 <deep>\n\n0010 <wide>:\n\n0020 <deep>:\n 20:\tcall\t0x3 <leaf>\n\n0030 <leaf>:\n";
    assert_eq!(
        direct_call_stack_bound(&sizes, disassembly, "test root", |symbol| symbol == "root"),
        DirectCallStackBound {
            bytes: 58,
            call_count: 2,
            terminal: "leaf".to_owned(),
        }
    );
}

#[test]
fn direct_call_stack_path_charges_a_return_for_a_zero_frame_leaf() {
    let sizes = [
        StackSize {
            bytes: 16,
            symbol: "root".to_owned(),
        },
        StackSize {
            bytes: 0,
            symbol: "leaf".to_owned(),
        },
    ];
    let disassembly =
        "Disassembly of section .text:\n\n0000 <root>:\n  0:\tcall\t0x1 <leaf>\n\n0010 <leaf>:\n";
    assert_eq!(
        direct_call_stack_bound(&sizes, disassembly, "zero-frame leaf", |symbol| {
            symbol == "root"
        }),
        DirectCallStackBound {
            bytes: 16,
            call_count: 1,
            terminal: "leaf".to_owned(),
        }
    );
}

#[test]
#[should_panic(expected = "unbounded indirect control transfer")]
fn direct_call_stack_path_rejects_unbounded_indirect_calls() {
    let sizes = [StackSize {
        bytes: 16,
        symbol: "root".to_owned(),
    }];
    let disassembly = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tcall\trax\n";
    let _ = direct_call_stack_bound(&sizes, disassembly, "test root", |symbol| symbol == "root");
}

#[test]
fn direct_call_stack_path_accepts_an_exact_linear_indirect_resolution() {
    let sizes = [
        StackSize {
            bytes: 16,
            symbol: "root".to_owned(),
        },
        StackSize {
            bytes: 32,
            symbol: "typed-target".to_owned(),
        },
    ];
    let disassembly =
        "Disassembly of section .text:\n\n0000 <root>:\n  0:\tcall\trax\n\n0010 <typed-target>:\n";
    let resolutions = BTreeMap::from([("root".to_owned(), vec!["typed-target".to_owned()])]);
    assert_eq!(
        direct_call_stack_bound_with_resolutions(
            &sizes,
            disassembly,
            "resolved test root",
            |symbol| symbol == "root",
            &resolutions,
        ),
        DirectCallStackBound {
            bytes: 48,
            call_count: 1,
            terminal: "typed-target".to_owned(),
        }
    );
}

#[test]
fn direct_call_stack_path_binds_a_typed_resolution_to_its_exact_indirect_owner() {
    let sizes = [
        StackSize {
            bytes: 16,
            symbol: "wrapper".to_owned(),
        },
        StackSize {
            bytes: 32,
            symbol: "locked-helper".to_owned(),
        },
        StackSize {
            bytes: 64,
            symbol: "typed-target".to_owned(),
        },
    ];
    let disassembly = "Disassembly of section .text:\n\n0000 <wrapper>:\n  0:\tcall\t0x10 <locked-helper>\n\n0010 <locked-helper>:\n 10:\tcall\trax\n\n0020 <typed-target>:\n";
    let wrong_owner = BTreeMap::from([("wrapper".to_owned(), vec!["typed-target".to_owned()])]);
    let rejected = std::panic::catch_unwind(|| {
        direct_call_stack_bound_with_resolutions(
            &sizes,
            disassembly,
            "wrong indirect owner",
            |symbol| symbol == "wrapper",
            &wrong_owner,
        )
    });
    assert!(rejected.is_err());

    let exact_owner =
        BTreeMap::from([("locked-helper".to_owned(), vec!["typed-target".to_owned()])]);
    assert_eq!(
        direct_call_stack_bound_with_resolutions(
            &sizes,
            disassembly,
            "exact indirect owner",
            |symbol| symbol == "wrapper",
            &exact_owner,
        ),
        DirectCallStackBound {
            bytes: 112,
            call_count: 2,
            terminal: "typed-target".to_owned(),
        }
    );
}

#[test]
fn resolved_terminal_reaper_graph_reuses_bounded_memoized_states() {
    let sizes = [
        StackSize {
            bytes: 8,
            symbol: "syscall-root".to_owned(),
        },
        StackSize {
            bytes: 16,
            symbol: "native_runtime_terminal_reaper::<F12Runtime>".to_owned(),
        },
        StackSize {
            bytes: 24,
            symbol: "shared-finalizer".to_owned(),
        },
        StackSize {
            bytes: 32,
            symbol: "typed-timer-cancel".to_owned(),
        },
    ];
    let disassembly = "Disassembly of section .text:\n\n0000 <syscall-root>:\n  0:\tcall\t0x20 <shared-finalizer>\n\n0010 <native_runtime_terminal_reaper::<F12Runtime>>:\n 10:\tcall\t0x20 <shared-finalizer>\n\n0020 <shared-finalizer>:\n 20:\tcall\trax\n\n0030 <typed-timer-cancel>:\n";
    let resolutions = BTreeMap::from([(
        "shared-finalizer".to_owned(),
        vec!["typed-timer-cancel".to_owned()],
    )]);
    let graph = DirectCallGraph::new(&sizes, disassembly);
    let mut resolved = graph.with_resolutions(&resolutions);
    assert_eq!(
        resolved.stack_bound("syscall root", |symbol| symbol == "syscall-root"),
        DirectCallStackBound {
            bytes: 64,
            call_count: 2,
            terminal: "typed-timer-cancel".to_owned(),
        }
    );
    assert_eq!(resolved.memoized_symbol_count(), 3);
    assert_eq!(
        resolved.stack_bound("terminal root", |symbol| {
            symbol == "native_runtime_terminal_reaper::<F12Runtime>"
        }),
        DirectCallStackBound {
            bytes: 72,
            call_count: 2,
            terminal: "typed-timer-cancel".to_owned(),
        }
    );
    assert_eq!(resolved.memoized_symbol_count(), sizes.len());
}

#[test]
fn resolved_old_stack_edge_stops_at_the_audited_terminal_reaper_pivot() {
    let sizes = [
        StackSize {
            bytes: 16,
            symbol: "old-stack-root".to_owned(),
        },
        StackSize {
            bytes: 8,
            symbol: "unused-selector-target".to_owned(),
        },
    ];
    let disassembly = "Disassembly of section .text:\n\n0000 <old-stack-root>:\n  0:\tcall\trax\n\n0010 <dw_x86_64_terminal_reaper_handoff>:\n 10:\tcli\n 11:\tmov\tecx, 0xc0000101\n 16:\trdmsr\n 18:\tmov\tecx, 0xc0000102\n 1d:\trdmsr\n 1f:\tmov\trsp, qword ptr [rax + 0x30]\n 24:\tand\trsp, -0x10\n 28:\txor\trbp, rbp\n 2b:\tcall\tr9\n 2e:\tud2\n\n0030 <unused-selector-target>:\n";
    let resolutions = BTreeMap::from([
        (
            "old-stack-root".to_owned(),
            vec!["dw_x86_64_terminal_reaper_handoff".to_owned()],
        ),
        (
            "unused-selector-root".to_owned(),
            vec!["unused-selector-target".to_owned()],
        ),
    ]);
    assert_eq!(
        direct_call_stack_bound_with_resolutions(
            &sizes,
            disassembly,
            "resolved terminal pivot",
            |symbol| symbol == "old-stack-root",
            &resolutions,
        ),
        DirectCallStackBound {
            bytes: 16,
            call_count: 1,
            terminal: "audited terminal-reaper stack pivot".to_owned(),
        }
    );
}

#[test]
#[should_panic(expected = "contains a cycle through root")]
fn resolved_indirect_edges_participate_in_cycle_rejection() {
    let sizes = [
        StackSize {
            bytes: 16,
            symbol: "root".to_owned(),
        },
        StackSize {
            bytes: 8,
            symbol: "child".to_owned(),
        },
    ];
    let disassembly = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tcall\trax\n\n0010 <child>:\n 10:\tcall\t0x0 <root>\n";
    let resolutions = BTreeMap::from([("root".to_owned(), vec!["child".to_owned()])]);
    let _ = direct_call_stack_bound_with_resolutions(
        &sizes,
        disassembly,
        "resolved cycle",
        |symbol| symbol == "root",
        &resolutions,
    );
}

#[test]
fn direct_call_stack_path_bounds_exact_terminal_panic_entries() {
    for panic in [
        "core::panicking::panic_fmt",
        "core::panicking::panic_nounwind_fmt",
    ] {
        let sizes = [
            StackSize {
                bytes: 16,
                symbol: "root".to_owned(),
            },
            StackSize {
                bytes: 32,
                symbol: panic.to_owned(),
            },
        ];
        let disassembly = format!(
            "Disassembly of section .text:\n\n0000 <root>:\n  0:\tcall\t0x1 <{panic}>\n\n0010 <{panic}>:\n 10:\tcall\t0x1 <{panic}>\n"
        );
        assert_eq!(
            direct_call_stack_bound(&sizes, &disassembly, "terminal panic", |symbol| {
                symbol == "root"
            }),
            DirectCallStackBound {
                bytes: 16 + 16 * 1024,
                call_count: 1,
                terminal: "bounded terminal kernel panic path".to_owned(),
            }
        );
    }
}

#[test]
fn direct_call_stack_path_accepts_only_the_complete_local_relative_jump_table_idiom() {
    let sizes = [StackSize {
        bytes: 16,
        symbol: "root".to_owned(),
    }];
    let local = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tlea\trax, [rip + 0x20]\n  7:\tmovsxd\trcx, dword ptr [rax + 4*rcx]\n  b:\tadd\trax, rcx\n  e:\tjmp\trax\n";
    assert_eq!(
        direct_call_stack_bound(&sizes, local, "local jump table", |symbol| symbol == "root"),
        DirectCallStackBound {
            bytes: 16,
            call_count: 0,
            terminal: "root".to_owned(),
        }
    );
    let incomplete = "Disassembly of section .text:\n\n0000 <root>:\n  0:\tlea\trax, [rip + 0x20]\n  7:\tjmp\trax\n";
    let failed = std::panic::catch_unwind(|| {
        direct_call_stack_bound(&sizes, incomplete, "incomplete jump table", |symbol| {
            symbol == "root"
        })
    });
    assert!(failed.is_err());
}

#[path = "stack/dw1c.rs"]
mod dw1c;
#[path = "stack/e7.rs"]
mod e7;
#[path = "stack/f12.rs"]
mod f12;
#[path = "stack/f9.rs"]
mod f9;
#[path = "stack/geometry.rs"]
mod geometry;
#[path = "stack/ist.rs"]
mod ist;
#[path = "stack/primordial.rs"]
mod primordial;
#[path = "stack/production.rs"]
mod production;
#[path = "stack/selector.rs"]
mod selector;

pub(super) use dw1c::validate_dw1c_thread_stack_margin;
pub(super) use e7::validate_e7_stack_margin;
pub(super) use f9::validate_f9_stack_context_evidence;
pub(super) use f12::validate_f12_stack_context_evidence;
pub(super) use geometry::linked_boot_stack_payload_bytes;
pub(super) use geometry::linked_terminal_reaper_stack_payload_bytes;
pub(super) use geometry::linked_thread_kernel_stack_payload_bytes;
pub(super) use geometry::validate_kernel_stack_artifact_geometry;
pub(super) use primordial::validate_primordial_boot_stack_margin;
pub(super) use production::validate_production_ist_stack_margin;
pub(super) use selector::validate_selector_stack_margin;
