//! A minimal ELF64 reader for the analysis kernel, and the direct-call stack
//! bound computed from it.
//!
//! The analysis kernel is linked with `--emit-relocs`, so every place the
//! linker patched in `.text` is listed in `.rela.text`. A direct call or tail
//! jump to another function always carries one (each function is its own input
//! section), so the relocations find every such call site without a
//! disassembler; the bytes before the patched field say which instruction it
//! is, and the patched field itself says where it goes. Calls through a
//! register are not visible here: that is dynamic dispatch, which the measured
//! half of the check covers (DW2 plan §10.2 item 2).

use std::collections::{BTreeMap, BTreeSet};

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const SHT_SYMTAB: u32 = 2;
const SHT_RELA: u32 = 4;
const SHT_NOBITS: u32 = 8;
const STT_FUNC: u8 = 2;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const R_X86_64_PC32: u32 = 2;
const R_X86_64_PLT32: u32 = 4;
const R_X86_64_GOTPCREL: u32 = 9;
const R_X86_64_GOTPCRELX: u32 = 41;
const R_X86_64_REX_GOTPCRELX: u32 = 42;

#[derive(Clone, Debug)]
pub(crate) struct Section {
    pub(crate) name: String,
    kind: u32,
    addr: u64,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Function {
    pub(crate) name: String,
    pub(crate) addr: u64,
    pub(crate) size: u64,
}

pub(crate) struct Elf<'a> {
    bytes: &'a [u8],
    sections: Vec<Section>,
    program_types: Vec<u32>,
    elf_type: u16,
}

fn field<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N], String> {
    at.checked_add(N)
        .and_then(|end| bytes.get(at..end))
        .and_then(|slice| slice.try_into().ok())
        .ok_or_else(|| format!("ELF read of {N} bytes at {at:#x} is out of bounds"))
}
fn u16_at(bytes: &[u8], at: usize) -> Result<u16, String> {
    field(bytes, at).map(u16::from_le_bytes)
}
fn u32_at(bytes: &[u8], at: usize) -> Result<u32, String> {
    field(bytes, at).map(u32::from_le_bytes)
}
fn u64_at(bytes: &[u8], at: usize) -> Result<u64, String> {
    field(bytes, at).map(u64::from_le_bytes)
}
fn usize_of(value: u64) -> Result<usize, String> {
    usize::try_from(value).map_err(|_| format!("ELF value {value:#x} does not fit"))
}
fn c_string(table: &[u8], at: u32) -> Result<String, String> {
    let tail = table
        .get(at as usize..)
        .ok_or_else(|| format!("string offset {at:#x} is out of bounds"))?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("unterminated ELF string")?;
    String::from_utf8(tail[..end].to_vec()).map_err(|_| "non-UTF-8 ELF string".into())
}

impl<'a> Elf<'a> {
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, String> {
        if bytes.get(..4) != Some(ELF_MAGIC.as_slice())
            || bytes.get(4) != Some(&ELFCLASS64)
            || bytes.get(5) != Some(&ELFDATA2LSB)
        {
            return Err("not a little-endian ELF64 file".into());
        }
        if u16_at(bytes, 0x12)? != EM_X86_64 {
            return Err("not an x86_64 ELF file".into());
        }
        let elf_type = u16_at(bytes, 0x10)?;
        let phoff = usize_of(u64_at(bytes, 0x20)?)?;
        let shoff = usize_of(u64_at(bytes, 0x28)?)?;
        let phentsize = usize::from(u16_at(bytes, 0x36)?);
        let phnum = usize::from(u16_at(bytes, 0x38)?);
        let shentsize = usize::from(u16_at(bytes, 0x3a)?);
        let shnum = usize::from(u16_at(bytes, 0x3c)?);
        let shstrndx = usize::from(u16_at(bytes, 0x3e)?);
        if (phnum > 0 && phentsize < 56) || shentsize < 64 || shnum == 0 {
            return Err("unexpected ELF header table geometry".into());
        }
        let mut program_types = Vec::with_capacity(phnum);
        for index in 0..phnum {
            program_types.push(u32_at(bytes, phoff + index * phentsize)?);
        }
        let mut raw = Vec::with_capacity(shnum);
        for index in 0..shnum {
            let at = shoff + index * shentsize;
            raw.push((
                u32_at(bytes, at)?,
                Section {
                    name: String::new(),
                    kind: u32_at(bytes, at + 4)?,
                    addr: u64_at(bytes, at + 16)?,
                    offset: u64_at(bytes, at + 24)?,
                    size: u64_at(bytes, at + 32)?,
                    link: u32_at(bytes, at + 40)?,
                    info: u32_at(bytes, at + 44)?,
                },
            ));
        }
        let mut elf = Self {
            bytes,
            sections: raw.iter().map(|(_, section)| section.clone()).collect(),
            program_types,
            elf_type,
        };
        let names = elf
            .contents(shstrndx)
            .map_err(|error| format!("section name table: {error}"))?
            .to_vec();
        for (section, (name, _)) in elf.sections.iter_mut().zip(&raw) {
            section.name = c_string(&names, *name)?;
        }
        Ok(elf)
    }

    /// A statically linked executable: no interpreter and no dynamic section.
    pub(crate) fn freestanding_problem(&self) -> Option<&'static str> {
        if self.elf_type != ET_EXEC {
            Some("the kernel is not an ET_EXEC image")
        } else if self.program_types.contains(&PT_INTERP) {
            Some("the kernel names a program interpreter")
        } else if self.program_types.contains(&PT_DYNAMIC) {
            Some("the kernel has a dynamic section")
        } else {
            None
        }
    }

    fn contents(&self, index: usize) -> Result<&'a [u8], String> {
        let section = self
            .sections
            .get(index)
            .ok_or_else(|| format!("section {index} does not exist"))?;
        if section.kind == SHT_NOBITS {
            return Ok(&[]);
        }
        let start = usize_of(section.offset)?;
        start
            .checked_add(usize_of(section.size)?)
            .and_then(|end| self.bytes.get(start..end))
            .ok_or_else(|| format!("section {} lies outside the file", section.name))
    }

    fn named(&self, name: &str) -> Result<usize, String> {
        let mut matches = self
            .sections
            .iter()
            .enumerate()
            .filter(|(_, s)| s.name == name);
        match (matches.next(), matches.next()) {
            (Some((index, _)), None) => Ok(index),
            (None, _) => Err(format!("the kernel has no {name} section")),
            (Some(_), Some(_)) => Err(format!("the kernel has two {name} sections")),
        }
    }

    pub(crate) fn section_bytes(&self, name: &str) -> Result<&'a [u8], String> {
        self.contents(self.named(name)?)
    }

    /// The function pointer a constant slot holds: a slot in `.rodata`. A
    /// slot anywhere else is written at run time (dynamic dispatch, `None`).
    fn constant_slot(&self, addr: u64) -> Result<Option<u64>, String> {
        let index = self.named(".rodata")?;
        let section = &self.sections[index];
        let inside = addr >= section.addr
            && addr
                .checked_add(8)
                .is_some_and(|end| end <= section.addr.saturating_add(section.size));
        if !inside {
            return Ok(None);
        }
        let start = usize_of(addr - section.addr)?;
        u64_at(self.contents(index)?, start).map(Some)
    }

    /// The frame a function without a stack-size entry (precompiled sysroot
    /// code, assembly) sets up in its prologue: see [`prologue_frame`].
    pub(crate) fn prologue_frame(&self, function: &Function) -> Result<u64, String> {
        let text = self.named(".text")?;
        let section = &self.sections[text];
        let start = usize_of(
            function
                .addr
                .checked_sub(section.addr)
                .ok_or("a function lies before .text")?,
        )?;
        let code = self.contents(text)?;
        let end = start
            .checked_add(usize_of(function.size)?)
            .filter(|end| *end <= code.len())
            .ok_or("a function runs past .text")?;
        Ok(prologue_frame(&code[start..end]))
    }

    pub(crate) fn functions(&self) -> Result<Vec<Function>, String> {
        let symtab = self
            .sections
            .iter()
            .position(|section| section.kind == SHT_SYMTAB)
            .ok_or("the kernel has no symbol table")?;
        let strings = self.contents(self.sections[symtab].link as usize)?;
        let table = self.contents(symtab)?;
        let mut functions = Vec::new();
        for entry in table.as_chunks::<24>().0 {
            let info = entry[4];
            let size = u64_at(entry, 16)?;
            if info & 0xf == STT_FUNC && size > 0 {
                functions.push(Function {
                    name: c_string(strings, u32_at(entry, 0)?)?,
                    addr: u64_at(entry, 8)?,
                    size,
                });
            }
        }
        functions.sort_by(|a, b| (a.addr, &a.name).cmp(&(b.addr, &b.name)));
        functions.dedup_by(|b, a| a.addr == b.addr && a.size == b.size);
        for pair in functions.windows(2) {
            if pair[0].addr + pair[0].size > pair[1].addr {
                return Err(format!(
                    "functions {} and {} overlap",
                    pair[0].name, pair[1].name
                ));
            }
        }
        Ok(functions)
    }

    /// LLVM's `.stack_sizes`: a function address and a ULEB128 frame size per
    /// entry. The frame excludes the return address its caller pushed.
    pub(crate) fn stack_sizes(&self) -> Result<BTreeMap<u64, u64>, String> {
        parse_stack_sizes(self.section_bytes(".stack_sizes")?)
    }

    /// Every direct call and tail jump in `.text`, and every call or jump
    /// through a constant slot, with its resolved destination.
    pub(crate) fn branches(&self) -> Result<Vec<Branch>, String> {
        let text = self.named(".text")?;
        let base = self.sections[text].addr;
        let code = self.contents(text)?;
        let mut branches = Vec::new();
        for (index, section) in self.sections.iter().enumerate() {
            if section.kind != SHT_RELA || section.info as usize != text {
                continue;
            }
            for entry in self.contents(index)?.as_chunks::<24>().0 {
                let place = u64_at(entry, 0)?;
                let kind = u64_at(entry, 8)? as u32;
                if !matches!(
                    kind,
                    R_X86_64_PC32
                        | R_X86_64_PLT32
                        | R_X86_64_GOTPCREL
                        | R_X86_64_GOTPCRELX
                        | R_X86_64_REX_GOTPCRELX
                ) {
                    continue;
                }
                let at = usize_of(
                    place
                        .checked_sub(base)
                        .ok_or("a .text relocation lies before .text")?,
                )?;
                if let Some(branch) = classify(code, at, place, |slot| self.constant_slot(slot))? {
                    branches.push(branch);
                }
            }
        }
        if branches.is_empty() {
            return Err("no branch relocations: was the kernel linked with --emit-relocs?".into());
        }
        Ok(branches)
    }
}

/// Bytes an LLVM-style prologue reserves: its leading `push`es and
/// `sub rsp, imm`, past an optional `endbr64` and `mov rbp, rsp`. Code without
/// a stack-size entry is precompiled builtins and hand-written assembly, which
/// set up their whole frame there.
pub(crate) fn prologue_frame(code: &[u8]) -> u64 {
    let mut frame = 0u64;
    let mut at = 0;
    loop {
        let rest = &code[at.min(code.len())..];
        match rest {
            [0xf3, 0x0f, 0x1e, 0xfa, ..] => at += 4,
            [0x50..=0x57, ..] => {
                frame += 8;
                at += 1;
            }
            [0x41, 0x50..=0x57, ..] => {
                frame += 8;
                at += 2;
            }
            [0x48, 0x89, 0xe5, ..] => at += 3,
            [0x48, 0x83, 0xec, imm, ..] => {
                frame += u64::from(*imm);
                at += 4;
            }
            [0x48, 0x81, 0xec, a, b, c, d, ..] => {
                frame += u64::from(u32::from_le_bytes([*a, *b, *c, *d]));
                at += 7;
            }
            _ => return frame,
        }
    }
}

pub(crate) fn parse_stack_sizes(section: &[u8]) -> Result<BTreeMap<u64, u64>, String> {
    let mut sizes = BTreeMap::new();
    let mut at = 0;
    while at < section.len() {
        let addr = u64_at(section, at)?;
        at += 8;
        let mut size = 0u64;
        let mut shift = 0;
        loop {
            let byte = *section.get(at).ok_or("truncated .stack_sizes entry")?;
            at += 1;
            if shift > 63 {
                return Err("oversized .stack_sizes entry".into());
            }
            size |= u64::from(byte & 0x7f) << shift;
            shift += 7;
            if byte & 0x80 == 0 {
                break;
            }
        }
        let entry = sizes.entry(addr).or_insert(size);
        *entry = (*entry).max(size);
    }
    Ok(sizes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BranchKind {
    /// Pushes a return address; the caller's frame stays.
    Call,
    /// Leaves for another function; charged as if the caller's frame stayed.
    Jump,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Branch {
    pub(crate) site: u64,
    pub(crate) kind: BranchKind,
    pub(crate) target: u64,
}

/// What instruction owns a 32-bit PC-relative field at `at` (`place` is its
/// address). A memory operand's field is preceded by its ModRM byte, and no
/// RIP-relative ModRM byte (`00 reg 101`) is E8, E9 or 80–8F, so those bytes
/// can only be the opcodes of `call rel32`, `jmp rel32` and `jcc rel32`.
/// `FF 15` and `FF 25` are `call`/`jmp [rip+disp32]`: a constant slot is read
/// from the image, and a writable one is dynamic dispatch, left out.
pub(crate) fn classify(
    code: &[u8],
    at: usize,
    place: u64,
    read_slot: impl Fn(u64) -> Result<Option<u64>, String>,
) -> Result<Option<Branch>, String> {
    let field = i64::from(i32::from_le_bytes(field(code, at)?));
    let destination = (place as i64).wrapping_add(4).wrapping_add(field) as u64;
    let one = at.checked_sub(1).and_then(|i| code.get(i)).copied();
    let two = at.checked_sub(2).and_then(|i| code.get(i)).copied();
    let branch = |kind, target| {
        Some(Branch {
            site: place,
            kind,
            target,
        })
    };
    Ok(match (two, one) {
        (_, Some(0xe8)) => branch(BranchKind::Call, destination),
        (_, Some(0xe9)) => branch(BranchKind::Jump, destination),
        (Some(0x0f), Some(0x80..=0x8f)) => branch(BranchKind::Jump, destination),
        (Some(0xff), Some(0x15)) => {
            read_slot(destination)?.and_then(|t| branch(BranchKind::Call, t))
        }
        (Some(0xff), Some(0x25)) => {
            read_slot(destination)?.and_then(|t| branch(BranchKind::Jump, t))
        }
        _ => None,
    })
}

/// A readable path from a v0-mangled name: its identifiers joined by `::`.
/// Generic arguments are flattened into the path, so the result is for people,
/// never for matching.
pub(crate) fn display_name(mangled: &str) -> String {
    let name = mangled.split(".llvm.").next().unwrap_or(mangled);
    let Some(body) = name.strip_prefix("_R") else {
        return name.to_owned();
    };
    let bytes = body.as_bytes();
    let mut parts: Vec<&str> = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'0'..=b'9' => {
                let start = at;
                while at < bytes.len() && bytes[at].is_ascii_digit() {
                    at += 1;
                }
                let Ok(length) = body[start..at].parse::<usize>() else {
                    break;
                };
                if bytes.get(at) == Some(&b'_') {
                    at += 1;
                }
                let Some(ident) = body.get(at..at + length) else {
                    break;
                };
                parts.push(ident);
                at += length;
            }
            b'C' | b'N' | b'M' | b'X' | b'Y' | b'I' if bytes.get(at + 1) == Some(&b's') => {
                at += 2;
                skip_past_underscore(bytes, &mut at);
            }
            b'B' => {
                at += 1;
                skip_past_underscore(bytes, &mut at);
            }
            b'K' => {
                at += 2;
                skip_past_underscore(bytes, &mut at);
            }
            b's' if at > 0 && matches!(bytes[at - 1], b'N' | b'C' | b'v' | b't' | b'X' | b'M') => {
                at += 1;
                skip_past_underscore(bytes, &mut at);
            }
            _ => at += 1,
        }
    }
    if parts.is_empty() {
        name.to_owned()
    } else {
        parts.join("::")
    }
}

fn skip_past_underscore(bytes: &[u8], at: &mut usize) {
    while *at < bytes.len() && bytes[*at].is_ascii_alphanumeric() {
        *at += 1;
    }
    if *at < bytes.len() && bytes[*at] == b'_' {
        *at += 1;
    }
}

/// The call graph between functions, keyed by function index.
pub(crate) struct CallGraph {
    pub(crate) functions: Vec<Function>,
    pub(crate) frames: Vec<Option<u64>>,
    pub(crate) edges: Vec<BTreeSet<(usize, BranchKind)>>,
    /// Functions whose frame was read from their prologue.
    pub(crate) decoded: BTreeSet<usize>,
}

impl PartialOrd for BranchKind {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for BranchKind {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

impl CallGraph {
    pub(crate) fn build(
        functions: Vec<Function>,
        sizes: &BTreeMap<u64, u64>,
        branches: &[Branch],
    ) -> Result<Self, String> {
        let frames = functions
            .iter()
            .map(|f| sizes.get(&f.addr).copied())
            .collect();
        let mut edges = vec![BTreeSet::new(); functions.len()];
        let containing = |addr: u64| {
            let index = functions
                .partition_point(|f| f.addr <= addr)
                .checked_sub(1)?;
            (addr < functions[index].addr + functions[index].size).then_some(index)
        };
        for branch in branches {
            // A patched field outside every sized symbol belongs to code with
            // no symbol of its own; nothing in the graph can reach it.
            let Some(caller) = containing(branch.site) else {
                continue;
            };
            let Some(callee) = containing(branch.target) else {
                return Err(format!(
                    "{} branches to {:#x}, which is in no function",
                    display_name(&functions[caller].name),
                    branch.target
                ));
            };
            if callee == caller {
                if functions[callee].addr == branch.target {
                    edges[caller].insert((callee, branch.kind));
                }
                continue;
            }
            if functions[callee].addr != branch.target {
                return Err(format!(
                    "{} branches into the middle of {}",
                    display_name(&functions[caller].name),
                    display_name(&functions[callee].name)
                ));
            }
            edges[caller].insert((callee, branch.kind));
        }
        Ok(Self {
            functions,
            frames,
            edges,
            decoded: BTreeSet::new(),
        })
    }

    pub(crate) fn add_edge(&mut self, from: usize, to: usize) {
        self.edges[from].insert((to, BranchKind::Call));
    }

    /// Charges a self-recursive function `depth` nested frames and drops its
    /// self edge.
    pub(crate) fn unroll_self_recursion(&mut self, index: usize, depth: u64) {
        self.edges[index].retain(|(callee, _)| *callee != index);
        if let Some(frame) = self.frames[index] {
            self.frames[index] = Some(frame * depth + 8 * depth.saturating_sub(1));
        }
    }

    pub(crate) fn matching(&self, predicate: impl Fn(&str) -> bool) -> Vec<usize> {
        (0..self.functions.len())
            .filter(|index| predicate(&self.functions[*index].name))
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum BoundError {
    Recursion(Vec<usize>),
    NoFrame(Vec<usize>),
}

/// The deepest stack a root can reach through direct branches, and the path
/// that reaches it. `cut` names callees that are not followed (terminal
/// paths). A function with no frame size fails the bound.
pub(crate) fn deepest_path(
    graph: &CallGraph,
    root: usize,
    cut: &dyn Fn(&str) -> bool,
) -> Result<(u64, Vec<usize>), BoundError> {
    enum Visit {
        Enter(usize),
        Leave(usize),
    }
    let mut done: BTreeMap<usize, (u64, Option<usize>)> = BTreeMap::new();
    let mut on_path: Vec<usize> = Vec::new();
    let mut stack = vec![Visit::Enter(root)];
    while let Some(visit) = stack.pop() {
        match visit {
            Visit::Enter(node) => {
                if done.contains_key(&node) {
                    continue;
                }
                if let Some(start) = on_path.iter().position(|n| *n == node) {
                    let mut cycle = on_path[start..].to_vec();
                    cycle.push(node);
                    return Err(BoundError::Recursion(cycle));
                }
                on_path.push(node);
                stack.push(Visit::Leave(node));
                for (callee, _) in graph.edges[node].iter().rev() {
                    if !cut(&graph.functions[*callee].name) && !done.contains_key(callee) {
                        stack.push(Visit::Enter(*callee));
                    }
                }
            }
            Visit::Leave(node) => {
                on_path.pop();
                let Some(frame) = graph.frames[node] else {
                    let mut path = on_path.clone();
                    path.push(node);
                    return Err(BoundError::NoFrame(path));
                };
                let mut best = (0, None);
                for (callee, kind) in &graph.edges[node] {
                    if cut(&graph.functions[*callee].name) {
                        continue;
                    }
                    let below = done[callee].0
                        + match kind {
                            BranchKind::Call => 8,
                            BranchKind::Jump => 0,
                        };
                    if below > best.0 {
                        best = (below, Some(*callee));
                    }
                }
                done.insert(node, (frame + best.0, best.1));
            }
        }
    }
    let mut path = vec![root];
    while let Some(next) = done[path.last().expect("path starts at the root")].1 {
        path.push(next);
    }
    Ok((done[&root].0, path))
}
