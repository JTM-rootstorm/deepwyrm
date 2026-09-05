#[allow(dead_code)]
#[path = "../build.rs"]
mod kernel_build;

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const ELF64_SECTION_HEADER_SIZE: usize = 64;
const ELF64_SYMBOL_SIZE: usize = 24;
const SHT_RELA: u32 = 4;
const SHT_SYMTAB: u32 = 2;
const SHT_REL: u32 = 9;
const PAGE_SIZE: u64 = 4096;

#[test]
fn h1_trampoline_build_and_link_paths_retain_the_template_section() {
    let build = source("build.rs");
    let linker = source("arch/x86_64/linker.ld");

    for evidence in [
        "src/arch/x86_64/ap_trampoline.S",
        "deepwyrm-x86_64-ap-trampoline.o",
        "assemble_source(&ap_trampoline_path, &ap_trampoline_object, layout)?",
        "ap_trampoline_object.as_path()",
    ] {
        assert!(build.contains(evidence), "build path omitted `{evidence}`");
    }
    assert!(
        linker.contains("KEEP(*(.rodata.ap_trampoline_template))"),
        "the linker must retain the copyable AP trampoline template"
    );
}

#[test]
fn h1_trampoline_template_is_one_page_and_relocation_free() {
    let clang = env::var_os("DEEPWYRM_CLANG").unwrap_or_else(|| "clang".into());
    if !tool_available(&clang) {
        eprintln!("skipping AP trampoline artifact probe: clang unavailable");
        return;
    }

    let layout_source = fs::read_to_string(kernel_root().join("arch/x86_64/layout.toml"))
        .expect("read canonical layout manifest");
    let layout =
        kernel_build::Layout::parse(&layout_source).expect("parse canonical layout manifest");
    let temporary = TemporaryDirectory::new("deepwyrm-h1-ap-trampoline");
    let object = temporary.path.join("ap-trampoline.o");

    kernel_build::assemble_source(&assembly_path(), &object, layout)
        .expect("assemble the AP trampoline through the production build helper");

    let object = fs::read(&object).expect("read AP trampoline object");
    let elf = Elf::parse(&object);
    let template = elf
        .section_named(".rodata.ap_trampoline_template")
        .expect("AP trampoline template section");
    assert!(
        template.size > 0 && template.size <= PAGE_SIZE,
        "AP trampoline template must fit one low page, got {} bytes",
        template.size
    );
    assert_eq!(
        elf.sections_named(".rodata.ap_trampoline_template").count(),
        1,
        "AP trampoline template section must be unique"
    );

    let start = elf.symbol("__dw_ap_trampoline_template_start");
    let end = elf.symbol("__dw_ap_trampoline_template_end");
    assert_eq!(start.section_index, template.index);
    assert_eq!(end.section_index, template.index);
    assert_eq!(start.value, template.address);
    assert_eq!(end.value - start.value, template.size);

    for (symbol, width) in [
        ("__dw_ap_trampoline_physical_base", 4),
        ("__dw_ap_trampoline_gdt_base", 4),
        ("__dw_ap_trampoline_protected_entry", 4),
        ("__dw_ap_trampoline_long_entry", 4),
        ("__dw_ap_trampoline_long_pointer", 4),
        ("__dw_ap_trampoline_page_table_root", 4),
        ("__dw_ap_trampoline_cpu_index", 4),
        ("__dw_ap_trampoline_local_apic_id", 4),
        ("__dw_ap_trampoline_stack_top", 8),
        ("__dw_ap_trampoline_higher_half_entry", 8),
    ] {
        let patch = elf.symbol(symbol);
        assert_eq!(
            patch.section_index, template.index,
            "{symbol} escaped template"
        );
        assert!(
            patch.value >= start.value && patch.value + width <= end.value,
            "{symbol} patch range exceeds AP trampoline template"
        );
    }

    if let Some(relocation) = elf.relocations_for(template.index).next() {
        panic!(
            "AP trampoline template must be relocation-free; relocation section {} entry {} targets it",
            relocation.section_name, relocation.entry_index
        );
    }
}

fn source(relative: &str) -> String {
    fs::read_to_string(kernel_root().join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn kernel_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn assembly_path() -> PathBuf {
    kernel_root().join("src/arch/x86_64/ap_trampoline.S")
}

fn tool_available(program: &OsStr) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success())
}

struct TemporaryDirectory {
    path: PathBuf,
}

impl TemporaryDirectory {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let path = env::temp_dir().join(format!("{label}-{}-{nonce}", std::process::id()));
        fs::create_dir(&path).expect("create test temporary directory");
        Self { path }
    }
}

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct Elf<'a> {
    bytes: &'a [u8],
    sections: Vec<Section<'a>>,
}

struct Section<'a> {
    index: u16,
    name: &'a str,
    kind: u32,
    address: u64,
    offset: u64,
    size: u64,
    info: u32,
    entry_size: u64,
}

struct Symbol {
    section_index: u16,
    value: u64,
}

struct Relocation<'a> {
    section_name: &'a str,
    entry_index: u64,
}

impl<'a> Elf<'a> {
    fn parse(bytes: &'a [u8]) -> Self {
        assert!(
            bytes.starts_with(b"\x7fELF\x02\x01\x01"),
            "expected ELF64 little-endian object"
        );
        assert_eq!(u16_at(bytes, 58), ELF64_SECTION_HEADER_SIZE as u16);
        let section_count = u16_at(bytes, 60);
        let names_index = u16_at(bytes, 62);
        let section_offset = u64_at(bytes, 40);
        let names = section_at(bytes, section_offset, names_index)
            .expect("section-name string table header");
        let names_offset = u64_at(names, 24) as usize;
        let names_size = u64_at(names, 32) as usize;
        let name_bytes =
            checked_slice(bytes, names_offset, names_size, "section-name string table");

        let sections = (0..section_count)
            .map(|index| {
                let header = section_at(bytes, section_offset, index).expect("section header");
                let name_offset = u32_at(header, 0) as usize;
                Section {
                    index,
                    name: string_at(name_bytes, name_offset, "section name"),
                    kind: u32_at(header, 4),
                    address: u64_at(header, 16),
                    offset: u64_at(header, 24),
                    size: u64_at(header, 32),
                    info: u32_at(header, 44),
                    entry_size: u64_at(header, 56),
                }
            })
            .collect();
        Self { bytes, sections }
    }

    fn section_named(&self, name: &str) -> Option<&Section<'a>> {
        self.sections.iter().find(|section| section.name == name)
    }

    fn sections_named(&self, name: &str) -> impl Iterator<Item = &Section<'a>> {
        self.sections
            .iter()
            .filter(move |section| section.name == name)
    }

    fn symbol(&self, expected: &str) -> Symbol {
        let symbols = self
            .sections
            .iter()
            .find(|section| section.kind == SHT_SYMTAB)
            .expect("ELF symbol table");
        assert_eq!(symbols.entry_size, ELF64_SYMBOL_SIZE as u64);
        let strings_index = section_link(
            self.bytes,
            symbols.offset,
            symbols.size,
            &self.sections,
            symbols.index,
        );
        let strings = &self.sections[strings_index as usize];
        let strings = checked_slice(
            self.bytes,
            strings.offset as usize,
            strings.size as usize,
            "symbol-name string table",
        );
        let symbols_bytes = checked_slice(
            self.bytes,
            symbols.offset as usize,
            symbols.size as usize,
            "symbol table",
        );
        for entry in symbols_bytes.as_chunks::<ELF64_SYMBOL_SIZE>().0 {
            if string_at(strings, u32_at(entry, 0) as usize, "symbol name") == expected {
                return Symbol {
                    section_index: u16_at(entry, 6),
                    value: u64_at(entry, 8),
                };
            }
        }
        panic!("missing AP trampoline symbol `{expected}`");
    }

    fn relocations_for(&self, target_section: u16) -> impl Iterator<Item = Relocation<'a>> + '_ {
        self.sections
            .iter()
            .filter(move |section| {
                matches!(section.kind, SHT_REL | SHT_RELA)
                    && section.info == u32::from(target_section)
            })
            .flat_map(|section| {
                let count = usize::try_from(section.size / section.entry_size)
                    .expect("relocation section entry count");
                (0..count).map(move |entry_index| Relocation {
                    section_name: section.name,
                    entry_index: entry_index as u64,
                })
            })
    }
}

fn section_at(bytes: &[u8], table_offset: u64, index: u16) -> Option<&[u8]> {
    let offset =
        usize::try_from(table_offset).ok()? + usize::from(index) * ELF64_SECTION_HEADER_SIZE;
    bytes.get(offset..offset + ELF64_SECTION_HEADER_SIZE)
}

fn section_link(
    bytes: &[u8],
    offset: u64,
    size: u64,
    sections: &[Section<'_>],
    section_index: u16,
) -> u32 {
    let header_offset = usize::try_from(offset).expect("symbol section offset");
    let header_size = usize::try_from(size).expect("symbol section size");
    let symbol_section = sections
        .get(usize::from(section_index))
        .expect("symbol section index");
    assert_eq!(symbol_section.offset as usize, header_offset);
    assert_eq!(symbol_section.size as usize, header_size);
    let section_header_offset =
        u64_at(bytes, 40) as usize + usize::from(section_index) * ELF64_SECTION_HEADER_SIZE;
    u32_at(
        checked_slice(
            bytes,
            section_header_offset,
            ELF64_SECTION_HEADER_SIZE,
            "symbol section header",
        ),
        40,
    )
}

fn checked_slice<'a>(bytes: &'a [u8], offset: usize, size: usize, label: &str) -> &'a [u8] {
    bytes
        .get(offset..offset.checked_add(size).expect("ELF range overflow"))
        .unwrap_or_else(|| panic!("truncated {label}"))
}

fn string_at<'a>(bytes: &'a [u8], offset: usize, label: &str) -> &'a str {
    let tail = bytes
        .get(offset..)
        .unwrap_or_else(|| panic!("invalid {label} offset"));
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .expect("NUL-terminated ELF string");
    std::str::from_utf8(&tail[..end]).expect("ELF string is UTF-8")
}

fn u16_at(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        checked_slice(bytes, offset, 2, "u16 field")
            .try_into()
            .expect("u16 field"),
    )
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        checked_slice(bytes, offset, 4, "u32 field")
            .try_into()
            .expect("u32 field"),
    )
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        checked_slice(bytes, offset, 8, "u64 field")
            .try_into()
            .expect("u64 field"),
    )
}
