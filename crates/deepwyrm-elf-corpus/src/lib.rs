//! One corpus of static user ELF images, and the verdicts the two runtime
//! parsers that read such images must reach on each (root
//! `OS_STACK_ARCHITECTURE_PLAN.md` Z1).
//!
//! Deepwyrm's primordial parser loads the bootstrap image, and Wyrmroot's
//! `wyrmroot-loader` loads every image after it. They are separate code by
//! design (the kernel keeps its own parser), so nothing but a shared corpus
//! keeps them agreeing. Each case is a deterministic mutation of one valid
//! image and names its expected verdict per parser. Where the parsers are
//! meant to disagree, the case names an entry in [`LIMITS`], which says why;
//! a disagreement that names no limit is a defect in one of them. The third
//! runtime parser, the EFI loader's for the kernel image, reads another kind
//! of image and must refuse every case here without panicking.
//!
//! Host-only: the parsers' host tests depend on this crate, nothing ships it.

use deepwyrm_abi::{DW_ABI_FINGERPRINT, DW_ABI_NOTE_NAME, DW_ABI_NOTE_TYPE_FINGERPRINT};

/// A parser's verdict on one image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    Accept,
    Reject,
}

/// A deliberate difference between the two parsers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limit {
    pub name: &'static str,
    pub why: &'static str,
}

/// The parsers' intended differences. Every case whose expected verdicts
/// differ names one of these.
pub const LIMITS: &[Limit] = &[
    Limit {
        name: "abi-note",
        why: "wyrmroot-loader requires the Deepwyrm ABI note with its build's fingerprint; \
              the kernel only bounds a note, and bootstrap checks its own fingerprint \
              against the kernel's before any other syscall (V1)",
    },
    Limit {
        name: "tls",
        why: "wyrmroot-loader accepts a checked PT_TLS for SDK programs; bootstrap has no \
              thread-local storage, so the kernel refuses the header",
    },
];

/// One corpus image.
#[derive(Clone, Debug)]
pub struct Case {
    pub name: &'static str,
    pub bytes: Vec<u8>,
    pub primordial: Verdict,
    pub loader: Verdict,
    /// The [`LIMITS`] entry that explains differing verdicts.
    pub limit: Option<&'static str>,
}

const HEADER: usize = 64;
const PH: usize = 56;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PT_NOTE: u32 = 4;
const PT_PHDR: u32 = 6;
const PT_TLS: u32 = 7;
const PT_GNU_STACK: u32 = 0x6474_e551;
const PT_GNU_RELRO: u32 = 0x6474_e552;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;
const NOTE_OFFSET: usize = 0x3000;
const NOTE_BYTES: usize = 56;
/// Where the base image's headers are, by index.
const TEXT: usize = 0;
const DATA: usize = 1;
const STACK: usize = 2;
const NOTE: usize = 3;

/// The program header fields the corpus writes, in ELF64 order.
#[derive(Clone, Copy)]
struct Ph {
    kind: u32,
    flags: u32,
    offset: u64,
    address: u64,
    file_size: u64,
    memory_size: u64,
    alignment: u64,
}

fn put16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn write_ph(bytes: &mut [u8], index: usize, ph: Ph) {
    let at = HEADER + index * PH;
    put32(bytes, at, ph.kind);
    put32(bytes, at + 4, ph.flags);
    put64(bytes, at + 8, ph.offset);
    put64(bytes, at + 16, ph.address);
    put64(bytes, at + 24, ph.address);
    put64(bytes, at + 32, ph.file_size);
    put64(bytes, at + 40, ph.memory_size);
    put64(bytes, at + 48, ph.alignment);
}

/// The image every case mutates: two page-aligned PT_LOADs (R+X text at
/// 0x401000, RW data at 0x402000), a non-executable PT_GNU_STACK and the
/// ABI note, entry at the start of text.
#[must_use]
pub fn base_image() -> Vec<u8> {
    let mut bytes = vec![0_u8; NOTE_OFFSET + NOTE_BYTES];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2; // ELFCLASS64
    bytes[5] = 1; // little-endian
    bytes[6] = 1; // EV_CURRENT
    put16(&mut bytes, 16, 2); // ET_EXEC
    put16(&mut bytes, 18, 62); // EM_X86_64
    put32(&mut bytes, 20, 1);
    put64(&mut bytes, 24, 0x401000);
    put64(&mut bytes, 32, HEADER as u64);
    put16(&mut bytes, 52, HEADER as u16);
    put16(&mut bytes, 54, PH as u16);
    put16(&mut bytes, 56, 4);
    write_ph(
        &mut bytes,
        TEXT,
        Ph {
            kind: PT_LOAD,
            flags: PF_R | PF_X,
            offset: 0x1000,
            address: 0x401000,
            file_size: 0x100,
            memory_size: 0x100,
            alignment: 0x1000,
        },
    );
    write_ph(
        &mut bytes,
        DATA,
        Ph {
            kind: PT_LOAD,
            flags: PF_R | PF_W,
            offset: 0x2000,
            address: 0x402000,
            file_size: 0x80,
            memory_size: 0x1000,
            alignment: 0x1000,
        },
    );
    write_ph(
        &mut bytes,
        STACK,
        Ph {
            kind: PT_GNU_STACK,
            flags: PF_R | PF_W,
            offset: 0,
            address: 0,
            file_size: 0,
            memory_size: 0,
            alignment: 16,
        },
    );
    write_ph(
        &mut bytes,
        NOTE,
        Ph {
            kind: PT_NOTE,
            flags: PF_R,
            offset: NOTE_OFFSET as u64,
            address: 0,
            file_size: NOTE_BYTES as u64,
            memory_size: NOTE_BYTES as u64,
            alignment: 4,
        },
    );
    let note = &mut bytes[NOTE_OFFSET..];
    put32(note, 0, DW_ABI_NOTE_NAME.len() as u32);
    put32(note, 4, DW_ABI_FINGERPRINT.len() as u32);
    put32(note, 8, DW_ABI_NOTE_TYPE_FINGERPRINT);
    note[12..12 + DW_ABI_NOTE_NAME.len()].copy_from_slice(&DW_ABI_NOTE_NAME);
    note[24..56].copy_from_slice(&DW_ABI_FINGERPRINT);
    bytes
}

/// A case both parsers must reach the same verdict on.
fn both(name: &'static str, verdict: Verdict, mutate: impl FnOnce(&mut Vec<u8>)) -> Case {
    let mut bytes = base_image();
    mutate(&mut bytes);
    Case {
        name,
        bytes,
        primordial: verdict,
        loader: verdict,
        limit: None,
    }
}

/// A case the parsers decide differently, for the reason `limit` names.
fn differ(
    name: &'static str,
    primordial: Verdict,
    loader: Verdict,
    limit: &'static str,
    mutate: impl FnOnce(&mut Vec<u8>),
) -> Case {
    let mut case = both(name, primordial, mutate);
    case.loader = loader;
    case.limit = Some(limit);
    case
}

/// Drops the note header: four headers become three.
fn without_note(bytes: &mut [u8]) {
    put16(bytes, 56, 3);
    bytes[HEADER + NOTE * PH..HEADER + (NOTE + 1) * PH].fill(0);
}

/// Every corpus case, in a fixed order.
#[must_use]
pub fn cases() -> Vec<Case> {
    use Verdict::{Accept, Reject};
    let field = |index: usize, offset: usize| HEADER + index * PH + offset;
    let mut cases = vec![
        both("base", Accept, |_| {}),
        // Identification and header.
        both("empty", Reject, |bytes| bytes.clear()),
        both("truncated-header", Reject, |bytes| bytes.truncate(40)),
        both("truncated-program-headers", Reject, |bytes| {
            bytes.truncate(HEADER + PH + 8)
        }),
        both("bad-magic", Reject, |bytes| bytes[1] = b'X'),
        both("class-32", Reject, |bytes| bytes[4] = 1),
        both("big-endian", Reject, |bytes| bytes[5] = 2),
        both("ident-version-0", Reject, |bytes| bytes[6] = 0),
        both("type-dyn", Reject, |bytes| put16(bytes, 16, 3)),
        both("type-rel", Reject, |bytes| put16(bytes, 16, 1)),
        both("machine-i386", Reject, |bytes| put16(bytes, 18, 3)),
        both("version-0", Reject, |bytes| put32(bytes, 20, 0)),
        both("header-size-wrong", Reject, |bytes| put16(bytes, 52, 63)),
        both("program-header-size-wrong", Reject, |bytes| {
            put16(bytes, 54, 55)
        }),
        both("no-program-headers", Reject, |bytes| put16(bytes, 56, 0)),
        both("seventeen-program-headers", Reject, |bytes| {
            put16(bytes, 56, 17)
        }),
        both("program-headers-past-file", Reject, |bytes| {
            put64(bytes, 32, 0x3020)
        }),
        both("program-header-offset-overflows", Reject, |bytes| {
            put64(bytes, 32, u64::MAX - 8)
        }),
        // Entry point.
        both("entry-zero", Reject, |bytes| put64(bytes, 24, 0)),
        both("entry-in-data", Reject, |bytes| put64(bytes, 24, 0x402000)),
        both("entry-past-text", Reject, |bytes| {
            put64(bytes, 24, 0x401100)
        }),
        // Load segments.
        both("no-load-segment", Reject, |bytes| {
            put32(bytes, field(TEXT, 0), PT_GNU_RELRO);
            put32(bytes, field(DATA, 0), PT_GNU_RELRO);
        }),
        both("load-file-range-past-file", Reject, |bytes| {
            put64(bytes, field(TEXT, 32), 0x4000)
        }),
        both("load-file-range-overflows", Reject, |bytes| {
            put64(bytes, field(TEXT, 8), u64::MAX - 0x10)
        }),
        both("load-file-larger-than-memory", Reject, |bytes| {
            put64(bytes, field(DATA, 32), 0x2000);
            put64(bytes, field(DATA, 40), 0x80);
        }),
        both("load-writable-executable", Reject, |bytes| {
            put32(bytes, field(TEXT, 4), PF_R | PF_W | PF_X)
        }),
        both("load-unknown-flags", Reject, |bytes| {
            put32(bytes, field(DATA, 4), PF_R | PF_W | 0x100)
        }),
        both("load-address-in-kernel-half", Reject, |bytes| {
            put64(bytes, field(DATA, 16), 0xffff_8000_0000_2000);
            put64(bytes, field(DATA, 24), 0xffff_8000_0000_2000);
        }),
        both("load-virtual-range-overflows", Reject, |bytes| {
            put64(bytes, field(DATA, 40), u64::MAX - 0x1000)
        }),
        both("load-overlapping-pages", Reject, |bytes| {
            put64(bytes, field(DATA, 16), 0x401000);
            put64(bytes, field(DATA, 24), 0x401000);
        }),
        both("load-offset-and-address-misaligned", Reject, |bytes| {
            put64(bytes, field(DATA, 8), 0x2010)
        }),
        both("load-alignment-not-power-of-two", Reject, |bytes| {
            put64(bytes, field(DATA, 48), 0x3000)
        }),
        both("load-memory-past-user-space", Reject, |bytes| {
            put64(bytes, field(DATA, 40), 0x7fff_ffbf_f000)
        }),
        // Other headers.
        both("executable-stack", Reject, |bytes| {
            put32(bytes, field(STACK, 4), PF_R | PF_W | PF_X)
        }),
        both("interpreter", Reject, |bytes| {
            put32(bytes, field(STACK, 0), PT_INTERP)
        }),
        both("dynamic", Reject, |bytes| {
            put32(bytes, field(STACK, 0), PT_DYNAMIC)
        }),
        both("unknown-program-header", Reject, |bytes| {
            put32(bytes, field(STACK, 0), 0x7000_0001)
        }),
        both("second-note-header", Reject, |bytes| {
            put32(bytes, field(STACK, 0), PT_NOTE);
            put64(bytes, field(STACK, 8), NOTE_OFFSET as u64);
            put64(bytes, field(STACK, 32), NOTE_BYTES as u64);
            put64(bytes, field(STACK, 40), NOTE_BYTES as u64);
            put64(bytes, field(STACK, 48), 4);
        }),
        both("note-past-file", Reject, |bytes| {
            put64(bytes, field(NOTE, 8), NOTE_OFFSET as u64 + 8)
        }),
        both("note-range-overflows", Reject, |bytes| {
            put64(bytes, field(NOTE, 8), u64::MAX - 8)
        }),
        // Deliberate differences.
        differ("no-note", Accept, Reject, "abi-note", |bytes| {
            without_note(bytes)
        }),
        differ("stale-fingerprint", Accept, Reject, "abi-note", |bytes| {
            bytes[NOTE_OFFSET + 24] ^= 1
        }),
        differ(
            "note-of-another-owner",
            Accept,
            Reject,
            "abi-note",
            |bytes| bytes[NOTE_OFFSET + 12] = b'd',
        ),
        differ("tls-template", Reject, Accept, "tls", |bytes| {
            put32(bytes, field(STACK, 0), PT_TLS);
            put32(bytes, field(STACK, 4), PF_R);
            put64(bytes, field(STACK, 8), 0x2000);
            put64(bytes, field(STACK, 16), 0x402000);
            put64(bytes, field(STACK, 24), 0x402000);
            put64(bytes, field(STACK, 32), 0x40);
            put64(bytes, field(STACK, 40), 0x80);
            put64(bytes, field(STACK, 48), 8);
        }),
    ];
    // A program-header table that names itself, both where the text segment
    // maps it and where it does not.
    cases.push(both("phdr-unmapped", Accept, |bytes| {
        put32(bytes, field(STACK, 0), PT_PHDR);
        put32(bytes, field(STACK, 4), PF_R);
        put64(bytes, field(STACK, 8), HEADER as u64);
        put64(bytes, field(STACK, 16), 0x400040);
        put64(bytes, field(STACK, 24), 0x400040);
        put64(bytes, field(STACK, 32), (4 * PH) as u64);
        put64(bytes, field(STACK, 40), (4 * PH) as u64);
        put64(bytes, field(STACK, 48), 8);
    }));
    cases
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_names_are_unique_and_differences_name_a_limit() {
        let cases = cases();
        for (index, case) in cases.iter().enumerate() {
            assert!(
                cases[..index].iter().all(|other| other.name != case.name),
                "{} repeats",
                case.name
            );
            assert_eq!(
                case.limit.is_some(),
                case.primordial != case.loader,
                "{}: a difference must name a limit, and only a difference may",
                case.name
            );
            if let Some(limit) = case.limit {
                assert!(
                    LIMITS.iter().any(|known| known.name == limit),
                    "{}: unknown limit {limit}",
                    case.name
                );
            }
        }
        for limit in LIMITS {
            assert!(
                cases.iter().any(|case| case.limit == Some(limit.name)),
                "limit {} has no case",
                limit.name
            );
        }
    }

    #[test]
    fn the_base_image_is_deterministic_and_carries_one_note() {
        let base = base_image();
        assert_eq!(base, base_image());
        assert_eq!(&base[NOTE_OFFSET + 24..], &DW_ABI_FINGERPRINT);
    }
}
