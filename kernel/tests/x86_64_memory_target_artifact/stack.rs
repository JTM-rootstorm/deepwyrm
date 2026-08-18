use super::*;

#[derive(Clone, Debug)]
pub(super) struct StackSize {
    bytes: usize,
    symbol: String,
}

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

pub(super) fn stack_sizes(llvm_readelf: &Path, artifact: &Path) -> Vec<StackSize> {
    let mut command = helper_command(llvm_readelf);
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

#[path = "stack/geometry.rs"]
mod geometry;
#[path = "stack/ist.rs"]
mod ist;
#[path = "stack/production.rs"]
mod production;
#[path = "stack/selector.rs"]
mod selector;

pub(super) use geometry::validate_kernel_stack_artifact_geometry;
pub(super) use production::validate_production_ist_stack_margin;
pub(super) use selector::validate_selector_stack_margin;
