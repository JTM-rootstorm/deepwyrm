use std::fs;
use std::path::PathBuf;

fn source(relative: &str) -> String {
    fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative))
        .unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

fn rust_sources(root: &std::path::Path, files: &mut Vec<PathBuf>) {
    for entry in
        fs::read_dir(root).unwrap_or_else(|error| panic!("read {}: {error}", root.display()))
    {
        let entry = entry.expect("source directory entry");
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, files);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            files.push(path);
        }
    }
}

#[test]
fn scalar_port_assembly_has_one_architecture_module_and_no_string_surface() {
    let io = source("src/arch/x86_64/io_port.rs");
    for instruction in [
        "\"in al, dx\"",
        "\"in ax, dx\"",
        "\"in eax, dx\"",
        "\"out dx, al\"",
        "\"out dx, ax\"",
        "\"out dx, eax\"",
    ] {
        assert_eq!(
            io.match_indices(instruction).count(),
            1,
            "scalar instruction `{instruction}` must have one architecture boundary"
        );
    }
    let lowered = io.to_ascii_lowercase();
    assert!(!lowered.contains("rep ins"));
    assert!(!lowered.contains("rep outs"));
    assert!(!lowered.contains("read_slice"));
    assert!(!lowered.contains("write_slice"));

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let io_path = manifest.join("src/arch/x86_64/io_port.rs");
    let test_exit_path = manifest.join("src/test_support/x86_64.rs");
    let mut files = Vec::new();
    rust_sources(&manifest.join("src"), &mut files);
    for path in files {
        if path == io_path {
            continue;
        }
        let source = fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        for instruction in [
            "\"in al, dx\"",
            "\"in ax, dx\"",
            "\"in eax, dx\"",
            "\"out dx, al\"",
            "\"out dx, ax\"",
            "\"out dx, eax\"",
        ] {
            if path == test_exit_path && instruction == "\"out dx, eax\"" {
                continue;
            }
            assert!(
                !source.contains(instruction),
                "direct scalar port instruction `{instruction}` escaped io_port.rs into {}",
                path.display()
            );
        }
    }
}

#[test]
fn com1_and_pm_timer_consume_the_central_scalar_boundary() {
    let debug = source("src/debug/mod.rs");
    let time = source("src/time/live.rs");

    assert!(debug.contains("io_port::BytePortIo"));
    assert!(debug.contains("io_port::X86PortIo"));
    assert!(!debug.contains("trait PortIo"));
    assert!(!debug.contains("struct X86PortIo"));
    assert!(!debug.contains("\"in al, dx\""));
    assert!(!debug.contains("\"out dx, al\""));

    assert!(time.contains("io_port::ScalarPortIo"));
    assert!(time.contains("io_port::X86PortIo"));
    assert!(!time.contains("\"in eax, dx\""));
}
