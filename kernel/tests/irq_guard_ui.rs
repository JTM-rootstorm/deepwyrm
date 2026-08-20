use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[test]
fn irq_guard_is_neither_send_nor_sync() {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let rustc = env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let output_dir = env::temp_dir().join(format!("deepwyrm-irq-guard-ui-{}", std::process::id()));
    fs::create_dir_all(&output_dir).unwrap();
    for (fixture, trait_name) in [("irq_guard_send.rs", "Send"), ("irq_guard_sync.rs", "Sync")] {
        let output = Command::new(&rustc)
            .args([
                "--edition=2024",
                "--crate-type=lib",
                "--emit=metadata",
                "--deny=unsafe-code",
            ])
            .arg("--out-dir")
            .arg(&output_dir)
            .arg(manifest.join("tests/ui").join(fixture))
            .output()
            .unwrap();
        assert!(!output.status.success(), "{fixture} unexpectedly compiled");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(trait_name),
            "{fixture} did not fail on {trait_name}: {stderr}"
        );
        assert!(
            stderr.contains("*mut ()"),
            "{fixture} did not cite the CPU-local marker: {stderr}"
        );
    }
    fs::remove_dir_all(output_dir).unwrap();
}
