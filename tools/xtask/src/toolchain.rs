use super::*;

pub(super) fn print_toolchain_diagnostics() -> io::Result<u8> {
    let mut stdout = io::stdout().lock();
    writeln!(stdout, "Deepwyrm host tool availability")?;
    writeln!(
        stdout,
        "This report does not assert toolchain adoption or pinning."
    )?;
    for (name, program) in [
        ("cargo", "cargo"),
        ("rustc", "rustc"),
        ("clang", "clang"),
        ("clang++", "clang++"),
        ("ld.lld", "ld.lld"),
        ("llvm-ar", "llvm-ar"),
        ("llvm-readelf", "llvm-readelf"),
        ("llvm-objdump", "llvm-objdump"),
        ("llvm-objcopy", "llvm-objcopy"),
        ("llvm-symbolizer", "llvm-symbolizer"),
        ("llvm-nm", "llvm-nm"),
        ("gdb", "gdb"),
    ] {
        write!(stdout, "{name}: ")?;
        match Command::new(program).arg("--version").output() {
            Ok(output) if output.status.success() => {
                let version_output = String::from_utf8_lossy(&output.stdout);
                writeln!(
                    stdout,
                    "{}",
                    version_output.lines().next().unwrap_or("available")
                )?;
            }
            Ok(output) => writeln!(stdout, "unavailable (exit {})", output.status)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => writeln!(stdout, "not found")?,
            Err(error) => writeln!(stdout, "unavailable ({error})")?,
        }
    }
    Ok(0)
}
