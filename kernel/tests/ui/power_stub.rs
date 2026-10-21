// Minimal crate context for the compile-fail fixtures that build
// `arch/x86_64/power.rs` as a standalone crate (design §11.2.6). The real
// `soft_off_then_halt` signature is checked against the runtime-authority
// handle and the guard-free token; the ACPI, port and debug items it calls
// are stand-ins with the same shapes.

include!("runtime_authority_stub.rs");

mod arch {
    pub(crate) mod x86_64 {
        pub(crate) mod syscall {
            pub(crate) use crate::GuardFree;
        }
        pub(crate) mod io_port {
            pub(crate) struct X86PortIo;
        }
        pub(crate) mod acpi {
            pub(crate) mod sleep {
                pub(crate) struct S5SoftOff;
                pub(crate) fn authorized_soft_off() -> Option<S5SoftOff> {
                    None
                }
                pub(crate) fn request_soft_off(
                    _port_io: &mut crate::arch::x86_64::io_port::X86PortIo,
                    _command: S5SoftOff,
                ) {
                }
            }
        }
    }
}

mod debug {
    pub(crate) enum DiagnosticLevel {
        Warn,
    }
    pub(crate) fn emit_early_record(
        _level: DiagnosticLevel,
        _subsystem: &str,
        _message: &str,
    ) -> Result<(), ()> {
        Ok(())
    }
}

#[path = "../../src/arch/x86_64/power.rs"]
mod power;
