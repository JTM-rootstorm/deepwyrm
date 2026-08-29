//! Central x86 scalar I/O-port instruction boundary.
//!
//! Callers own every authorization and range check. This module exposes only
//! one scalar instruction per operation and deliberately has no string/REP
//! surface.

/// Byte-only port access used by early COM1 diagnostics.
pub(crate) trait BytePortIo {
    fn read_u8(&mut self, port: u16) -> u8;
    fn write_u8(&mut self, port: u16, value: u8);
}

/// Scalar port access used after a DeviceResource has authorized one exact
/// operation.
pub(crate) trait ScalarPortIo: BytePortIo {
    fn read_u16(&mut self, port: u16) -> u16;
    fn read_u32(&mut self, port: u16) -> u32;
    fn write_u16(&mut self, port: u16, value: u16);
    fn write_u32(&mut self, port: u16, value: u32);
}

/// Direct x86 port I/O for the freestanding kernel target.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) struct X86PortIo;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl BytePortIo for X86PortIo {
    #[allow(
        unsafe_code,
        reason = "central x86 scalar byte input instruction boundary"
    )]
    fn read_u8(&mut self, port: u16) -> u8 {
        let value: u8;
        // SAFETY: the caller has already authorized and range-checked this
        // exact scalar port operation. The freestanding kernel owns execution
        // at CPL0 and this block performs exactly one non-string instruction.
        unsafe {
            core::arch::asm!(
                "in al, dx",
                in("dx") port,
                out("al") value,
                options(nomem, nostack, preserves_flags),
            );
        }
        value
    }

    #[allow(
        unsafe_code,
        reason = "central x86 scalar byte output instruction boundary"
    )]
    fn write_u8(&mut self, port: u16, value: u8) {
        // SAFETY: see `read_u8`; this performs exactly one scalar output.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") value,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl ScalarPortIo for X86PortIo {
    #[allow(
        unsafe_code,
        reason = "central x86 scalar word input instruction boundary"
    )]
    fn read_u16(&mut self, port: u16) -> u16 {
        let value: u16;
        // SAFETY: see `BytePortIo::read_u8`; this performs one word input.
        unsafe {
            core::arch::asm!(
                "in ax, dx",
                in("dx") port,
                out("ax") value,
                options(nomem, nostack, preserves_flags),
            );
        }
        value
    }

    #[allow(
        unsafe_code,
        reason = "central x86 scalar doubleword input instruction boundary"
    )]
    fn read_u32(&mut self, port: u16) -> u32 {
        let value: u32;
        // SAFETY: see `BytePortIo::read_u8`; this performs one doubleword input.
        unsafe {
            core::arch::asm!(
                "in eax, dx",
                in("dx") port,
                out("eax") value,
                options(nomem, nostack, preserves_flags),
            );
        }
        value
    }

    #[allow(
        unsafe_code,
        reason = "central x86 scalar word output instruction boundary"
    )]
    fn write_u16(&mut self, port: u16, value: u16) {
        // SAFETY: see `BytePortIo::read_u8`; this performs one word output.
        unsafe {
            core::arch::asm!(
                "out dx, ax",
                in("dx") port,
                in("ax") value,
                options(nomem, nostack, preserves_flags),
            );
        }
    }

    #[allow(
        unsafe_code,
        reason = "central x86 scalar doubleword output instruction boundary"
    )]
    fn write_u32(&mut self, port: u16, value: u32) {
        // SAFETY: see `BytePortIo::read_u8`; this performs one doubleword output.
        unsafe {
            core::arch::asm!(
                "out dx, eax",
                in("dx") port,
                in("eax") value,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
}
