//! Early COM1 diagnostics and panic records.
//!
//! This module is intentionally a kernel-only development facility. It does
//! not define a syscall, userspace protocol, logger, or test-completion ABI.
//! The only architecture-specific operation is the x86 port-I/O adapter;
//! formatting, bounded polling, and record construction are host-testable.

#![cfg_attr(not(any(test, target_os = "none")), allow(dead_code))]

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicBool, Ordering};

#[cfg(all(target_os = "none", any(target_arch = "x86", target_arch = "x86_64")))]
use core::panic::PanicInfo;

#[cfg(all(
    not(feature = "test-support"),
    target_os = "none",
    any(target_arch = "x86", target_arch = "x86_64")
))]
use core::arch::asm;

/// The reference-machine COM1 base port.
const COM1_BASE: u16 = 0x03f8;

const DATA: u16 = 0;
const INTERRUPT_ENABLE: u16 = 1;
const FIFO_CONTROL: u16 = 2;
const LINE_CONTROL: u16 = 3;
const MODEM_CONTROL: u16 = 4;
const LINE_STATUS: u16 = 5;
const DIVISOR_LOW: u16 = 0;
const DIVISOR_HIGH: u16 = 1;
const LINE_STATUS_THR_EMPTY: u8 = 1 << 5;
#[cfg(any(test, feature = "test-support"))]
const LINE_STATUS_TRANSMITTER_EMPTY: u8 = 1 << 6;
const LINE_CONTROL_DLAB: u8 = 1 << 7;
const LINE_CONTROL_8N1: u8 = 0x03;
const FIFO_ENABLE_CLEAR_14: u8 = 0xc7;
const MODEM_DTR_RTS_OUT2: u8 = 0x0b;
const DEFAULT_POLL_LIMIT: u32 = 4_096;
#[cfg_attr(
    all(feature = "test-support", target_os = "none"),
    allow(
        dead_code,
        reason = "production diagnostics are omitted from test images"
    )
)]
const MAX_SUBSYSTEM_BYTES: usize = 32;
#[cfg_attr(
    all(feature = "test-support", target_os = "none"),
    allow(
        dead_code,
        reason = "production diagnostics are omitted from test images"
    )
)]
const MAX_DIAGNOSTIC_MESSAGE_BYTES: usize = 192;
const MAX_PANIC_REASON_BYTES: usize = 192;
const MAX_BACKTRACE_FRAMES: usize = 16;
#[cfg(any(test, feature = "test-support"))]
const MAX_RAW_RECORD_BYTES: usize = 64;

/// Minimal byte-port interface used by the early serial writer.
///
/// The trait keeps formatting and polling testable without permitting tests to
/// execute privileged port I/O.
trait PortIo {
    fn read_u8(&mut self, port: u16) -> u8;
    fn write_u8(&mut self, port: u16, value: u8);
}

/// A bounded early COM1 writer.
struct Com1<P> {
    io: P,
    poll_limit: u32,
}

struct PanicReasonBuffer {
    bytes: [u8; MAX_PANIC_REASON_BYTES],
    length: usize,
}

impl PanicReasonBuffer {
    const fn new() -> Self {
        Self {
            bytes: [0; MAX_PANIC_REASON_BYTES],
            length: 0,
        }
    }

    fn as_str(&self) -> &str {
        // `write_str` copies only complete UTF-8 scalar values.
        core::str::from_utf8(&self.bytes[..self.length]).unwrap_or("panic")
    }
}

impl Write for PanicReasonBuffer {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        for character in value.chars() {
            let mut encoded = [0; 4];
            let encoded = character.encode_utf8(&mut encoded).as_bytes();
            let remaining = MAX_PANIC_REASON_BYTES.saturating_sub(self.length);
            if encoded.len() > remaining {
                break;
            }
            self.bytes[self.length..self.length + encoded.len()].copy_from_slice(encoded);
            self.length += encoded.len();
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SerialError {
    Busy,
    TransmitTimeout,
    #[cfg(any(test, feature = "test-support"))]
    TransmitDrainTimeout,
    #[cfg(any(test, feature = "test-support"))]
    RecordTooLong,
}

impl<P: PortIo> Com1<P> {
    pub const fn new(io: P) -> Self {
        Self::with_poll_limit(io, DEFAULT_POLL_LIMIT)
    }

    pub const fn with_poll_limit(io: P, poll_limit: u32) -> Self {
        Self { io, poll_limit }
    }

    /// Programs COM1 for 115200 baud, 8N1, polling-only transmit.
    pub fn initialize(&mut self) {
        self.io.write_u8(COM1_BASE + INTERRUPT_ENABLE, 0);
        self.io
            .write_u8(COM1_BASE + LINE_CONTROL, LINE_CONTROL_DLAB);
        self.io.write_u8(COM1_BASE + DIVISOR_LOW, 1);
        self.io.write_u8(COM1_BASE + DIVISOR_HIGH, 0);
        self.io.write_u8(COM1_BASE + LINE_CONTROL, LINE_CONTROL_8N1);
        self.io
            .write_u8(COM1_BASE + FIFO_CONTROL, FIFO_ENABLE_CLEAR_14);
        self.io
            .write_u8(COM1_BASE + MODEM_CONTROL, MODEM_DTR_RTS_OUT2);
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), SerialError> {
        for &byte in bytes {
            if byte == b'\n' {
                self.write_hardware_byte(b'\r')?;
            }
            self.write_hardware_byte(byte)?;
        }
        Ok(())
    }

    /// Writes protocol bytes exactly as supplied, including any line endings.
    ///
    /// This is for fixed machine records such as test completion markers;
    /// human diagnostics should use [`Self::write_bytes`] for CRLF output.
    #[cfg(any(test, feature = "test-support"))]
    pub fn write_raw_bytes(&mut self, bytes: &[u8]) -> Result<(), SerialError> {
        for &byte in bytes {
            self.write_hardware_byte(byte)?;
        }
        Ok(())
    }

    fn write_hardware_byte(&mut self, byte: u8) -> Result<(), SerialError> {
        for _ in 0..self.poll_limit {
            if self.io.read_u8(COM1_BASE + LINE_STATUS) & LINE_STATUS_THR_EMPTY != 0 {
                self.io.write_u8(COM1_BASE + DATA, byte);
                return Ok(());
            }
        }
        Err(SerialError::TransmitTimeout)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn wait_until_transmitter_drained(&mut self) -> Result<(), SerialError> {
        for _ in 0..self.poll_limit {
            if self.io.read_u8(COM1_BASE + LINE_STATUS) & LINE_STATUS_TRANSMITTER_EMPTY != 0 {
                return Ok(());
            }
        }
        Err(SerialError::TransmitDrainTimeout)
    }
}

impl<P: PortIo> Write for Com1<P> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.write_bytes(value.as_bytes()).map_err(|_| fmt::Error)
    }
}

/// Severity used in the stable, kernel-only serial prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "the bounded diagnostic vocabulary is established before all call sites exist"
)]
pub(crate) enum DiagnosticLevel {
    Info,
    Warn,
    Error,
    Panic,
}

impl DiagnosticLevel {
    #[cfg_attr(
        all(feature = "test-support", target_os = "none"),
        allow(
            dead_code,
            reason = "production diagnostics are omitted from test images"
        )
    )]
    const fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Panic => "PANIC",
        }
    }
}

/// A bounded, allocation-free kernel panic record.
pub(crate) struct PanicRecord<'a> {
    pub(crate) reason: &'a str,
    pub(crate) cpu_id: Option<u32>,
    pub(crate) instruction_pointer: Option<u64>,
    pub(crate) fault_address: Option<u64>,
    pub(crate) backtrace_frames: &'a [u64],
}

static EARLY_OUTPUT_ACTIVE: AtomicBool = AtomicBool::new(false);

struct OutputGuard;

impl OutputGuard {
    fn acquire() -> Option<Self> {
        EARLY_OUTPUT_ACTIVE
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for OutputGuard {
    fn drop(&mut self) {
        EARLY_OUTPUT_ACTIVE.store(false, Ordering::Release);
    }
}

/// Emits one bounded structured diagnostic record.
///
/// A concurrent or recursive writer returns immediately rather than spinning
/// in an already-failing path. Serial timeouts likewise stop the record rather
/// than blocking panic handling indefinitely.
#[cfg_attr(
    all(feature = "test-support", target_os = "none"),
    allow(
        dead_code,
        reason = "production diagnostics are omitted from test images"
    )
)]
fn emit_record<P: PortIo>(
    serial: &mut Com1<P>,
    level: DiagnosticLevel,
    subsystem: &str,
    message: &str,
) -> Result<(), SerialError> {
    let _guard = OutputGuard::acquire().ok_or(SerialError::Busy)?;
    write!(serial, "[DW0][{}][", level.label()).map_err(|_| SerialError::TransmitTimeout)?;
    write_limited(serial, subsystem.as_bytes(), MAX_SUBSYSTEM_BYTES)?;
    serial
        .write_str("] ")
        .map_err(|_| SerialError::TransmitTimeout)?;
    write_limited(serial, message.as_bytes(), MAX_DIAGNOSTIC_MESSAGE_BYTES)?;
    serial
        .write_str("\n")
        .map_err(|_| SerialError::TransmitTimeout)
}

/// Emits one bounded panic record. Address-bearing fields are redacted outside
/// debug builds so a release serial log cannot disclose kernel layout.
#[cfg_attr(
    test,
    allow(dead_code, reason = "target wrapper exercises the renderer indirectly")
)]
fn emit_panic_record<P: PortIo>(
    serial: &mut Com1<P>,
    record: &PanicRecord<'_>,
) -> Result<(), SerialError> {
    let _guard = OutputGuard::acquire().ok_or(SerialError::Busy)?;
    render_panic_record(serial, record, cfg!(debug_assertions))
}

fn render_panic_record<P: PortIo>(
    serial: &mut Com1<P>,
    record: &PanicRecord<'_>,
    expose_addresses: bool,
) -> Result<(), SerialError> {
    serial
        .write_str("[DW0][PANIC][kernel] reason=")
        .map_err(|_| SerialError::TransmitTimeout)?;
    let reason = if expose_addresses {
        record.reason
    } else {
        "redacted"
    };
    write_limited(serial, reason.as_bytes(), MAX_PANIC_REASON_BYTES)?;
    serial
        .write_str("\n[DW0][PANIC][kernel] cpu=")
        .map_err(|_| SerialError::TransmitTimeout)?;
    write_optional_u32(serial, record.cpu_id)?;
    serial
        .write_str(" ip=")
        .map_err(|_| SerialError::TransmitTimeout)?;
    write_address(serial, record.instruction_pointer, expose_addresses)?;
    serial
        .write_str(" fault=")
        .map_err(|_| SerialError::TransmitTimeout)?;
    write_address(serial, record.fault_address, expose_addresses)?;
    serial
        .write_str("\n[DW0][PANIC][kernel] frames=")
        .map_err(|_| SerialError::TransmitTimeout)?;

    for (count, &frame) in record
        .backtrace_frames
        .iter()
        .take(MAX_BACKTRACE_FRAMES)
        .enumerate()
    {
        if count != 0 {
            serial
                .write_str(",")
                .map_err(|_| SerialError::TransmitTimeout)?;
        }
        write_address(serial, Some(frame), expose_addresses)?;
    }
    if record.backtrace_frames.len() > MAX_BACKTRACE_FRAMES {
        serial
            .write_str(",...")
            .map_err(|_| SerialError::TransmitTimeout)?;
    }
    serial
        .write_str("\n")
        .map_err(|_| SerialError::TransmitTimeout)
}

fn write_limited<P: PortIo>(
    serial: &mut Com1<P>,
    bytes: &[u8],
    limit: usize,
) -> Result<(), SerialError> {
    let count = bytes.len().min(limit);
    serial
        .write_bytes(&bytes[..count])
        .map_err(|_| SerialError::TransmitTimeout)?;
    if bytes.len() > limit {
        serial
            .write_str("...")
            .map_err(|_| SerialError::TransmitTimeout)?;
    }
    Ok(())
}

fn write_optional_u32<P: PortIo>(
    serial: &mut Com1<P>,
    value: Option<u32>,
) -> Result<(), SerialError> {
    match value {
        Some(value) => write!(serial, "{value}").map_err(|_| SerialError::TransmitTimeout),
        None => serial
            .write_str("unavailable")
            .map_err(|_| SerialError::TransmitTimeout),
    }
}

fn write_address<P: PortIo>(
    serial: &mut Com1<P>,
    value: Option<u64>,
    expose: bool,
) -> Result<(), SerialError> {
    match (value, expose) {
        (Some(value), true) => {
            write!(serial, "0x{value:016x}").map_err(|_| SerialError::TransmitTimeout)
        }
        (Some(_), false) => serial
            .write_str("redacted")
            .map_err(|_| SerialError::TransmitTimeout),
        (None, _) => serial
            .write_str("unavailable")
            .map_err(|_| SerialError::TransmitTimeout),
    }
}

/// Direct x86 port I/O for the freestanding kernel target.
#[cfg(all(target_os = "none", any(target_arch = "x86", target_arch = "x86_64")))]
struct X86PortIo;

#[cfg(all(target_os = "none", any(target_arch = "x86", target_arch = "x86_64")))]
impl PortIo for X86PortIo {
    #[allow(
        unsafe_code,
        reason = "x86 COM1 port I/O boundary for freestanding kernel diagnostics"
    )]
    fn read_u8(&mut self, port: u16) -> u8 {
        let value: u8;
        // SAFETY: this is the sole x86 I/O-port boundary. Callers use only
        // COM1's fixed legacy ports on the freestanding x86 kernel target.
        unsafe {
            core::arch::asm!(
                "in al, dx",
                in("dx") port,
                out("al") value,
                options(nomem, nostack, preserves_flags)
            );
        }
        value
    }

    #[allow(
        unsafe_code,
        reason = "x86 COM1 port I/O boundary for freestanding kernel diagnostics"
    )]
    fn write_u8(&mut self, port: u16, value: u8) {
        // SAFETY: this is the sole x86 I/O-port boundary. Callers use only
        // COM1's fixed legacy ports on the freestanding x86 kernel target.
        unsafe {
            core::arch::asm!(
                "out dx, al",
                in("dx") port,
                in("al") value,
                options(nomem, nostack, preserves_flags)
            );
        }
    }
}

/// Initializes the kernel's COM1 diagnostic writer.
#[cfg(all(target_os = "none", any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) fn initialize_early_com1() {
    let mut serial = Com1::new(X86PortIo);
    serial.initialize();
}

/// Emits a structured record through the kernel's initialized COM1 path.
#[cfg(all(
    not(feature = "test-support"),
    target_os = "none",
    any(target_arch = "x86", target_arch = "x86_64")
))]
pub(crate) fn emit_early_record(
    level: DiagnosticLevel,
    subsystem: &str,
    message: &str,
) -> Result<(), SerialError> {
    let mut serial = Com1::new(X86PortIo);
    emit_record(&mut serial, level, subsystem, message)
}

/// Emits a panic record through the kernel's COM1 diagnostic writer.
#[cfg(all(target_os = "none", any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) fn emit_early_panic_record(record: &PanicRecord<'_>) -> Result<(), SerialError> {
    let mut serial = Com1::new(X86PortIo);
    emit_panic_record(&mut serial, record)
}

/// Converts the core panic payload into a bounded early serial record, then
/// permanently stops the current CPU.
///
/// The generic panic path has no trustworthy architectural exception frame,
/// so CPU, instruction pointer, fault address, and backtrace are explicitly
/// reported as unavailable. Exception handling may provide richer fields via
/// [`emit_early_panic_record`] once that boundary exists.
#[cfg(all(target_os = "none", any(target_arch = "x86", target_arch = "x86_64")))]
pub(crate) fn handle_early_panic(info: &PanicInfo<'_>) -> ! {
    let mut reason = PanicReasonBuffer::new();
    let _ = write!(&mut reason, "{}", info.message());
    let record = PanicRecord {
        reason: reason.as_str(),
        cpu_id: None,
        instruction_pointer: None,
        fault_address: None,
        backtrace_frames: &[],
    };

    initialize_early_com1();
    let _ = emit_early_panic_record(&record);

    // The test-support completion transport is deliberately only provided for
    // the canonical x86_64 guest target. Other freestanding x86 builds retain
    // the production halt path below.
    #[cfg(all(feature = "test-support", target_arch = "x86_64"))]
    {
        crate::test_support::complete_panic(0x5041_4E49);
    }

    #[cfg(not(all(feature = "test-support", target_arch = "x86_64")))]
    halt_after_early_panic()
}

/// Terminal x86 panic path when no higher-level scheduler or recovery policy
/// exists yet.
#[cfg(all(
    not(feature = "test-support"),
    target_os = "none",
    any(target_arch = "x86", target_arch = "x86_64")
))]
#[allow(
    unsafe_code,
    reason = "x86 terminal cli/hlt boundary for freestanding kernel panic handling"
)]
fn halt_after_early_panic() -> ! {
    loop {
        // SAFETY: after an unrecoverable kernel panic this CPU must not resume
        // normal execution; disabling maskable interrupts prevents a wakeup.
        unsafe {
            asm!("cli; hlt", options(nomem, nostack));
        }
    }
}

/// Writes one bounded, byte-exact machine record through COM1.
///
/// This deliberately bypasses the CRLF formatting used for human diagnostics.
/// It is crate-private so only the kernel's explicit test-support seam can use
/// it; it does not expose a general hardware-port operation to callers.
#[cfg(all(
    feature = "test-support",
    target_os = "none",
    any(target_arch = "x86", target_arch = "x86_64")
))]
pub(crate) fn emit_early_raw_record(record: &[u8]) -> Result<(), SerialError> {
    let _guard = OutputGuard::acquire().ok_or(SerialError::Busy)?;
    let mut serial = Com1::new(X86PortIo);
    write_bounded_raw_record(&mut serial, record)
}

#[cfg(any(test, feature = "test-support"))]
fn write_bounded_raw_record<P: PortIo>(
    serial: &mut Com1<P>,
    record: &[u8],
) -> Result<(), SerialError> {
    if record.len() > MAX_RAW_RECORD_BYTES {
        return Err(SerialError::RecordTooLong);
    }
    serial.write_raw_bytes(record)?;
    if !record.is_empty() {
        serial.wait_until_transmitter_drained()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
