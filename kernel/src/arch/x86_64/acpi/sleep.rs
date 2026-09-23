//! Bounded, snapshot-based discovery of the ACPI S5 (soft-off) control values.
//!
//! This is the production power-off path. It follows the same discipline as the
//! parent module: firmware bytes are copied once into kernel-owned workspace,
//! checksummed, and parsed only from that immutable observation. Discovery
//! yields a proposal; the locked q35 profile separately authorizes the exact
//! PM1 control port before any write is permitted.
//!
//! Unlike the `test-support` debug-exit transport, nothing here depends on a
//! QEMU test device. The values come from firmware and the write is the
//! architectural one, so this path is also correct on physical hardware that
//! implements ACPI 2.0 fixed hardware.

use super::{
    AcpiByteReader, AcpiSnapshotWorkspace, AcpiTimeError, MAX_ROOT_ENTRIES, RootTable,
    SDT_HEADER_BYTES, finish_sdt_snapshot, snapshot_rsdp, snapshot_sdt, snapshot_sdt_header,
};
use crate::arch::x86_64::io_port::ScalarPortIo;

const FADT_DSDT: usize = 40;
const FADT_PM1A_CNT_BLK: usize = 64;
const FADT_PM1B_CNT_BLK: usize = 68;
const FADT_PM1_CNT_LEN: usize = 89;
const FADT_FLAGS: usize = 112;
const FADT_X_DSDT: usize = 140;
const FADT_X_PM1A_CNT_BLK: usize = 172;
const FADT_X_PM1B_CNT_BLK: usize = 184;
const FADT_MINIMUM_BYTES: usize = 116;
const FADT_X_DSDT_END: usize = 148;
const FADT_X_PM1A_END: usize = 184;
const FADT_X_PM1B_END: usize = 196;
const FADT_HW_REDUCED_ACPI: u32 = 1 << 20;
const GAS_SYSTEM_IO: u8 = 1;
const GAS_WORD_ACCESS: u8 = 2;
const PM1_CNT_WIDTH_BITS: u8 = 16;
const PM1_CNT_BYTES: u8 = 2;

/// AML `NameOp`, the only opcode that may introduce a `\_S5_` definition.
const AML_NAME_OP: u8 = 0x08;
const AML_ROOT_CHAR: u8 = 0x5c;
const AML_PACKAGE_OP: u8 = 0x12;
const AML_ZERO_OP: u8 = 0x00;
const AML_ONE_OP: u8 = 0x01;
const AML_BYTE_PREFIX: u8 = 0x0a;
/// `_S5` padded to a four-character `NameSeg`.
const AML_S5_NAME_SEG: [u8; 4] = *b"_S5_";
/// `SLP_TYP` occupies PM1_CNT bits 10..=12, so only these values encode.
const MAX_SLP_TYP: u8 = 7;
const SLP_TYP_SHIFT: u32 = 10;
/// `SLP_EN`, PM1_CNT bit 13.
const SLP_EN: u16 = 1 << 13;

/// q35 places the ACPI PM block at 0x600; PM1a_CNT is at offset 4, which the
/// already-authorized PM timer port (0x608, offset 8) independently confirms.
pub(crate) const Q35_PM1A_CONTROL_PORT: u16 = 0x604;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcpiSleepError {
    ReadFailure,
    InvalidRsdp,
    InvalidRootTable,
    RootEntryLimit,
    MissingFadt,
    DuplicateFadt,
    InvalidFadt,
    HardwareReduced,
    MissingPm1aControl,
    ConflictingPm1aControl,
    ConflictingPm1bControl,
    UnexpectedPm1ControlLength,
    MissingDsdt,
    InvalidDsdt,
    MissingS5,
    MalformedS5,
    ConflictingS5,
    UnsupportedSlpTyp,
    UnauthorizedControlPort,
}

/// What firmware proposes for entering S5, before any profile authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct S5Proposal {
    pm1a_control_port: u16,
    pm1b_control_port: Option<u16>,
    pm1a_slp_typ: u8,
    pm1b_slp_typ: u8,
}

#[allow(
    dead_code,
    reason = "host ACPI tests inspect the proposal and the authorized command; the target path moves them between discovery, publication and the PM1 write without reading the fields back"
)]
impl S5Proposal {
    pub(crate) const fn pm1a_control_port(self) -> u16 {
        self.pm1a_control_port
    }
    pub(crate) const fn pm1b_control_port(self) -> Option<u16> {
        self.pm1b_control_port
    }
    pub(crate) const fn pm1a_slp_typ(self) -> u8 {
        self.pm1a_slp_typ
    }
    pub(crate) const fn pm1b_slp_typ(self) -> u8 {
        self.pm1b_slp_typ
    }
}

/// An authorized soft-off command: exact ports and exact words to write.
///
/// Holding one of these is the authority to power the machine off. It is
/// constructible only by [`authorize_q35_s5`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct S5SoftOff {
    pm1a_control_port: u16,
    pm1a_value: u16,
    pm1b: Option<(u16, u16)>,
}

#[allow(
    dead_code,
    reason = "host ACPI tests inspect the proposal and the authorized command; the target path moves them between discovery, publication and the PM1 write without reading the fields back"
)]
impl S5SoftOff {
    pub(crate) const fn pm1a_control_port(self) -> u16 {
        self.pm1a_control_port
    }
    pub(crate) const fn pm1a_value(self) -> u16 {
        self.pm1a_value
    }
    pub(crate) const fn pm1b(self) -> Option<(u16, u16)> {
        self.pm1b
    }
}

/// The bounded FADT facts S5 needs, extracted before the shared table buffer is
/// reused for the DSDT.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Pm1ControlFacts {
    pm1a_control_port: u16,
    pm1b_control_port: Option<u16>,
    dsdt_physical: u64,
}

pub(crate) fn discover_s5_proposal<R: AcpiByteReader>(
    reader: &mut R,
    rsdp_physical: u64,
    workspace: &mut AcpiSnapshotWorkspace,
) -> Result<S5Proposal, AcpiSleepError> {
    let facts = discover_pm1_control_facts(reader, rsdp_physical, workspace)?;
    let dsdt_len = snapshot_sdt(
        reader,
        facts.dsdt_physical,
        &mut workspace.table,
        AcpiTimeError::InvalidFadt,
    )
    .map_err(|error| match error {
        AcpiTimeError::ReadFailure => AcpiSleepError::ReadFailure,
        _ => AcpiSleepError::InvalidDsdt,
    })?;
    if workspace.table[..4] != *b"DSDT" {
        return Err(AcpiSleepError::InvalidDsdt);
    }
    let (pm1a_slp_typ, pm1b_slp_typ) =
        parse_s5_package(&workspace.table[SDT_HEADER_BYTES..dsdt_len])?;
    Ok(S5Proposal {
        pm1a_control_port: facts.pm1a_control_port,
        pm1b_control_port: facts.pm1b_control_port,
        pm1a_slp_typ,
        pm1b_slp_typ,
    })
}

fn discover_pm1_control_facts<R: AcpiByteReader>(
    reader: &mut R,
    rsdp_physical: u64,
    workspace: &mut AcpiSnapshotWorkspace,
) -> Result<Pm1ControlFacts, AcpiSleepError> {
    if rsdp_physical == 0 {
        return Err(AcpiSleepError::InvalidRsdp);
    }
    let root = snapshot_rsdp(reader, rsdp_physical, &mut workspace.rsdp).map_err(map_shared)?;
    let (root_physical, entry_bytes, expected_signature) = match root {
        RootTable::Xsdt(address) => (address, 8_usize, *b"XSDT"),
        RootTable::Rsdt(address) => (address, 4_usize, *b"RSDT"),
    };
    let root_len = snapshot_sdt(
        reader,
        root_physical,
        &mut workspace.table,
        AcpiTimeError::InvalidRootTable,
    )
    .map_err(map_shared)?;
    let root_bytes = &workspace.table[..root_len];
    if root_bytes[..4] != expected_signature {
        return Err(AcpiSleepError::InvalidRootTable);
    }
    let payload = root_len
        .checked_sub(SDT_HEADER_BYTES)
        .ok_or(AcpiSleepError::InvalidRootTable)?;
    if payload % entry_bytes != 0 {
        return Err(AcpiSleepError::InvalidRootTable);
    }
    let count = payload / entry_bytes;
    if count == 0 || count > MAX_ROOT_ENTRIES {
        return Err(AcpiSleepError::RootEntryLimit);
    }
    for index in 0..count {
        let start = SDT_HEADER_BYTES + index * entry_bytes;
        workspace.root_entries[index] = if entry_bytes == 8 {
            u64::from_le_bytes(root_bytes[start..start + 8].try_into().unwrap())
        } else {
            u64::from(u32::from_le_bytes(
                root_bytes[start..start + 4].try_into().unwrap(),
            ))
        };
    }

    let mut facts = None;
    for index in 0..count {
        let physical = workspace.root_entries[index];
        if physical == 0 {
            continue;
        }
        let header_len =
            snapshot_sdt_header(reader, physical, &mut workspace.table).map_err(map_shared)?;
        if workspace.table[..4] != *b"FACP" {
            continue;
        }
        if facts.is_some() {
            return Err(AcpiSleepError::DuplicateFadt);
        }
        let fadt_len = finish_sdt_snapshot(
            reader,
            physical,
            header_len,
            &mut workspace.table,
            AcpiTimeError::InvalidFadt,
        )
        .map_err(|error| match error {
            AcpiTimeError::ReadFailure => AcpiSleepError::ReadFailure,
            _ => AcpiSleepError::InvalidFadt,
        })?;
        facts = Some(parse_fadt_pm1_control(&workspace.table[..fadt_len])?);
    }
    facts.ok_or(AcpiSleepError::MissingFadt)
}

/// The shared snapshot helpers report in the parent module's vocabulary. Map
/// every variant explicitly rather than wildcarding an error type at a
/// boundary.
fn map_shared(error: AcpiTimeError) -> AcpiSleepError {
    match error {
        AcpiTimeError::ReadFailure => AcpiSleepError::ReadFailure,
        AcpiTimeError::InvalidRsdp => AcpiSleepError::InvalidRsdp,
        AcpiTimeError::InvalidRootTable => AcpiSleepError::InvalidRootTable,
        AcpiTimeError::RootEntryLimit => AcpiSleepError::RootEntryLimit,
        AcpiTimeError::MissingFadt => AcpiSleepError::MissingFadt,
        AcpiTimeError::DuplicateFadt => AcpiSleepError::DuplicateFadt,
        AcpiTimeError::InvalidFadt
        | AcpiTimeError::MissingPmTimer
        | AcpiTimeError::ConflictingPmTimer
        | AcpiTimeError::UnauthorizedPmTimerPort => AcpiSleepError::InvalidFadt,
        AcpiTimeError::HardwareReduced => AcpiSleepError::HardwareReduced,
    }
}

fn parse_fadt_pm1_control(bytes: &[u8]) -> Result<Pm1ControlFacts, AcpiSleepError> {
    if bytes.len() < FADT_MINIMUM_BYTES {
        return Err(AcpiSleepError::InvalidFadt);
    }
    let flags = u32::from_le_bytes(bytes[FADT_FLAGS..FADT_FLAGS + 4].try_into().unwrap());
    if flags & FADT_HW_REDUCED_ACPI != 0 {
        return Err(AcpiSleepError::HardwareReduced);
    }
    if bytes[FADT_PM1_CNT_LEN] != PM1_CNT_BYTES {
        return Err(AcpiSleepError::UnexpectedPm1ControlLength);
    }

    let legacy_a = legacy_port(bytes, FADT_PM1A_CNT_BLK);
    let legacy_b = legacy_port(bytes, FADT_PM1B_CNT_BLK);
    let extended_a = extended_port(bytes, FADT_X_PM1A_CNT_BLK, FADT_X_PM1A_END);
    let extended_b = extended_port(bytes, FADT_X_PM1B_CNT_BLK, FADT_X_PM1B_END);

    if let (Some(extended), Some(legacy)) = (extended_a, legacy_a)
        && extended != legacy
    {
        return Err(AcpiSleepError::ConflictingPm1aControl);
    }
    if let (Some(extended), Some(legacy)) = (extended_b, legacy_b)
        && extended != legacy
    {
        return Err(AcpiSleepError::ConflictingPm1bControl);
    }
    let pm1a_control_port = extended_a
        .or(legacy_a)
        .ok_or(AcpiSleepError::MissingPm1aControl)?;

    let dsdt_physical = extended_dsdt(bytes)
        .or_else(|| {
            let legacy = u32::from_le_bytes(bytes[FADT_DSDT..FADT_DSDT + 4].try_into().unwrap());
            (legacy != 0).then_some(u64::from(legacy))
        })
        .ok_or(AcpiSleepError::MissingDsdt)?;

    Ok(Pm1ControlFacts {
        pm1a_control_port,
        pm1b_control_port: extended_b.or(legacy_b),
        dsdt_physical,
    })
}

fn legacy_port(bytes: &[u8], offset: usize) -> Option<u16> {
    let address = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    (address != 0 && address <= u32::from(u16::MAX)).then_some(address as u16)
}

fn extended_port(bytes: &[u8], offset: usize, end: usize) -> Option<u16> {
    if bytes.len() < end {
        return None;
    }
    let gas = &bytes[offset..offset + 12];
    let address = u64::from_le_bytes(gas[4..12].try_into().ok()?);
    (gas[0] == GAS_SYSTEM_IO
        && gas[1] == PM1_CNT_WIDTH_BITS
        && gas[2] == 0
        && matches!(gas[3], 0 | GAS_WORD_ACCESS)
        && address != 0
        && address <= u64::from(u16::MAX))
    .then_some(address as u16)
}

fn extended_dsdt(bytes: &[u8]) -> Option<u64> {
    if bytes.len() < FADT_X_DSDT_END {
        return None;
    }
    let address = u64::from_le_bytes(bytes[FADT_X_DSDT..FADT_X_DSDT + 8].try_into().ok()?);
    (address != 0).then_some(address)
}

/// Scan a DSDT body for `Name(\_S5_, Package(){ SLP_TYPa, SLP_TYPb, .. })`.
///
/// The four-byte `NameSeg` can also occur inside unrelated buffer or string
/// data, so a signature hit is only a candidate: it counts once the whole
/// package decodes. Candidates that never decode are reported as
/// [`AcpiSleepError::MalformedS5`], which is a different fact from a DSDT that
/// never mentions `_S5_` at all.
fn parse_s5_package(body: &[u8]) -> Result<(u8, u8), AcpiSleepError> {
    let mut found: Option<(u8, u8)> = None;
    let mut candidates = 0_usize;
    let mut index = 0_usize;
    while index + AML_S5_NAME_SEG.len() <= body.len() {
        if body[index..index + AML_S5_NAME_SEG.len()] != AML_S5_NAME_SEG {
            index += 1;
            continue;
        }
        if !name_op_precedes(body, index) {
            index += 1;
            continue;
        }
        candidates += 1;
        let Some(values) = decode_s5_package(&body[index + AML_S5_NAME_SEG.len()..]) else {
            index += 1;
            continue;
        };
        match found {
            Some(existing) if existing != values => return Err(AcpiSleepError::ConflictingS5),
            Some(_) => {}
            None => found = Some(values),
        }
        index += 1;
    }
    match found {
        Some(values) => Ok(values),
        None if candidates > 0 => Err(AcpiSleepError::MalformedS5),
        None => Err(AcpiSleepError::MissingS5),
    }
}

/// `NameOp` sits immediately before the `NameSeg`, optionally separated by the
/// root prefix `\`.
fn name_op_precedes(body: &[u8], name_seg: usize) -> bool {
    if name_seg >= 1 && body[name_seg - 1] == AML_NAME_OP {
        return true;
    }
    name_seg >= 2 && body[name_seg - 1] == AML_ROOT_CHAR && body[name_seg - 2] == AML_NAME_OP
}

fn decode_s5_package(bytes: &[u8]) -> Option<(u8, u8)> {
    let (&opcode, rest) = bytes.split_first()?;
    if opcode != AML_PACKAGE_OP {
        return None;
    }
    let (package_bytes, rest) = package_length(rest)?;
    // The declared package must fit inside what actually follows it.
    if package_bytes > rest.len() {
        return None;
    }
    let (&elements, rest) = rest.split_first()?;
    if elements < 2 {
        return None;
    }
    let (first, rest) = package_integer(rest)?;
    let (second, _) = package_integer(rest)?;
    Some((first, second))
}

/// Decode an AML `PkgLength`, returning the declared byte count measured from
/// the first length byte, and the bytes that follow the encoding itself.
fn package_length(bytes: &[u8]) -> Option<(usize, &[u8])> {
    let (&lead, rest) = bytes.split_first()?;
    let follow = usize::from(lead >> 6);
    if follow == 0 {
        let total = usize::from(lead & 0x3f);
        return Some((total.checked_sub(1)?, rest));
    }
    if rest.len() < follow {
        return None;
    }
    let mut total = usize::from(lead & 0x0f);
    for (step, byte) in rest[..follow].iter().copied().enumerate() {
        total |= usize::from(byte) << (4 + 8 * step);
    }
    Some((total.checked_sub(1 + follow)?, &rest[follow..]))
}

/// S5 `SLP_TYP` values are three bits, so only the small integer encodings can
/// legitimately appear here.
fn package_integer(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let (&opcode, rest) = bytes.split_first()?;
    match opcode {
        AML_ZERO_OP => Some((0, rest)),
        AML_ONE_OP => Some((1, rest)),
        AML_BYTE_PREFIX => {
            let (&value, rest) = rest.split_first()?;
            Some((value, rest))
        }
        _ => None,
    }
}

/// Authorize a firmware proposal against the locked q35 profile.
pub(crate) fn authorize_q35_s5(proposal: S5Proposal) -> Result<S5SoftOff, AcpiSleepError> {
    if proposal.pm1a_control_port != Q35_PM1A_CONTROL_PORT {
        return Err(AcpiSleepError::UnauthorizedControlPort);
    }
    if proposal.pm1a_slp_typ > MAX_SLP_TYP || proposal.pm1b_slp_typ > MAX_SLP_TYP {
        return Err(AcpiSleepError::UnsupportedSlpTyp);
    }
    Ok(S5SoftOff {
        pm1a_control_port: proposal.pm1a_control_port,
        pm1a_value: sleep_command(proposal.pm1a_slp_typ),
        pm1b: proposal
            .pm1b_control_port
            .map(|port| (port, sleep_command(proposal.pm1b_slp_typ))),
    })
}

const fn sleep_command(slp_typ: u8) -> u16 {
    ((slp_typ as u16) << SLP_TYP_SHIFT) | SLP_EN
}

/// The authorized soft-off command, published once by the BSP during boot and
/// read by the terminal path long after the ACPI workspace is gone.
///
/// Packed into one word so publication needs no lock and no `unsafe`: PM1a port
/// in bits 48..64, PM1a value in 32..48, PM1b port in 16..32, PM1b value in
/// 0..16. A PM1a port of zero is not a legal control register, so an all-zero
/// word unambiguously means "no soft-off is available".
static AUTHORIZED_SOFT_OFF: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

const fn pack_soft_off(command: S5SoftOff) -> u64 {
    let (pm1b_port, pm1b_value) = match command.pm1b {
        Some((port, value)) => (port, value),
        None => (0, 0),
    };
    ((command.pm1a_control_port as u64) << 48)
        | ((command.pm1a_value as u64) << 32)
        | ((pm1b_port as u64) << 16)
        | (pm1b_value as u64)
}

const fn unpack_soft_off(word: u64) -> Option<S5SoftOff> {
    let pm1a_control_port = (word >> 48) as u16;
    if pm1a_control_port == 0 {
        return None;
    }
    let pm1b_port = (word >> 16) as u16;
    Some(S5SoftOff {
        pm1a_control_port,
        pm1a_value: (word >> 32) as u16,
        pm1b: if pm1b_port == 0 {
            None
        } else {
            Some((pm1b_port, word as u16))
        },
    })
}

/// Publish the one authorized soft-off command for the rest of the boot.
///
/// Called once by the BSP before any other CPU can reach the terminal path.
pub(crate) fn publish_authorized_soft_off(command: S5SoftOff) {
    AUTHORIZED_SOFT_OFF.store(
        pack_soft_off(command),
        core::sync::atomic::Ordering::Release,
    );
}

/// The authorized soft-off command, or `None` when discovery never succeeded.
pub(crate) fn authorized_soft_off() -> Option<S5SoftOff> {
    unpack_soft_off(AUTHORIZED_SOFT_OFF.load(core::sync::atomic::Ordering::Acquire))
}

/// Write the authorized S5 command to the PM1 control register(s).
///
/// On conforming firmware the machine powers off inside the PM1a write and this
/// never returns normally. It is written as a plain function so the caller owns
/// what happens if firmware declines, and so the whole sequence is observable
/// from host tests through [`ScalarPortIo`].
pub(crate) fn request_soft_off<P: ScalarPortIo>(port_io: &mut P, command: S5SoftOff) {
    port_io.write_u16(command.pm1a_control_port, command.pm1a_value);
    if let Some((port, value)) = command.pm1b {
        port_io.write_u16(port, value);
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::arch::x86_64::io_port::BytePortIo;
    use std::boxed::Box;
    use std::collections::BTreeMap;
    use std::vec;
    use std::vec::Vec;

    const RSDP: u64 = 0x1000;
    const XSDT: u64 = 0x2000;
    const FADT: u64 = 0x3000;
    const DSDT: u64 = 0x4000;
    const FADT_BYTES: usize = 244;

    #[derive(Default, Clone)]
    struct Memory(BTreeMap<u64, u8>);
    impl Memory {
        fn place(&mut self, address: u64, bytes: &[u8]) {
            for (offset, byte) in bytes.iter().copied().enumerate() {
                self.0.insert(address + offset as u64, byte);
            }
        }
    }
    impl AcpiByteReader for Memory {
        fn read_exact(&mut self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()> {
            for (offset, byte) in destination.iter_mut().enumerate() {
                *byte = *self.0.get(&(physical_start + offset as u64)).ok_or(())?;
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct RecordingPortIo(Vec<(u16, u16)>);
    impl BytePortIo for RecordingPortIo {
        fn read_u8(&mut self, _port: u16) -> u8 {
            unreachable!("S5 soft-off performs no byte input")
        }
        fn write_u8(&mut self, _port: u16, _value: u8) {
            unreachable!("S5 soft-off performs no byte output")
        }
    }
    impl ScalarPortIo for RecordingPortIo {
        fn read_u16(&mut self, _port: u16) -> u16 {
            unreachable!("S5 soft-off performs no word input")
        }
        fn read_u32(&mut self, _port: u16) -> u32 {
            unreachable!("S5 soft-off performs no doubleword input")
        }
        fn write_u16(&mut self, port: u16, value: u16) {
            self.0.push((port, value));
        }
        fn write_u32(&mut self, _port: u16, _value: u32) {
            unreachable!("S5 soft-off performs no doubleword output")
        }
    }

    fn workspace() -> Box<AcpiSnapshotWorkspace> {
        Box::new(AcpiSnapshotWorkspace::new())
    }
    fn checksum(bytes: &[u8]) -> u8 {
        bytes.iter().fold(0_u8, |sum, byte| sum.wrapping_add(*byte))
    }
    fn fix_checksum(bytes: &mut [u8], checksum_offset: usize) {
        bytes[checksum_offset] = 0;
        bytes[checksum_offset] = 0_u8.wrapping_sub(checksum(bytes));
    }
    fn sdt(signature: [u8; 4], length: usize) -> Vec<u8> {
        let mut bytes = vec![0_u8; length];
        bytes[..4].copy_from_slice(&signature);
        bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
        bytes[8] = 1;
        bytes
    }

    /// Encode `Package(){ .. }` with a correctly computed `PkgLength`.
    fn package(elements: &[u8]) -> Vec<u8> {
        let mut content = vec![elements.len() as u8];
        for value in elements.iter().copied() {
            match value {
                0 => content.push(AML_ZERO_OP),
                1 => content.push(AML_ONE_OP),
                other => {
                    content.push(AML_BYTE_PREFIX);
                    content.push(other);
                }
            }
        }
        let total = content.len() + 1;
        assert!(
            total <= 0x3f,
            "test packages use the one-byte PkgLength form"
        );
        let mut bytes = vec![AML_PACKAGE_OP, total as u8];
        bytes.extend_from_slice(&content);
        bytes
    }
    /// `Name(\_S5_, Package(){ .. })` as it appears in a DSDT body.
    fn s5_definition(elements: &[u8]) -> Vec<u8> {
        let mut bytes = vec![AML_NAME_OP, AML_ROOT_CHAR];
        bytes.extend_from_slice(&AML_S5_NAME_SEG);
        bytes.extend_from_slice(&package(elements));
        bytes
    }
    fn dsdt(body: &[u8]) -> Vec<u8> {
        let mut bytes = sdt(*b"DSDT", SDT_HEADER_BYTES + body.len());
        bytes[SDT_HEADER_BYTES..].copy_from_slice(body);
        fix_checksum(&mut bytes, 9);
        bytes
    }

    fn io_gas(port: u16, width: u8, access: u8) -> [u8; 12] {
        let mut gas = [0_u8; 12];
        gas[0] = GAS_SYSTEM_IO;
        gas[1] = width;
        gas[2] = 0;
        gas[3] = access;
        gas[4..12].copy_from_slice(&u64::from(port).to_le_bytes());
        gas
    }

    struct FadtSpec {
        legacy_pm1a: u16,
        legacy_pm1b: u16,
        extended_pm1a: Option<u16>,
        extended_pm1b: Option<u16>,
        pm1_cnt_len: u8,
        flags: u32,
        legacy_dsdt: u32,
        extended_dsdt: u64,
        length: usize,
    }
    impl Default for FadtSpec {
        fn default() -> Self {
            Self {
                legacy_pm1a: Q35_PM1A_CONTROL_PORT,
                legacy_pm1b: 0,
                extended_pm1a: None,
                extended_pm1b: None,
                pm1_cnt_len: PM1_CNT_BYTES,
                flags: 0,
                legacy_dsdt: DSDT as u32,
                extended_dsdt: 0,
                length: FADT_BYTES,
            }
        }
    }
    fn fadt(spec: &FadtSpec) -> Vec<u8> {
        let mut bytes = sdt(*b"FACP", spec.length);
        bytes[FADT_PM1A_CNT_BLK..FADT_PM1A_CNT_BLK + 4]
            .copy_from_slice(&u32::from(spec.legacy_pm1a).to_le_bytes());
        bytes[FADT_PM1B_CNT_BLK..FADT_PM1B_CNT_BLK + 4]
            .copy_from_slice(&u32::from(spec.legacy_pm1b).to_le_bytes());
        if spec.length > FADT_PM1_CNT_LEN {
            bytes[FADT_PM1_CNT_LEN] = spec.pm1_cnt_len;
        }
        if spec.length >= FADT_FLAGS + 4 {
            bytes[FADT_FLAGS..FADT_FLAGS + 4].copy_from_slice(&spec.flags.to_le_bytes());
        }
        bytes[FADT_DSDT..FADT_DSDT + 4].copy_from_slice(&spec.legacy_dsdt.to_le_bytes());
        if spec.length >= FADT_X_DSDT_END {
            bytes[FADT_X_DSDT..FADT_X_DSDT + 8].copy_from_slice(&spec.extended_dsdt.to_le_bytes());
        }
        if let Some(port) = spec.extended_pm1a
            && spec.length >= FADT_X_PM1A_END
        {
            bytes[FADT_X_PM1A_CNT_BLK..FADT_X_PM1A_CNT_BLK + 12].copy_from_slice(&io_gas(
                port,
                PM1_CNT_WIDTH_BITS,
                GAS_WORD_ACCESS,
            ));
        }
        if let Some(port) = spec.extended_pm1b
            && spec.length >= FADT_X_PM1B_END
        {
            bytes[FADT_X_PM1B_CNT_BLK..FADT_X_PM1B_CNT_BLK + 12].copy_from_slice(&io_gas(
                port,
                PM1_CNT_WIDTH_BITS,
                GAS_WORD_ACCESS,
            ));
        }
        fix_checksum(&mut bytes, 9);
        bytes
    }

    fn firmware(spec: &FadtSpec, dsdt_bytes: &[u8]) -> Memory {
        let mut memory = Memory::default();
        let fadt_bytes = fadt(spec);
        memory.place(FADT, &fadt_bytes);
        let dsdt_at = if spec.extended_dsdt != 0 {
            spec.extended_dsdt
        } else {
            u64::from(spec.legacy_dsdt)
        };
        if dsdt_at != 0 {
            memory.place(dsdt_at, dsdt_bytes);
        }
        let mut xsdt = sdt(*b"XSDT", SDT_HEADER_BYTES + 8);
        xsdt[SDT_HEADER_BYTES..SDT_HEADER_BYTES + 8].copy_from_slice(&FADT.to_le_bytes());
        fix_checksum(&mut xsdt, 9);
        memory.place(XSDT, &xsdt);
        let mut rsdp = vec![0_u8; 36];
        rsdp[..8].copy_from_slice(b"RSD PTR ");
        rsdp[15] = 2;
        rsdp[20..24].copy_from_slice(&36_u32.to_le_bytes());
        rsdp[24..32].copy_from_slice(&XSDT.to_le_bytes());
        fix_checksum(&mut rsdp[..20], 8);
        fix_checksum(&mut rsdp, 32);
        memory.place(RSDP, &rsdp);
        memory
    }

    fn discover(spec: &FadtSpec, dsdt_bytes: &[u8]) -> Result<S5Proposal, AcpiSleepError> {
        let mut memory = firmware(spec, dsdt_bytes);
        discover_s5_proposal(&mut memory, RSDP, &mut workspace())
    }

    // ---- end to end ----

    #[test]
    fn q35_shaped_firmware_yields_an_authorizable_soft_off() {
        let proposal = discover(&FadtSpec::default(), &dsdt(&s5_definition(&[0, 0, 0, 0])))
            .expect("q35-shaped firmware describes S5");
        assert_eq!(proposal.pm1a_control_port(), Q35_PM1A_CONTROL_PORT);
        assert_eq!(proposal.pm1b_control_port(), None);
        assert_eq!(proposal.pm1a_slp_typ(), 0);
        let command = authorize_q35_s5(proposal).expect("the locked profile authorizes 0x604");
        assert_eq!(command.pm1a_value(), SLP_EN);
        assert_eq!(command.pm1b(), None);
    }

    #[test]
    fn a_nonzero_sleep_type_reaches_the_control_word() {
        let proposal = discover(&FadtSpec::default(), &dsdt(&s5_definition(&[5, 5, 0, 0])))
            .expect("firmware may choose any encodable SLP_TYP");
        let command = authorize_q35_s5(proposal).expect("0x604 stays authorized");
        // ACPI 6.x table 4.13: SLP_TYPx is PM1_CNT bits 10..=12 and SLP_EN is
        // bit 13, so SLP_TYP 5 is 0x1400 | 0x2000. Spelled as a literal: an
        // assertion written in terms of SLP_TYP_SHIFT would hold for any shift.
        assert_eq!(command.pm1a_value(), 0x3400);
    }

    #[test]
    fn the_extended_dsdt_pointer_is_preferred_over_the_legacy_one() {
        // Only the extended target holds a DSDT; a parser that read the legacy
        // pointer would fail to find any table at all.
        let spec = FadtSpec {
            legacy_dsdt: 0xdead_0000,
            extended_dsdt: DSDT,
            ..FadtSpec::default()
        };
        let proposal =
            discover(&spec, &dsdt(&s5_definition(&[3, 0]))).expect("X_DSDT locates the DSDT");
        assert_eq!(proposal.pm1a_slp_typ(), 3);
    }

    #[test]
    fn a_second_control_register_is_carried_into_the_command() {
        let spec = FadtSpec {
            legacy_pm1b: 0x60c,
            ..FadtSpec::default()
        };
        let proposal = discover(&spec, &dsdt(&s5_definition(&[0, 2]))).expect("PM1b is optional");
        assert_eq!(proposal.pm1b_control_port(), Some(0x60c));
        let command = authorize_q35_s5(proposal).expect("0x604 stays authorized");
        assert_eq!(command.pm1b(), Some((0x60c, 0x2800)));
    }

    #[test]
    fn a_dsdt_without_s5_is_reported_as_missing_rather_than_guessed() {
        assert_eq!(
            discover(&FadtSpec::default(), &dsdt(&[0x5b, 0x82, 0x10, 0x2e])),
            Err(AcpiSleepError::MissingS5)
        );
    }

    #[test]
    fn a_table_that_is_not_a_dsdt_is_refused() {
        let mut wrong = sdt(*b"SSDT", SDT_HEADER_BYTES + 8);
        fix_checksum(&mut wrong, 9);
        assert_eq!(
            discover(&FadtSpec::default(), &wrong),
            Err(AcpiSleepError::InvalidDsdt)
        );
    }

    #[test]
    fn hardware_reduced_firmware_has_no_pm1_control_to_write() {
        let spec = FadtSpec {
            flags: FADT_HW_REDUCED_ACPI,
            ..FadtSpec::default()
        };
        assert_eq!(
            discover(&spec, &dsdt(&s5_definition(&[0, 0]))),
            Err(AcpiSleepError::HardwareReduced)
        );
    }

    #[test]
    fn a_missing_rsdp_is_not_read() {
        let mut memory = Memory::default();
        assert_eq!(
            discover_s5_proposal(&mut memory, 0, &mut workspace()),
            Err(AcpiSleepError::InvalidRsdp)
        );
    }

    // ---- FADT field parsing ----

    #[test]
    fn the_extended_pm1a_register_overrides_a_zero_legacy_field() {
        let spec = FadtSpec {
            legacy_pm1a: 0,
            extended_pm1a: Some(Q35_PM1A_CONTROL_PORT),
            ..FadtSpec::default()
        };
        let facts = parse_fadt_pm1_control(&fadt(&spec)).expect("X_PM1a_CNT_BLK is sufficient");
        assert_eq!(facts.pm1a_control_port, Q35_PM1A_CONTROL_PORT);
    }

    #[test]
    fn disagreeing_pm1a_registers_are_refused_rather_than_ranked() {
        let spec = FadtSpec {
            legacy_pm1a: 0x604,
            extended_pm1a: Some(0x704),
            ..FadtSpec::default()
        };
        assert_eq!(
            parse_fadt_pm1_control(&fadt(&spec)),
            Err(AcpiSleepError::ConflictingPm1aControl)
        );
    }

    #[test]
    fn disagreeing_pm1b_registers_are_refused_separately_from_pm1a() {
        let spec = FadtSpec {
            legacy_pm1b: 0x60c,
            extended_pm1b: Some(0x70c),
            ..FadtSpec::default()
        };
        assert_eq!(
            parse_fadt_pm1_control(&fadt(&spec)),
            Err(AcpiSleepError::ConflictingPm1bControl)
        );
    }

    #[test]
    fn a_pm1_control_register_that_is_not_two_bytes_is_refused() {
        for length in [0_u8, 1, 4] {
            let spec = FadtSpec {
                pm1_cnt_len: length,
                ..FadtSpec::default()
            };
            assert_eq!(
                parse_fadt_pm1_control(&fadt(&spec)),
                Err(AcpiSleepError::UnexpectedPm1ControlLength),
                "PM1_CNT_LEN {length} is not a 16-bit control register",
            );
        }
    }

    #[test]
    fn firmware_with_no_pm1a_control_register_is_refused() {
        let spec = FadtSpec {
            legacy_pm1a: 0,
            ..FadtSpec::default()
        };
        assert_eq!(
            parse_fadt_pm1_control(&fadt(&spec)),
            Err(AcpiSleepError::MissingPm1aControl)
        );
    }

    #[test]
    fn firmware_with_no_dsdt_pointer_is_refused() {
        let spec = FadtSpec {
            legacy_dsdt: 0,
            extended_dsdt: 0,
            ..FadtSpec::default()
        };
        assert_eq!(
            parse_fadt_pm1_control(&fadt(&spec)),
            Err(AcpiSleepError::MissingDsdt)
        );
    }

    #[test]
    fn a_fadt_too_short_for_the_flags_field_is_refused() {
        let spec = FadtSpec {
            length: FADT_MINIMUM_BYTES - 1,
            ..FadtSpec::default()
        };
        assert_eq!(
            parse_fadt_pm1_control(&fadt(&spec)),
            Err(AcpiSleepError::InvalidFadt)
        );
    }

    #[test]
    fn an_extended_register_is_ignored_when_the_fadt_is_too_short_to_hold_it() {
        // A revision-1 FADT stops before X_PM1a_CNT_BLK; reading it anyway
        // would interpret whatever follows the table as a port number.
        let spec = FadtSpec {
            length: FADT_MINIMUM_BYTES,
            ..FadtSpec::default()
        };
        let facts = parse_fadt_pm1_control(&fadt(&spec)).expect("the legacy fields suffice");
        assert_eq!(facts.pm1a_control_port, Q35_PM1A_CONTROL_PORT);
        assert_eq!(facts.dsdt_physical, DSDT);
    }

    #[test]
    fn an_extended_register_of_the_wrong_shape_is_not_used() {
        for (width, access) in [(32_u8, GAS_WORD_ACCESS), (PM1_CNT_WIDTH_BITS, 3)] {
            let mut bytes = fadt(&FadtSpec {
                legacy_pm1a: 0,
                ..FadtSpec::default()
            });
            bytes[FADT_X_PM1A_CNT_BLK..FADT_X_PM1A_CNT_BLK + 12].copy_from_slice(&io_gas(
                Q35_PM1A_CONTROL_PORT,
                width,
                access,
            ));
            fix_checksum(&mut bytes, 9);
            assert_eq!(
                parse_fadt_pm1_control(&bytes),
                Err(AcpiSleepError::MissingPm1aControl),
                "a {width}-bit/access-{access} GAS is not a PM1 control register",
            );
        }
    }

    // ---- AML scanning ----

    #[test]
    fn the_name_seg_is_only_honored_after_a_name_op() {
        // The same four bytes inside unrelated data must not be mistaken for a
        // definition, even when a well-formed package follows them.
        // 0x11 is BufferOp; none of these bytes is NameOp (0x08) or the root
        // prefix (0x5c), so the NameSeg here is payload, not a definition.
        let mut body = vec![0x11, 0x0b, 0x0a, 0x42];
        body.extend_from_slice(&AML_S5_NAME_SEG);
        body.extend_from_slice(&package(&[4, 4]));
        assert_eq!(parse_s5_package(&body), Err(AcpiSleepError::MissingS5));
    }

    #[test]
    fn a_name_op_without_the_root_prefix_is_honored() {
        let mut body = vec![AML_NAME_OP];
        body.extend_from_slice(&AML_S5_NAME_SEG);
        body.extend_from_slice(&package(&[6, 7]));
        assert_eq!(parse_s5_package(&body), Ok((6, 7)));
    }

    #[test]
    fn a_candidate_that_does_not_decode_is_distinguished_from_no_candidate() {
        let mut body = vec![AML_NAME_OP, AML_ROOT_CHAR];
        body.extend_from_slice(&AML_S5_NAME_SEG);
        body.extend_from_slice(&[0x0d, 0x41, 0x42, 0x00]);
        assert_eq!(parse_s5_package(&body), Err(AcpiSleepError::MalformedS5));
    }

    #[test]
    fn a_package_declaring_fewer_than_two_elements_does_not_decode() {
        let mut body = s5_definition(&[1]);
        body.extend_from_slice(&[0x00; 4]);
        assert_eq!(parse_s5_package(&body), Err(AcpiSleepError::MalformedS5));
    }

    #[test]
    fn a_package_longer_than_the_bytes_that_follow_it_does_not_decode() {
        let mut body = s5_definition(&[2, 2]);
        let package_length = body.len() - 7;
        body[7] = (package_length + 8) as u8;
        assert_eq!(parse_s5_package(&body), Err(AcpiSleepError::MalformedS5));
    }

    #[test]
    fn two_definitions_that_disagree_are_refused_rather_than_ranked() {
        let mut body = s5_definition(&[1, 1]);
        body.extend_from_slice(&s5_definition(&[2, 2]));
        assert_eq!(parse_s5_package(&body), Err(AcpiSleepError::ConflictingS5));
    }

    #[test]
    fn two_definitions_that_agree_are_accepted() {
        let mut body = s5_definition(&[1, 1]);
        body.extend_from_slice(&s5_definition(&[1, 1]));
        assert_eq!(parse_s5_package(&body), Ok((1, 1)));
    }

    #[test]
    fn the_multi_byte_package_length_form_decodes() {
        let mut content = vec![2_u8, AML_ZERO_OP, AML_BYTE_PREFIX, 3];
        content.extend_from_slice(&[0x00; 24]);
        let total = content.len() + 2;
        let mut body = vec![AML_NAME_OP, AML_ROOT_CHAR];
        body.extend_from_slice(&AML_S5_NAME_SEG);
        body.push(AML_PACKAGE_OP);
        body.push(0x40 | ((total & 0x0f) as u8));
        body.push((total >> 4) as u8);
        body.extend_from_slice(&content);
        assert_eq!(parse_s5_package(&body), Ok((0, 3)));
    }

    #[test]
    fn only_the_small_integer_opcodes_decode_as_sleep_types() {
        assert_eq!(
            package_integer(&[AML_ZERO_OP, 0xff]).map(|(v, _)| v),
            Some(0)
        );
        assert_eq!(
            package_integer(&[AML_ONE_OP, 0xff]).map(|(v, _)| v),
            Some(1)
        );
        assert_eq!(
            package_integer(&[AML_BYTE_PREFIX, 0x07]).map(|(v, _)| v),
            Some(7)
        );
        // WordPrefix, DWordPrefix and a bare name reference are all rejected.
        for opcode in [0x0b_u8, 0x0c, 0x5c] {
            assert_eq!(package_integer(&[opcode, 0, 0, 0, 0]), None);
        }
        assert_eq!(package_integer(&[]), None);
    }

    // ---- authorization and execution ----

    #[test]
    fn a_control_port_outside_the_locked_profile_is_refused() {
        let proposal = S5Proposal {
            pm1a_control_port: 0x404,
            pm1b_control_port: None,
            pm1a_slp_typ: 0,
            pm1b_slp_typ: 0,
        };
        assert_eq!(
            authorize_q35_s5(proposal),
            Err(AcpiSleepError::UnauthorizedControlPort)
        );
    }

    #[test]
    fn a_sleep_type_wider_than_three_bits_is_refused_on_either_register() {
        for (a, b) in [(8_u8, 0_u8), (0, 8), (0xff, 0)] {
            let proposal = S5Proposal {
                pm1a_control_port: Q35_PM1A_CONTROL_PORT,
                pm1b_control_port: Some(0x60c),
                pm1a_slp_typ: a,
                pm1b_slp_typ: b,
            };
            assert_eq!(
                authorize_q35_s5(proposal),
                Err(AcpiSleepError::UnsupportedSlpTyp),
                "SLP_TYP ({a}, {b}) does not fit PM1_CNT bits 10..=12",
            );
        }
    }

    #[test]
    fn every_encodable_sleep_type_lands_in_bits_ten_through_twelve() {
        // Literal control words from ACPI 6.x table 4.13. Deriving these from
        // SLP_TYP_SHIFT and SLP_EN would make the test true for any placement
        // of the field, which is the one thing it exists to pin.
        const EXPECTED: [u16; 8] = [
            0x2000, 0x2400, 0x2800, 0x2c00, 0x3000, 0x3400, 0x3800, 0x3c00,
        ];
        for slp_typ in 0..=MAX_SLP_TYP {
            assert_eq!(
                sleep_command(slp_typ),
                EXPECTED[usize::from(slp_typ)],
                "SLP_TYP {slp_typ} must occupy PM1_CNT bits 10..=12 with SLP_EN set",
            );
        }
    }

    #[test]
    fn the_authorized_control_port_is_the_q35_pm_block_control_register() {
        // q35 maps the ACPI PM block at 0x600: PM1a_CNT at offset 4 and the PM
        // timer at offset 8. The timer port is separately pinned and exercised
        // by the parent module, so it independently fixes the block base.
        assert_eq!(Q35_PM1A_CONTROL_PORT, 0x604);
        assert_eq!(
            Q35_PM1A_CONTROL_PORT + 4,
            super::super::Q35_PM_TIMER_PORT,
            "PM1a_CNT and PM_TMR must come from the same q35 PM block",
        );
    }

    #[test]
    fn an_unpublished_cell_offers_no_soft_off() {
        assert_eq!(unpack_soft_off(0), None);
    }

    #[test]
    fn publication_round_trips_both_register_shapes() {
        for command in [
            S5SoftOff {
                pm1a_control_port: 0x604,
                pm1a_value: 0x2000,
                pm1b: None,
            },
            S5SoftOff {
                pm1a_control_port: 0xffff,
                pm1a_value: 0x3c00,
                pm1b: Some((0x60c, 0x2400)),
            },
        ] {
            assert_eq!(
                unpack_soft_off(pack_soft_off(command)),
                Some(command),
                "the packed word must reproduce {command:?} exactly",
            );
        }
    }

    #[test]
    fn a_zero_pm1b_port_does_not_become_a_second_write() {
        // Packing an absent PM1b writes zeroes into both of its fields; reading
        // them back as a real register would issue a write to port 0.
        let command = S5SoftOff {
            pm1a_control_port: 0x604,
            pm1a_value: 0x2000,
            pm1b: None,
        };
        let restored = unpack_soft_off(pack_soft_off(command)).expect("PM1a is present");
        assert_eq!(restored.pm1b(), None);
        let mut port_io = RecordingPortIo::default();
        request_soft_off(&mut port_io, restored);
        assert_eq!(port_io.0, vec![(0x604, 0x2000)]);
    }

    // ---- the production terminal path ----
    //
    // The arms below are compiled only for the freestanding production
    // target, so no host test can execute them and no instrumented product
    // reaches them. Without these checks the whole feature could be silently
    // reverted to a halt loop and every gate would stay green.
    //
    // Two kinds of arm end a production run: the primordial completion
    // (F3A.7f), and the last Process leaving the machine empty (F3A.7j), which
    // is the one WYR1 actually reaches. Each kind appears once per terminal
    // path, and there are two terminal paths.

    const TERMINAL_REPORTS: [(&str, usize); 2] = [
        ("emit_early_bootstrap_completion_record", 2),
        ("emit_early_system_empty_record", 2),
    ];

    #[test]
    fn each_production_terminal_arm_powers_off_instead_of_halting() {
        const PRIMORDIAL: &str = include_str!("../mm/activation/primordial.rs");
        const POWER_OFF: &str = "crate::arch::x86_64::power::soft_off_then_halt()";

        let mut total = 0;
        for (report, expected) in TERMINAL_REPORTS {
            let arms: Vec<&str> = PRIMORDIAL
                .match_indices(report)
                .map(|(at, _)| &PRIMORDIAL[at..])
                .collect();
            assert_eq!(
                arms.len(),
                expected,
                "{report}: a new terminal arm needs a terminator too",
            );
            total += arms.len();
            for (index, arm) in arms.iter().enumerate() {
                // Skip the arm's own report so the scan measures what follows.
                let body = &arm[report.len()..];
                let power_off = body
                    .find(POWER_OFF)
                    .unwrap_or_else(|| panic!("{report} arm {index} never powers off"));
                // Nothing may halt between reporting the cause and acting on it.
                let before = &body[..power_off];
                assert!(
                    !before.contains("\"hlt\""),
                    "{report} arm {index} halts before it reaches soft-off",
                );
                // A report of either kind before the terminator means the scan
                // walked past the end of this arm and validated another one.
                for (other, _) in TERMINAL_REPORTS {
                    assert!(
                        !before.contains(&std::format!("{other}(")),
                        "{report} arm {index} runs into another arm instead of terminating",
                    );
                }
            }
        }
        assert_eq!(
            PRIMORDIAL.matches(POWER_OFF).count(),
            total,
            "every terminal arm, and nothing else, ends in soft-off",
        );
    }

    /// F3A.7k. The primordial completion arm powers off, so it must be
    /// reached only when the primordial is the last Process. A primordial
    /// retiring while others live -- bootstrap on SMP -- retires to idle.
    #[test]
    fn a_primordial_retiring_before_the_last_process_idles_instead_of_completing() {
        const PRIMORDIAL: &str = include_str!("../mm/activation/primordial.rs");
        let squeeze = |text: &str| -> std::string::String {
            text.chars().filter(|c| !c.is_whitespace()).collect()
        };
        let start = PRIMORDIAL
            .find("fn prepare_terminal_handoff_detached(")
            .expect("the detached terminal path is gone");
        let end = start
            + PRIMORDIAL[start..]
                .find("fn finish_terminal_successor(")
                .expect("the detached terminal path never ends");
        let body = squeeze(&PRIMORDIAL[start..end]);

        let completion = body
            .rfind("self.finish_primordial_terminal_handoff(")
            .expect("the primordial completion arm is gone");
        let guard = body[..completion]
            .rfind("ifself.tasks.any_process_unexited_except(retirement.retired_process){")
            .expect("the primordial completion arm is not guarded by the last-Process check");
        let retire = body[guard..completion]
            .find("TerminalKernelContinuation::RetirePrimordialToIdle{")
            .expect("a primordial that is not last must retire to idle");
        // The guarded block returns before the completion arm can run.
        assert!(body[guard..guard + retire].contains("returnPreparedTerminalStep::KernelRoot{"));
        assert!(body[guard..guard + retire].contains("self.unmap_primordial_userspace(&proof)"));

        let arm_start = PRIMORDIAL
            .find(
                "TerminalKernelContinuation::RetirePrimordialToIdle {\n                retirement,",
            )
            .expect("the retire-to-idle continuation is never handled");
        let arm = squeeze(&PRIMORDIAL[arm_start..arm_start + 900]);
        let retired = arm
            .find("self.finish_quiesced_process_root_retirement(")
            .expect("the continuation does not retire the primordial root");
        let idle = arm
            .find("PreparedTerminalStep::Final(PreparedTerminalHandoff::IdleScheduler)")
            .expect("the continuation does not idle");
        assert!(retired < idle);
        assert!(!arm[..idle].contains("soft_off_then_halt"));
    }

    #[test]
    fn the_power_off_path_writes_pm1_control_before_it_halts() {
        const POWER: &str = include_str!("../power.rs");
        let write = POWER
            .find("sleep::request_soft_off(&mut X86PortIo, command)")
            .expect("soft-off must issue the authorized PM1 control write");
        let halt = POWER
            .find("\"hlt\"")
            .expect("the fallback halt loop remains");
        assert!(
            write < halt,
            "the PM1 control write must precede the fallback halt loop",
        );
    }

    #[test]
    fn soft_off_writes_pm1a_first_and_pm1b_only_when_present() {
        let mut port_io = RecordingPortIo::default();
        request_soft_off(
            &mut port_io,
            S5SoftOff {
                pm1a_control_port: 0x604,
                pm1a_value: 0x2000,
                pm1b: Some((0x60c, 0x2400)),
            },
        );
        assert_eq!(port_io.0, vec![(0x604, 0x2000), (0x60c, 0x2400)]);

        let mut port_io = RecordingPortIo::default();
        request_soft_off(
            &mut port_io,
            S5SoftOff {
                pm1a_control_port: 0x604,
                pm1a_value: 0x2000,
                pm1b: None,
            },
        );
        assert_eq!(port_io.0, vec![(0x604, 0x2000)]);
    }
}
