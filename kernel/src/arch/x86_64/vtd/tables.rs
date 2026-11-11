//! VT-d root, context and second-level translation tables (storage K4).
//!
//! `DW2_PCI_DEVICE_DMA_CONTRACT.md` §5. Every table is one 4 KiB frame from a
//! fixed pool that [`TableMemory`] owns; entries are written one 64-bit word
//! at a time, with the present bit written last on install and first on
//! removal, so the unit never walks a half-written entry. The live pool maps
//! its frames strong-uncacheable, so a unit that does not snoop CPU caches
//! still reads every store.
//!
//! Only the legacy (non-scalable) formats are used: a root entry per bus, a
//! context entry per device/function, and a 4-level second-level table with
//! 48-bit input addresses.

pub(crate) const TABLE_ENTRIES: usize = 512;
const PAGE_BYTES: u64 = 4096;
const ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;

const PRESENT: u64 = 1;
/// Second-level read and write permission bits.
const SL_READ: u64 = 1 << 0;
const SL_WRITE: u64 = 1 << 1;
/// Context entry: address width 2 selects a 4-level, 48-bit table.
const CONTEXT_AW_4_LEVEL: u64 = 2;
const CONTEXT_DOMAIN_SHIFT: u32 = 8;
/// Input address bits a 4-level second-level table translates.
pub(crate) const FOUR_LEVEL_INPUT_BITS: u32 = 48;

/// The page-table frame pool. Frames come back all zero from [`allocate`]
/// and must be all zero when handed to [`free`].
///
/// [`allocate`]: TableMemory::allocate
/// [`free`]: TableMemory::free
pub(crate) trait TableMemory {
    /// Physical address of one zeroed table frame, or `None` when exhausted.
    fn allocate(&mut self) -> Option<u64>;
    fn free(&mut self, table: u64);
    fn read(&self, table: u64, index: usize) -> u64;
    fn write(&mut self, table: u64, index: usize, value: u64);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TableError {
    /// The pool has no free frame for an intermediate table.
    NoTables,
    /// The page is already mapped.
    Occupied,
    /// The page is not mapped.
    NotMapped,
    /// The address is unaligned or beyond the 48-bit input range.
    InvalidAddress,
}

/// Device permissions of one second-level leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DeviceAccess {
    pub(crate) read: bool,
    pub(crate) write: bool,
}

impl DeviceAccess {
    const fn bits(self) -> u64 {
        (if self.read { SL_READ } else { 0 }) | (if self.write { SL_WRITE } else { 0 })
    }
}

/// Links the context table for `bus` into the root table.
pub(crate) fn install_root_entry<M: TableMemory>(
    memory: &mut M,
    root: u64,
    bus: u8,
    context_table: u64,
) {
    let index = usize::from(bus) * 2;
    memory.write(root, index + 1, 0);
    memory.write(root, index, (context_table & ADDRESS_MASK) | PRESENT);
}

/// Points one device/function at `second_level_root` with `domain_id`.
pub(crate) fn install_context_entry<M: TableMemory>(
    memory: &mut M,
    context_table: u64,
    devfn: u8,
    second_level_root: u64,
    domain_id: u16,
) {
    let index = usize::from(devfn) * 2;
    memory.write(
        context_table,
        index + 1,
        (u64::from(domain_id) << CONTEXT_DOMAIN_SHIFT) | CONTEXT_AW_4_LEVEL,
    );
    // Translation type 0: untranslated requests only, through the
    // second-level table; fault processing stays enabled.
    memory.write(
        context_table,
        index,
        (second_level_root & ADDRESS_MASK) | PRESENT,
    );
}

pub(crate) fn clear_context_entry<M: TableMemory>(memory: &mut M, context_table: u64, devfn: u8) {
    let index = usize::from(devfn) * 2;
    memory.write(context_table, index, 0);
    memory.write(context_table, index + 1, 0);
}

pub(crate) fn context_entry_present<M: TableMemory>(
    memory: &M,
    context_table: u64,
    devfn: u8,
) -> bool {
    memory.read(context_table, usize::from(devfn) * 2) & PRESENT != 0
}

fn index_at(iova: u64, level: u32) -> usize {
    ((iova >> (12 + 9 * (level - 1))) & 0x1ff) as usize
}

fn check_page(iova: u64) -> Result<(), TableError> {
    if !iova.is_multiple_of(PAGE_BYTES) || iova >> FOUR_LEVEL_INPUT_BITS != 0 {
        return Err(TableError::InvalidAddress);
    }
    Ok(())
}

/// Maps one 4 KiB page. Missing intermediate tables are allocated; a failure
/// leaves every existing leaf as it was (a freshly allocated, still-empty
/// intermediate table may remain and is freed by [`free_tree`]).
pub(crate) fn map_page<M: TableMemory>(
    memory: &mut M,
    root: u64,
    iova: u64,
    physical: u64,
    access: DeviceAccess,
) -> Result<(), TableError> {
    check_page(iova)?;
    if !physical.is_multiple_of(PAGE_BYTES) || physical & !ADDRESS_MASK != 0 {
        return Err(TableError::InvalidAddress);
    }
    let mut table = root;
    for level in (2..=4).rev() {
        let index = index_at(iova, level);
        let entry = memory.read(table, index);
        table = if entry & (SL_READ | SL_WRITE) != 0 {
            entry & ADDRESS_MASK
        } else {
            let next = memory.allocate().ok_or(TableError::NoTables)?;
            memory.write(table, index, (next & ADDRESS_MASK) | SL_READ | SL_WRITE);
            next
        };
    }
    let index = index_at(iova, 1);
    if memory.read(table, index) != 0 {
        return Err(TableError::Occupied);
    }
    memory.write(table, index, (physical & ADDRESS_MASK) | access.bits());
    Ok(())
}

/// Clears one 4 KiB leaf. Intermediate tables stay until [`free_tree`].
pub(crate) fn unmap_page<M: TableMemory>(
    memory: &mut M,
    root: u64,
    iova: u64,
) -> Result<(), TableError> {
    check_page(iova)?;
    let mut table = root;
    for level in (2..=4).rev() {
        let entry = memory.read(table, index_at(iova, level));
        if entry & (SL_READ | SL_WRITE) == 0 {
            return Err(TableError::NotMapped);
        }
        table = entry & ADDRESS_MASK;
    }
    let index = index_at(iova, 1);
    if memory.read(table, index) == 0 {
        return Err(TableError::NotMapped);
    }
    memory.write(table, index, 0);
    Ok(())
}

/// The leaf for `iova`, if one is mapped: (physical page, access). Tests
/// use it to read back what a device would see.
#[cfg(test)]
pub(crate) fn translate<M: TableMemory>(
    memory: &M,
    root: u64,
    iova: u64,
) -> Option<(u64, DeviceAccess)> {
    let mut table = root;
    for level in (2..=4).rev() {
        let entry = memory.read(table, index_at(iova, level));
        if entry & (SL_READ | SL_WRITE) == 0 {
            return None;
        }
        table = entry & ADDRESS_MASK;
    }
    let leaf = memory.read(table, index_at(iova, 1));
    if leaf & (SL_READ | SL_WRITE) == 0 {
        return None;
    }
    Some((
        leaf & ADDRESS_MASK,
        DeviceAccess {
            read: leaf & SL_READ != 0,
            write: leaf & SL_WRITE != 0,
        },
    ))
}

/// Zeroes and frees every table under `root`, then `root` itself. Leaves
/// still present are cleared, not followed: they name object pages.
pub(crate) fn free_tree<M: TableMemory>(memory: &mut M, root: u64) {
    free_level(memory, root, 4);
}

fn free_level<M: TableMemory>(memory: &mut M, table: u64, level: u32) {
    for index in 0..TABLE_ENTRIES {
        let entry = memory.read(table, index);
        if entry == 0 {
            continue;
        }
        if level > 1 {
            free_level(memory, entry & ADDRESS_MASK, level - 1);
        }
        memory.write(table, index, 0);
    }
    memory.free(table);
}
