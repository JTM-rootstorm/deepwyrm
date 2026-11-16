extern crate std;

use super::*;
use std::vec::Vec;

#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "the synthetic model helper attests zeroing without dereferencing physical memory"
)]
pub(crate) fn synthetic_allocator_backing(
    physical_start: u64,
    page_count: u64,
) -> ObjectBackingGrant {
    use super::super::physical::PhysicalAddressLimit;

    let limit = PhysicalAddressLimit::new(1_u64 << 40).expect("test physical limit is valid");
    let candidate = PageRange::from_page_count(physical_start, page_count, limit)
        .expect("test backing range is valid");
    let allocator = PhysicalFrameAllocator::<1>::from_candidates(&[candidate], limit, [])
        .expect("test allocator initializes");
    let mut roles =
        FrameRoleManager::<1, 1>::new(allocator).expect("test role manager initializes");
    let allocation = roles.allocate(page_count).expect("test backing allocates");
    // SAFETY: host model tests never dereference synthetic physical memory;
    // the helper exists only to exercise typed ownership consumption.
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.expect("test backing is zeroed");
    roles
        .assign_object_backing(zeroed)
        .expect("test object backing role commits")
}

#[cfg(test)]
pub(crate) fn synthetic_frame_role_manager<
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    physical_start: u64,
    page_count: u64,
) -> FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY> {
    use super::super::physical::PhysicalAddressLimit;

    let limit = PhysicalAddressLimit::new(1_u64 << 40).expect("test physical limit is valid");
    let candidate = PageRange::from_page_count(physical_start, page_count, limit)
        .expect("test allocator range is valid");
    let allocator = PhysicalFrameAllocator::from_candidates(&[candidate], limit, [])
        .expect("test allocator initializes");
    FrameRoleManager::new(allocator).expect("test role manager initializes")
}

#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "the synthetic model helper supplies immutable boot provenance without physical access"
)]
pub(crate) fn synthetic_immutable_module_backing(
    physical_start: u64,
    page_count: u64,
    module_index: u32,
) -> ObjectBackingGrant {
    use super::super::physical::PhysicalAddressLimit;

    let limit = PhysicalAddressLimit::new(1_u64 << 40).expect("test physical limit is valid");
    let candidate = PageRange::from_page_count(BASE_PAGE_SIZE, 1, limit)
        .expect("test allocator range is valid");
    let allocator = PhysicalFrameAllocator::<1>::from_candidates(&[candidate], limit, [])
        .expect("test allocator initializes");
    let mut roles =
        FrameRoleManager::<1, 1>::new(allocator).expect("test role manager initializes");
    let byte_len = page_count
        .checked_mul(BASE_PAGE_SIZE)
        .expect("test module length is valid");
    let range = PhysicalRange::new(physical_start, byte_len).expect("test module range is valid");
    // SAFETY: this is a metadata-only host model with disjoint synthetic
    // immutable-module provenance.
    unsafe { roles.import_immutable_module(range, module_index) }
        .expect("test immutable module role commits")
}

#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "the synthetic model helper supplies BAR provenance without physical access"
)]
pub(crate) fn synthetic_device_mmio_backing(
    physical_start: u64,
    page_count: u64,
) -> ObjectBackingGrant {
    use super::super::physical::PhysicalAddressLimit;

    let limit = PhysicalAddressLimit::new(1_u64 << 40).expect("test physical limit is valid");
    let candidate = PageRange::from_page_count(BASE_PAGE_SIZE, 1, limit)
        .expect("test allocator range is valid");
    let allocator = PhysicalFrameAllocator::<1>::from_candidates(&[candidate], limit, [])
        .expect("test allocator initializes");
    let mut roles =
        FrameRoleManager::<1, 1>::new(allocator).expect("test role manager initializes");
    let byte_len = page_count
        .checked_mul(BASE_PAGE_SIZE)
        .expect("test BAR length is valid");
    let range = PhysicalRange::new(physical_start, byte_len).expect("test BAR range is valid");
    // SAFETY: a metadata-only host model with a synthetic BAR.
    unsafe { roles.import_device_mmio(range) }.expect("test device-MMIO role commits")
}

/// A leaked, 8-aligned buffer of at least `bytes`, standing in for the
/// table map's range over the grown role table's runs.
#[cfg(test)]
pub(crate) fn leaked_run(bytes: u64) -> *mut u8 {
    use std::{boxed::Box, vec};

    let words = usize::try_from(bytes.div_ceil(8)).expect("a test run fits memory");
    Box::leak(vec![0_u64; words].into_boxed_slice())
        .as_mut_ptr()
        .cast()
}

/// Grows `roles` from `pieces` staged runs (fewer if the table has fewer
/// pages), as near equal as can be. While they are allocated a one-page
/// spacer follows each but the last when memory allows, so no two runs are
/// adjacent in RAM; the spacers are freed after adoption. One leaked
/// buffer stands for the runs mapped back to back. Returns the layout and
/// the runs' slots, in staging order.
#[cfg(test)]
#[allow(
    unsafe_code,
    reason = "the host model hands the manager a leaked buffer as the range its runs are mapped at"
)]
pub(crate) fn grow_in_leaked_runs<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
    roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
    pieces: u64,
) -> (RoleTableLayout, Vec<usize>) {
    let layout = roles.grown_layout().expect("the test table has a layout");
    let total = layout.page_count();
    let count = pieces.clamp(1, total);
    let mut slots = Vec::new();
    let mut spacers = Vec::new();
    for index in 0..count {
        let pages = total / count + u64::from(index < total % count);
        let grant = roles.allocate(pages).expect("a test run allocates");
        slots.push((grant.identity.raw as u32 - 1) as usize);
        roles
            .stage_growth_part(grant)
            .unwrap_or_else(|_| panic!("run {index} stages"));
        if index + 1 < count
            && let Ok(spacer) = roles.allocate(1)
        {
            spacers.push(spacer);
        }
    }
    // SAFETY: the leaked buffer is 8-aligned, the staged runs' size, and
    // used by nothing else, for ever.
    unsafe { roles.adopt_storage(leaked_run(total * BASE_PAGE_SIZE)) }
        .expect("the staged table adopts");
    // Freed once the buddy allocator, which has no range limit, holds them.
    for spacer in spacers {
        roles.cancel_allocation(spacer).expect("a spacer frees");
    }
    (layout, slots)
}
