use super::*;

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
