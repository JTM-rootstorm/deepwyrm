#![no_std]

include!("f11_full_kernel_modules.rs");

// D1 option B2: a reclaim permit exists only after every target acknowledged.
fn forge(
    request: memory::address_region::ShootdownRequest,
) -> memory::address_region::ReclaimPermit {
    memory::address_region::ReclaimPermit {
        request,
        target_count: 0,
    }
}
