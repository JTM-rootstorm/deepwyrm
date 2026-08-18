//! Deepwyrm kernel crate boundary.
//!
//! The portable boot-intake model remains host-testable. Freestanding x86_64
//! entry installs the kernel's own diagnostic and descriptor state before it
//! validates the loader-owned handoff.

#![no_std]
#![deny(unsafe_code)]

pub mod arch;
pub mod boot;
pub mod debug;
#[allow(
    dead_code,
    reason = "DW0-D5 exposes handle/object services ahead of DW0-E syscall consumers"
)]
pub(crate) mod handle;
pub mod interrupt;
pub mod memory;
#[allow(
    dead_code,
    reason = "DW0-D5 consumes generic lifetime primitives ahead of DW0-E process/syscall ownership"
)]
pub(crate) mod object;
#[path = "handle/service.rs"]
#[allow(
    dead_code,
    reason = "DW0-D5 services precede their DW0-E syscall adapters"
)]
pub(crate) mod service;
#[allow(
    dead_code,
    reason = "DW0-E3 synchronization precedes E4/E5 shared execution consumers"
)]
pub(crate) mod sync;
#[allow(
    dead_code,
    reason = "DW0-E1 syscall decoding precedes E4 architecture entry and E5 handler integration"
)]
pub(crate) mod syscall;
#[allow(
    dead_code,
    reason = "DW0-E2 task payload authority precedes E3 scheduling and E5 syscall consumers"
)]
pub(crate) mod task;

#[cfg(feature = "test-support")]
pub mod test_support;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
use boot::BootInfoByteReader;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
const MAX_X86_PHYSICAL_ADDRESS_EXCLUSIVE: u64 = 1_u64 << 52;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
const BOOTSTRAP_FRAME_RANGE_CAPACITY: usize = memory::boot_map::MAX_SANITIZED_USABLE_RANGES;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
const BOOTSTRAP_FRAME_ROLE_CAPACITY: usize = 544;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct BootstrapStorage<T>(core::cell::UnsafeCell<core::mem::MaybeUninit<T>>);

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl<T> BootstrapStorage<T> {
    const fn uninit() -> Self {
        Self(core::cell::UnsafeCell::new(core::mem::MaybeUninit::uninit()))
    }

    fn slot(&self) -> *mut core::mem::MaybeUninit<T> {
        self.0.get()
    }
}

// SAFETY: these cells are reachable only from the one-shot BSP `kernel_main`
// path before AP startup; no shared reference to their contents is issued.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "one-shot BSP ownership serializes bootstrap static storage"
)]
unsafe impl<T> Sync for BootstrapStorage<T> {}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static BOOTSTRAP_ROLE_MANAGER: BootstrapStorage<
    memory::frame_roles::FrameRoleManager<
        BOOTSTRAP_FRAME_RANGE_CAPACITY,
        BOOTSTRAP_FRAME_ROLE_CAPACITY,
    >,
> = BootstrapStorage::uninit();

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static BOOTSTRAP_RESERVATIONS: BootstrapStorage<
    [memory::boot_map::BootstrapReservation; memory::boot_map::MAX_BOOTSTRAP_RESERVATIONS],
> = BootstrapStorage::uninit();

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static BOOTSTRAP_SANITIZED_MAP: BootstrapStorage<memory::boot_map::SanitizedBootMap> =
    BootstrapStorage::uninit();

/// Transfers from the raw architecture entry into validated DW0-B bring-up.
///
/// This symbol is architecture-internal. The loader enters through
/// `_dw_kernel_entry`, never by calling this Rust function directly.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "raw entry establishes the single-BSP descriptor-install preconditions"
)]
pub(crate) fn kernel_main(boot_info_physical: u64) -> ! {
    // SAFETY: the raw entry shim has already switched to the kernel-owned
    // stack and enforces the reconciled single-BSP, IF-clear entry contract.
    if let Err(error) = unsafe { arch::x86_64::install_early_descriptors() } {
        panic!("failed to install early x86_64 descriptors: {error:?}");
    }

    let reader = IdentityMappedBootInfoReader;
    let boot_info = boot::validate_boot_info(&reader, boot_info_physical)
        .unwrap_or_else(|error| panic!("invalid DwBootInfoV1 handoff: {error:?}"));

    #[cfg(feature = "test-support")]
    match test_support::BUILD_GUEST_TEST {
        test_support::BuildGuestTest::BootHandoffPass => test_support::complete_pass(0),
        test_support::BuildGuestTest::ExceptionFailPath => {
            test_support::trigger_expected_invalid_opcode()
        }
        test_support::BuildGuestTest::PanicPath => panic!("DW0-B panic-path guest test"),
        test if test.is_memory_foundation() => {}
        _ => unreachable!("all build-selected guest tests have explicit dispatch"),
    }

    {
        let physical_width =
            u8::try_from(boot_info.paging_handoff().header().physical_address_width)
                .unwrap_or_else(|_| panic!("paging handoff physical width is not representable"));
        let physical_limit =
            memory::physical::PhysicalAddressLimit::from_address_bits(physical_width)
                .unwrap_or_else(|error| panic!("invalid paging physical limit: {error:?}"));
        // SAFETY: `kernel_main` is the sole BSP owner and this static slot is
        // uninitialized. A sanitizer failure terminates this boot attempt.
        let sanitized = unsafe {
            memory::boot_map::sanitize_boot_map_in(
                &mut *BOOTSTRAP_SANITIZED_MAP.slot(),
                &boot_info,
                boot_info_physical,
                physical_limit,
            )
        }
        .unwrap_or_else(|error| panic!("invalid bootstrap memory map: {error:?}"));
        let reservations = unsafe {
            let array = (*BOOTSTRAP_RESERVATIONS.slot()).as_mut_ptr();
            let element = array.cast::<memory::boot_map::BootstrapReservation>();
            for index in 0..memory::boot_map::MAX_BOOTSTRAP_RESERVATIONS {
                element
                    .add(index)
                    .write(memory::boot_map::BootstrapReservation::placeholder());
            }
            &mut *array
        };
        let reservation_count = memory::boot_map::collect_bootstrap_reservations(
            &boot_info,
            boot_info_physical,
            reservations,
        )
        .unwrap_or_else(|error| panic!("invalid bootstrap reservations: {error:?}"));
        // SAFETY: `kernel_main` is the non-reentrant BSP owner of the consumed
        // boot snapshot and has created no other allocator over its candidates.
        let (roles, memory_witness) = unsafe {
            memory::frame_roles::FrameRoleManager::<
                BOOTSTRAP_FRAME_RANGE_CAPACITY,
                BOOTSTRAP_FRAME_ROLE_CAPACITY,
            >::from_boot_map_in(
                &mut *BOOTSTRAP_ROLE_MANAGER.slot(),
                &sanitized,
                &reservations[..reservation_count],
            )
        }
        .unwrap_or_else(|error| panic!("failed to claim physical ownership: {error:?}"));
        // SAFETY: the raw entry and descriptor installer establish the sole-BSP,
        // CPL0, IF-clear, stationary stack/descriptor contract. No AP or other
        // mapper can run during this complete consuming activation session.
        let active_paging = unsafe {
            arch::x86_64::mm::activate_bootstrap_deep_paging(
                boot_info.paging_handoff(),
                roles,
                memory_witness,
            )
        }
        .unwrap_or_else(|error| panic!("failed to activate Deep-owned paging: {error:?}"));
        #[cfg(not(feature = "test-support"))]
        let _ = debug::emit_early_record(
            debug::DiagnosticLevel::Info,
            "boot",
            "activated Deep-owned page tables",
        );
        #[cfg(feature = "test-support")]
        match test_support::BUILD_GUEST_TEST {
            test if test.is_memory_foundation() => {
                test_support::run_memory_guest_test(active_paging)
            }
            _ => unreachable!("DW0-B terminal selectors cannot pass the early dispatch"),
        }
        #[cfg(not(feature = "test-support"))]
        loop {
            core::hint::black_box(&active_paging);
            // SAFETY: the active session remains owned on this stack, APs are
            // offline, and DW0-C2 has no scheduler or later phase to resume.
            unsafe {
                core::arch::asm!("cli; hlt", options(nomem, nostack));
            }
        }
    }
}

/// Reads the loader's temporary identity mappings under
/// `DW_BOOT_X86_64_ENTRY_V1`.
///
/// Construction is private to [`kernel_main`]. The loader contract guarantees
/// that BootInfo and each referenced handoff range remain mapped and immutable
/// until Deepwyrm replaces the transition page tables.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
struct IdentityMappedBootInfoReader;

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl BootInfoByteReader for IdentityMappedBootInfoReader {
    #[allow(
        unsafe_code,
        reason = "audited identity-mapped physical handoff copy boundary"
    )]
    fn read_exact(&self, physical_start: u64, destination: &mut [u8]) -> Result<(), ()> {
        if destination.is_empty() {
            return Ok(());
        }
        let byte_len = u64::try_from(destination.len()).map_err(|_| ())?;
        let physical_end = physical_start.checked_add(byte_len).ok_or(())?;
        if physical_start == 0 || physical_end > MAX_X86_PHYSICAL_ADDRESS_EXCLUSIVE {
            return Err(());
        }
        let source = usize::try_from(physical_start).map_err(|_| ())? as *const u8;

        // SAFETY: the private reader is used only during the locked loader
        // handoff lifetime. The source is a checked physical range below the
        // maximum x86_64 physical-address width and is identity-mapped and
        // immutable by contract. The destination is a live Rust slice on the
        // disjoint higher-half kernel stack.
        unsafe {
            core::ptr::copy_nonoverlapping(source, destination.as_mut_ptr(), destination.len());
        }
        Ok(())
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    debug::handle_early_panic(info)
}
