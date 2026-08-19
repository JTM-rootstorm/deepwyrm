//! Transactional four-level x86_64 page-table policy.
//!
//! This module deliberately does not assume a permanent direct map. Physical
//! table access and publication are injected through [`PageTableTransaction`].
//! The transaction backend is the only component allowed to publish entries:
//! it must serialize the owned root, authenticate and claim every new table
//! frame as zeroed and exclusive, revalidate the complete journal, apply it,
//! and invalidate the local translation before returning success.
//!
//! DW0-C mutates one BSP address space with maskable interrupts disabled. The
//! contract is intentionally not SMP-safe; cross-CPU shootdown is mandatory
//! before this interface can be used after secondary CPUs are online.

use crate::memory::physical::{BASE_PAGE_SIZE, PhysicalAddressLimit};

mod journal;
pub(crate) mod transition;

#[cfg(all(feature = "test-support", target_os = "none", target_arch = "x86_64"))]
pub(crate) use transition::LiveActivePagingTarget;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unused_imports,
    reason = "the C2 one-shot activation facade is wired by later bootstrap sequencing"
)]
pub(crate) use transition::activate_bootstrap_deep_paging;
#[allow(
    unused_imports,
    reason = "the C2 activation typestate precedes its target-only CR3 backend"
)]
pub(crate) use transition::{
    ActivationCpuState, ActivationPrepareError, ActiveDeepPaging, Cr3ActivationTarget,
    InactiveRootAuthority, PreparedActivation,
};

#[allow(
    unused_imports,
    reason = "DW0-C exposes the sealed publisher before the live temporary mapper is wired"
)]
pub(crate) use journal::{
    AtomicPageTableTarget, X86AddressSpacePublishError, X86AddressSpacePublisher,
};
#[allow(
    unused_imports,
    reason = "the one-shot C1 claim is wired by the later bootstrap integration"
)]
pub(crate) use transition::claim_live_transition_mapper;
#[allow(
    unused_imports,
    reason = "the C1 linear facade and terminal handoff precede their C2 consumer"
)]
pub(crate) use transition::{LiveTransitionMapper, TransitionActivationHandoff};

const PAGE_SIZE: u64 = BASE_PAGE_SIZE;
const MAX_MUTATIONS: usize = 4;
const MAX_NEW_TABLES: usize = 3;
const MAX_PATH_ASSERTIONS: usize = 3;
const PRESENT: u64 = 1;
const WRITABLE: u64 = 1 << 1;
const USER: u64 = 1 << 2;
const WRITE_THROUGH: u64 = 1 << 3;
const CACHE_DISABLE: u64 = 1 << 4;
const ACCESSED: u64 = 1 << 5;
const DIRTY: u64 = 1 << 6;
const HUGE: u64 = 1 << 7;
const GLOBAL: u64 = 1 << 8;
const NO_EXECUTE: u64 = 1 << 63;
const SOFTWARE_LOW: u64 = 0b111 << 9;
const SOFTWARE_HIGH: u64 = 0x7ff << 52;
const LEAF_NON_PERMISSION_ATTRIBUTES: u64 =
    WRITE_THROUGH | CACHE_DISABLE | HUGE | GLOBAL | SOFTWARE_LOW | SOFTWARE_HIGH;
const PERMITTED_ENTRY_FLAGS: u64 = PRESENT
    | WRITABLE
    | USER
    | WRITE_THROUGH
    | CACHE_DISABLE
    | ACCESSED
    | DIRTY
    | HUGE
    | GLOBAL
    | SOFTWARE_LOW
    | SOFTWARE_HIGH
    | NO_EXECUTE;

/// A checked physical base-page address. It is never dereferenced directly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct FrameAddress(u64);

impl FrameAddress {
    pub fn new(address: u64, limit: PhysicalAddressLimit) -> Result<Self, AddressError> {
        if address == 0 || !address.is_multiple_of(PAGE_SIZE) || address >= limit.exclusive() {
            return Err(AddressError::InvalidPhysicalFrame(address));
        }
        Ok(Self(address))
    }

    pub const fn address(self) -> u64 {
        self.0
    }
}

/// A canonical base-page virtual address in locked four-level paging mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub struct VirtualPage(u64);

impl VirtualPage {
    pub const fn new(address: u64) -> Result<Self, AddressError> {
        if address & (PAGE_SIZE - 1) != 0 || !is_canonical(address) {
            return Err(AddressError::InvalidVirtualPage(address));
        }
        Ok(Self(address))
    }

    pub const fn containing(address: u64) -> Result<Self, AddressError> {
        if !is_canonical(address) {
            return Err(AddressError::InvalidVirtualPage(address));
        }
        Ok(Self(address & !(PAGE_SIZE - 1)))
    }

    pub const fn address(self) -> u64 {
        self.0
    }

    const fn index(self, level: usize) -> usize {
        ((self.0 >> (12 + level * 9)) & 0x1ff) as usize
    }

    pub const fn is_user_half(self) -> bool {
        self.0 < 0x0000_8000_0000_0000
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddressError {
    InvalidPhysicalFrame(u64),
    InvalidVirtualPage(u64),
    InvalidPhysicalWidth(u8),
    FourLevelPagingRequired,
    NoExecuteRequired,
    WriteProtectRequired,
    InterruptsMustBeDisabled,
}

/// One validated x86_64 paging fact shared with sanitization and allocation.
/// The target-specific CPUID/control-register boundary supplies these inputs;
/// portable callers cannot independently select a page-table width.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PagingCapabilities {
    physical_limit: PhysicalAddressLimit,
}

impl PagingCapabilities {
    #[allow(
        dead_code,
        reason = "used by the target-only bootstrap observer and host policy tests"
    )]
    fn validate(
        max_physical_address_bits: u8,
        four_level_paging: bool,
        no_execute_enabled: bool,
        write_protect_enabled: bool,
    ) -> Result<Self, AddressError> {
        if !four_level_paging {
            return Err(AddressError::FourLevelPagingRequired);
        }
        if !no_execute_enabled {
            return Err(AddressError::NoExecuteRequired);
        }
        if !write_protect_enabled {
            return Err(AddressError::WriteProtectRequired);
        }
        let physical_limit = PhysicalAddressLimit::from_address_bits(max_physical_address_bits)
            .map_err(|_| AddressError::InvalidPhysicalWidth(max_physical_address_bits))?;
        Ok(Self { physical_limit })
    }

    pub const fn physical_limit(self) -> PhysicalAddressLimit {
        self.physical_limit
    }
}

/// Observes the locked bootstrap CPU state and produces the only production
/// paging-capability token.
///
/// # Safety
///
/// The caller must be the BSP on the non-reentrant early entry path, before
/// any AP is started, with CPL0 and maskable interrupts already disabled. No
/// caller may cache the returned fact across a CPU-mode transition.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "audited CPUID/control-register observation at the early x86 paging boundary"
)]
#[allow(
    dead_code,
    reason = "consumed by the pending owned-CR3 transaction backend in DW0-C"
)]
pub(crate) unsafe fn observe_bootstrap_paging_capabilities()
-> Result<PagingCapabilities, AddressError> {
    use core::arch::asm;
    use core::arch::x86_64::__cpuid;

    let highest_extended = __cpuid(0x8000_0000).eax;
    if highest_extended < 0x8000_0008 {
        return Err(AddressError::InvalidPhysicalWidth(0));
    }
    let max_physical_address_bits = (__cpuid(0x8000_0008).eax & 0xff) as u8;
    let cr0: u64;
    let cr4: u64;
    let rflags: u64;
    let efer_low: u32;
    let efer_high: u32;
    // SAFETY: privileged register reads are confined to the documented CPL0
    // bootstrap boundary and do not mutate architectural state.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) rflags, options(nomem, preserves_flags));
        asm!(
            "rdmsr",
            in("ecx") 0xc000_0080_u32,
            out("eax") efer_low,
            out("edx") efer_high,
            options(nomem, nostack, preserves_flags),
        );
    }
    let efer = u64::from(efer_low) | (u64::from(efer_high) << 32);
    if rflags & (1 << 9) != 0 {
        return Err(AddressError::InterruptsMustBeDisabled);
    }
    PagingCapabilities::validate(
        max_physical_address_bits,
        cr4 & (1 << 12) == 0,
        efer & (1 << 11) != 0,
        cr0 & (1 << 16) != 0,
    )
}

/// Requested effective permissions. x86_64 supports only R, RW, and RX here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MappingPermissions {
    pub user: bool,
    pub readable: bool,
    pub writable: bool,
    pub executable: bool,
}

impl MappingPermissions {
    pub const USER_READ_ONLY: Self = Self {
        user: true,
        readable: true,
        writable: false,
        executable: false,
    };
    pub const USER_READ_WRITE: Self = Self {
        user: true,
        readable: true,
        writable: true,
        executable: false,
    };
    pub const KERNEL_READ_EXECUTE: Self = Self {
        user: false,
        readable: true,
        writable: false,
        executable: true,
    };
    pub const KERNEL_READ_WRITE: Self = Self {
        user: false,
        readable: true,
        writable: true,
        executable: false,
    };
}

/// One expected-old/new entry mutation in an atomic publication request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryMutation {
    table: FrameAddress,
    index: usize,
    expected: u64,
    compare_mask: u64,
    replacement: u64,
    preserve_mask: u64,
}

impl EntryMutation {
    pub const fn table(self) -> FrameAddress {
        self.table
    }
    pub const fn index(self) -> usize {
        self.index
    }
    pub const fn expected(self) -> u64 {
        self.expected
    }
    pub const fn compare_mask(self) -> u64 {
        self.compare_mask
    }
    pub const fn replacement(self) -> u64 {
        self.replacement
    }
    pub const fn preserve_mask(self) -> u64 {
        self.preserve_mask
    }
}

const EMPTY_FRAME: FrameAddress = FrameAddress(0);
const EMPTY_MUTATION: EntryMutation = EntryMutation {
    table: EMPTY_FRAME,
    index: 0,
    expected: 0,
    compare_mask: u64::MAX,
    replacement: 0,
    preserve_mask: 0,
};

/// An unchanged ancestor entry that must still reach the journaled leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryAssertion {
    table: FrameAddress,
    index: usize,
    expected: u64,
    compare_mask: u64,
}

impl EntryAssertion {
    pub const fn table(self) -> FrameAddress {
        self.table
    }
    pub const fn index(self) -> usize {
        self.index
    }
    pub const fn expected(self) -> u64 {
        self.expected
    }
    pub const fn compare_mask(self) -> u64 {
        self.compare_mask
    }
}

const EMPTY_ASSERTION: EntryAssertion = EntryAssertion {
    table: EMPTY_FRAME,
    index: 0,
    expected: 0,
    compare_mask: u64::MAX,
};

/// Complete one-page publication plan supplied to the serialized backend.
pub struct MutationPlan {
    root: FrameAddress,
    page: VirtualPage,
    leaf_data: Option<FrameAddress>,
    assertions: [EntryAssertion; MAX_PATH_ASSERTIONS],
    assertion_count: usize,
    mutations: [EntryMutation; MAX_MUTATIONS],
    mutation_count: usize,
    new_tables: [FrameAddress; MAX_NEW_TABLES],
    new_table_count: usize,
}

impl MutationPlan {
    pub const fn root(&self) -> FrameAddress {
        self.root
    }
    pub const fn page(&self) -> VirtualPage {
        self.page
    }
    pub fn mutations(&self) -> &[EntryMutation] {
        &self.mutations[..self.mutation_count]
    }
    pub fn new_tables(&self) -> &[FrameAddress] {
        &self.new_tables[..self.new_table_count]
    }
    pub const fn leaf_data(&self) -> Option<FrameAddress> {
        self.leaf_data
    }
    pub fn assertions(&self) -> &[EntryAssertion] {
        &self.assertions[..self.assertion_count]
    }

    fn empty(root: FrameAddress, page: VirtualPage) -> Self {
        Self {
            root,
            page,
            leaf_data: None,
            assertions: [EMPTY_ASSERTION; MAX_PATH_ASSERTIONS],
            assertion_count: 0,
            mutations: [EMPTY_MUTATION; MAX_MUTATIONS],
            mutation_count: 0,
            new_tables: [EMPTY_FRAME; MAX_NEW_TABLES],
            new_table_count: 0,
        }
    }

    fn push_mutation(&mut self, mutation: EntryMutation) {
        debug_assert!(self.mutation_count < MAX_MUTATIONS);
        self.mutations[self.mutation_count] = mutation;
        self.mutation_count += 1;
    }

    fn push_new_table(&mut self, frame: FrameAddress) {
        debug_assert!(self.new_table_count < MAX_NEW_TABLES);
        self.new_tables[self.new_table_count] = frame;
        self.new_table_count += 1;
    }

    fn push_assertion(&mut self, assertion: EntryAssertion) {
        debug_assert!(self.assertion_count < MAX_PATH_ASSERTIONS);
        self.assertions[self.assertion_count] = assertion;
        self.assertion_count += 1;
    }
}

/// Backend failure before any page-table state may be considered committed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitError<E> {
    Access(E),
    JournalConflict,
    TableClaimRejected,
}

/// Serialized access and atomic publication for one owned page-table root.
///
/// `commit` must first authenticate `plan.root` as the uniquely owned active
/// root for this serialization domain and every journal table as a table
/// reachable from it or a newly claimed child. It must reject `leaf_data` if
/// that frame has a table role anywhere in the owned address space.
///
/// It must then, under one root-mutation lock: revalidate every mutation with
/// `(actual & compare_mask) == (expected & compare_mask)`; prove every
/// `new_table` is allocator-issued, zeroed, exclusive, and not already linked;
/// apply child-table entries before publishing their parent links while
/// preserving `actual & preserve_mask`; execute a local invalidation for
/// `plan.page`; and only then return success. Any
/// error must leave entries and frame claims exactly unchanged. Callers must
/// keep all candidate frames allocated until the result is known.
pub trait PageTableTransaction {
    type Error;

    fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error>;
    fn commit(&mut self, plan: &MutationPlan) -> Result<(), CommitError<Self::Error>>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapError<E> {
    Access(E),
    CommitConflict,
    TableClaimRejected,
    PageZero,
    UserKernelSplit,
    WritableExecutable,
    UnsupportedPermission,
    ExistingMapping,
    MissingMapping,
    ParentConflict,
    InvalidPath,
    InsufficientTableFrames,
    FrameMismatch,
}

/// A four-level root whose state can change only through an atomic backend.
#[derive(Debug, Eq, PartialEq)]
pub struct PageTableRoot {
    frame: FrameAddress,
    capabilities: PagingCapabilities,
}

impl PageTableRoot {
    /// Establishes ownership of one inactive or serialized active root.
    ///
    /// # Safety
    ///
    /// `physical_start` must name a page-table root exclusively owned by this
    /// address-space instance. Every later access must use one backend
    /// serialization domain, with APs offline and IF clear throughout the
    /// DW0-C bootstrap mutation window.
    #[allow(
        unsafe_code,
        reason = "audited ownership transfer for an architecture page-table root"
    )]
    #[allow(
        dead_code,
        reason = "DW0-C target transaction backend will become the sole root constructor"
    )]
    pub(crate) unsafe fn from_owned_root(
        physical_start: u64,
        capabilities: PagingCapabilities,
    ) -> Result<Self, AddressError> {
        Ok(Self {
            frame: FrameAddress::new(physical_start, capabilities.physical_limit())?,
            capabilities,
        })
    }

    pub const fn frame(&self) -> FrameAddress {
        self.frame
    }

    pub const fn physical_limit(&self) -> PhysicalAddressLimit {
        self.capabilities.physical_limit()
    }

    /// Maps one base page. Candidate table frames are consumed only by a
    /// successful backend commit; unused candidates remain caller-owned.
    pub fn map_page<A: PageTableTransaction>(
        &self,
        access: &mut A,
        page: VirtualPage,
        physical_start: u64,
        permissions: MappingPermissions,
        candidate_tables: &[u64],
    ) -> Result<(), MapError<A::Error>> {
        validate_mapping(page, permissions).map_err(policy_error)?;
        let physical_limit = self.physical_limit();
        let data =
            FrameAddress::new(physical_start, physical_limit).map_err(|_| MapError::InvalidPath)?;
        if data == self.frame {
            return Err(MapError::InvalidPath);
        }
        let mut candidates = [EMPTY_FRAME; MAX_NEW_TABLES];
        if candidate_tables.len() > MAX_NEW_TABLES {
            return Err(MapError::InvalidPath);
        }
        for (index, address) in candidate_tables.iter().copied().enumerate() {
            let frame =
                FrameAddress::new(address, physical_limit).map_err(|_| MapError::InvalidPath)?;
            if frame == self.frame || frame == data || candidates[..index].contains(&frame) {
                return Err(MapError::InvalidPath);
            }
            candidates[index] = frame;
        }

        let mut plan = MutationPlan::empty(self.frame, page);
        let mut current = self.frame;
        let mut current_is_new = false;
        let mut traversed = [EMPTY_FRAME; 4];
        traversed[0] = self.frame;
        let mut candidate_index = 0;
        for (depth, level) in (1..=3).rev().enumerate() {
            let traversed_count = depth + 1;
            let index = page.index(level);
            let old = if current_is_new {
                0
            } else {
                access
                    .read_entry(current, index)
                    .map_err(MapError::Access)?
            };
            let child_is_new = old == 0;
            let child = if child_is_new {
                let child = *candidates
                    .get(candidate_index)
                    .filter(|frame| **frame != EMPTY_FRAME)
                    .ok_or(MapError::InsufficientTableFrames)?;
                if traversed[..traversed_count].contains(&child) {
                    return Err(MapError::InvalidPath);
                }
                candidate_index += 1;
                plan.push_new_table(child);
                plan.push_mutation(EntryMutation {
                    table: current,
                    index,
                    expected: 0,
                    compare_mask: u64::MAX,
                    replacement: intermediate_entry(child, permissions.user),
                    preserve_mask: 0,
                });
                child
            } else {
                let child = decode_intermediate(old, permissions.user, physical_limit)
                    .map_err(|_| MapError::ParentConflict)?;
                if child == data
                    || traversed[..traversed_count].contains(&child)
                    || candidates[..candidate_tables.len()].contains(&child)
                {
                    return Err(MapError::InvalidPath);
                }
                plan.push_assertion(EntryAssertion {
                    table: current,
                    index,
                    expected: old,
                    compare_mask: !ACCESSED,
                });
                child
            };
            traversed[traversed_count] = child;
            current = child;
            current_is_new = child_is_new;
        }

        let leaf_index = page.index(0);
        let old = if current_is_new {
            0
        } else {
            access
                .read_entry(current, leaf_index)
                .map_err(MapError::Access)?
        };
        if old != 0 {
            return Err(MapError::ExistingMapping);
        }
        plan.push_mutation(EntryMutation {
            table: current,
            index: leaf_index,
            expected: 0,
            compare_mask: u64::MAX,
            replacement: leaf_entry(data, permissions),
            preserve_mask: 0,
        });
        plan.leaf_data = Some(data);
        commit(access, &plan)
    }

    /// Removes one present base-page mapping after rewalking from this root.
    pub fn unmap_page<A: PageTableTransaction>(
        &self,
        access: &mut A,
        page: VirtualPage,
    ) -> Result<FrameAddress, MapError<A::Error>> {
        validate_page_half(page)?;
        let mut plan = MutationPlan::empty(self.frame, page);
        let (leaf_table, old) = self.walk_leaf(access, page, &mut plan)?;
        let frame = decode_leaf(old, page.is_user_half(), self.physical_limit())?;
        plan.push_mutation(EntryMutation {
            table: leaf_table,
            index: page.index(0),
            expected: old,
            compare_mask: !(ACCESSED | DIRTY),
            replacement: 0,
            preserve_mask: 0,
        });
        plan.leaf_data = Some(frame);
        commit(access, &plan)?;
        Ok(frame)
    }

    /// Changes one present base-page mapping without changing its frame.
    pub fn protect_page<A: PageTableTransaction>(
        &self,
        access: &mut A,
        page: VirtualPage,
        permissions: MappingPermissions,
    ) -> Result<(), MapError<A::Error>> {
        validate_mapping(page, permissions).map_err(policy_error)?;
        let mut plan = MutationPlan::empty(self.frame, page);
        let (leaf_table, old) = self.walk_leaf(access, page, &mut plan)?;
        let frame = decode_leaf(old, permissions.user, self.physical_limit())?;
        plan.push_mutation(EntryMutation {
            table: leaf_table,
            index: page.index(0),
            expected: old,
            compare_mask: !(ACCESSED | DIRTY),
            replacement: leaf_entry(frame, permissions),
            preserve_mask: ACCESSED | DIRTY | LEAF_NON_PERMISSION_ATTRIBUTES,
        });
        plan.leaf_data = Some(frame);
        commit(access, &plan)
    }

    /// Atomically replaces one present base-page frame and its permissions.
    pub fn replace_page<A: PageTableTransaction>(
        &self,
        access: &mut A,
        page: VirtualPage,
        expected_physical_start: u64,
        replacement_physical_start: u64,
        permissions: MappingPermissions,
    ) -> Result<(), MapError<A::Error>> {
        validate_mapping(page, permissions).map_err(policy_error)?;
        let expected = FrameAddress::new(expected_physical_start, self.physical_limit())
            .map_err(|_| MapError::InvalidPath)?;
        let replacement = FrameAddress::new(replacement_physical_start, self.physical_limit())
            .map_err(|_| MapError::InvalidPath)?;
        if replacement == self.frame {
            return Err(MapError::InvalidPath);
        }
        let mut plan = MutationPlan::empty(self.frame, page);
        let (leaf_table, old) = self.walk_leaf(access, page, &mut plan)?;
        let actual = decode_leaf(old, permissions.user, self.physical_limit())?;
        if actual != expected {
            return Err(MapError::FrameMismatch);
        }
        plan.push_mutation(EntryMutation {
            table: leaf_table,
            index: page.index(0),
            expected: old,
            compare_mask: !(ACCESSED | DIRTY),
            replacement: leaf_entry(replacement, permissions),
            preserve_mask: 0,
        });
        plan.leaf_data = Some(replacement);
        commit(access, &plan)
    }

    fn walk_leaf<A: PageTableTransaction>(
        &self,
        access: &mut A,
        page: VirtualPage,
        plan: &mut MutationPlan,
    ) -> Result<(FrameAddress, u64), MapError<A::Error>> {
        let user = page.is_user_half();
        let mut current = self.frame;
        let mut traversed = [EMPTY_FRAME; 4];
        traversed[0] = current;
        for (depth, level) in (1..=3).rev().enumerate() {
            let old = access
                .read_entry(current, page.index(level))
                .map_err(MapError::Access)?;
            let child = decode_intermediate(old, user, self.physical_limit())
                .map_err(|_| MapError::InvalidPath)?;
            if traversed[..=depth].contains(&child) {
                return Err(MapError::InvalidPath);
            }
            plan.push_assertion(EntryAssertion {
                table: current,
                index: page.index(level),
                expected: old,
                compare_mask: !ACCESSED,
            });
            traversed[depth + 1] = child;
            current = child;
        }
        let old = access
            .read_entry(current, page.index(0))
            .map_err(MapError::Access)?;
        if old == 0 {
            return Err(MapError::MissingMapping);
        }
        decode_leaf(old, user, self.physical_limit())?;
        Ok((current, old))
    }
}

fn commit<A: PageTableTransaction>(
    access: &mut A,
    plan: &MutationPlan,
) -> Result<(), MapError<A::Error>> {
    access.commit(plan).map_err(|error| match error {
        CommitError::Access(error) => MapError::Access(error),
        CommitError::JournalConflict => MapError::CommitConflict,
        CommitError::TableClaimRejected => MapError::TableClaimRejected,
    })
}

/// A stack mapping with one intentionally absent page on each side.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardedStackLayout {
    pub guard_low: VirtualPage,
    pub first_stack_page: VirtualPage,
    pub page_count: u64,
    pub guard_high: VirtualPage,
}

impl GuardedStackLayout {
    pub fn new(first_stack_page: VirtualPage, page_count: u64) -> Result<Self, AddressError> {
        if page_count == 0 {
            return Err(AddressError::InvalidVirtualPage(first_stack_page.address()));
        }
        let low = first_stack_page
            .address()
            .checked_sub(PAGE_SIZE)
            .ok_or(AddressError::InvalidVirtualPage(0))?;
        let stack_bytes = page_count
            .checked_mul(PAGE_SIZE)
            .ok_or(AddressError::InvalidVirtualPage(first_stack_page.address()))?;
        let high = first_stack_page
            .address()
            .checked_add(stack_bytes)
            .ok_or(AddressError::InvalidVirtualPage(first_stack_page.address()))?;
        Ok(Self {
            guard_low: VirtualPage::new(low)?,
            first_stack_page,
            page_count,
            guard_high: VirtualPage::new(high)?,
        })
    }
}

#[derive(Clone, Copy)]
enum PolicyError {
    PageZero,
    UserKernelSplit,
    WritableExecutable,
    UnsupportedPermission,
}

fn policy_error<E>(error: PolicyError) -> MapError<E> {
    match error {
        PolicyError::PageZero => MapError::PageZero,
        PolicyError::UserKernelSplit => MapError::UserKernelSplit,
        PolicyError::WritableExecutable => MapError::WritableExecutable,
        PolicyError::UnsupportedPermission => MapError::UnsupportedPermission,
    }
}

fn validate_page_half<E>(page: VirtualPage) -> Result<(), MapError<E>> {
    if page.address() == 0 {
        return Err(MapError::PageZero);
    }
    Ok(())
}

fn validate_mapping(page: VirtualPage, permissions: MappingPermissions) -> Result<(), PolicyError> {
    if page.address() == 0 {
        return Err(PolicyError::PageZero);
    }
    if page.is_user_half() != permissions.user {
        return Err(PolicyError::UserKernelSplit);
    }
    if permissions.writable && permissions.executable {
        return Err(PolicyError::WritableExecutable);
    }
    if !permissions.readable {
        return Err(PolicyError::UnsupportedPermission);
    }
    Ok(())
}

fn intermediate_entry(frame: FrameAddress, user: bool) -> u64 {
    frame.address() | PRESENT | WRITABLE | if user { USER } else { 0 }
}

fn leaf_entry(frame: FrameAddress, permissions: MappingPermissions) -> u64 {
    frame.address()
        | PRESENT
        | if permissions.writable { WRITABLE } else { 0 }
        | if permissions.user { USER } else { 0 }
        | if permissions.executable {
            0
        } else {
            NO_EXECUTE
        }
}

fn address_mask(limit: PhysicalAddressLimit) -> u64 {
    (limit.exclusive() - PAGE_SIZE) & !(PAGE_SIZE - 1)
}

fn validate_entry_bits(entry: u64, limit: PhysicalAddressLimit) -> Result<(), ()> {
    let address = entry & !(PAGE_SIZE - 1) & !NO_EXECUTE;
    if entry & !(address_mask(limit) | PERMITTED_ENTRY_FLAGS) != 0
        || address == 0
        || address >= limit.exclusive()
    {
        return Err(());
    }
    Ok(())
}

fn decode_intermediate(
    entry: u64,
    user: bool,
    limit: PhysicalAddressLimit,
) -> Result<FrameAddress, ()> {
    validate_entry_bits(entry, limit)?;
    if entry & PRESENT == 0 || entry & HUGE != 0 || (entry & USER != 0) != user {
        return Err(());
    }
    FrameAddress::new(entry & address_mask(limit), limit).map_err(|_| ())
}

fn decode_leaf<E>(
    entry: u64,
    user: bool,
    limit: PhysicalAddressLimit,
) -> Result<FrameAddress, MapError<E>> {
    validate_entry_bits(entry, limit).map_err(|_| MapError::InvalidPath)?;
    // Bit 7 is PAT in a base-page leaf, not the intermediate huge-page bit.
    if entry & PRESENT == 0 || (entry & USER != 0) != user {
        return Err(MapError::InvalidPath);
    }
    FrameAddress::new(entry & address_mask(limit), limit).map_err(|_| MapError::InvalidPath)
}

const fn is_canonical(address: u64) -> bool {
    let sign_extended = address >> 47;
    sign_extended == 0 || sign_extended == 0x1ffff
}

#[cfg(test)]
mod tests;
