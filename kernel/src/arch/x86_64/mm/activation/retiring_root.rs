//! Tearing down a retiring root by whole mappings, then by tables (DW2
//! §10.14 revision 2).
//!
//! A dead Process's owed teardown first moves its root's binding one way
//! into retiring (item 0): no CPU can enter it again, and none is resident.
//! With PCID and global pages off, no CPU can then walk the root or hold
//! anything cached from it, so its leaves need not be cleared: the region
//! releases each mapping's leases without touching the tables (item 1,
//! [`RetiringRootPublisher`]), then the tables are freed bottom-up, a page
//! table without being read (item 2,
//! [`AddressSpaceRootBindings::teardown_tables_step`]), and last the root
//! (item 3, [`AddressSpaceRootBindings::teardown_empty_owned_settled`]).

use super::super::super::super::{FrameAddress, HUGE, PageTableRoot, decode_intermediate};
use super::{AddressSpaceRootBindings, RootBinding, RootBindingError, RootStorage};
use crate::arch::x86_64::mm::journal::{AtomicPageTableTarget, JournalWrite};
use crate::memory::address_region::{
    AddressSpaceCoherencyError, AddressSpaceKey, DetachedTeardown, detached_seal,
};
use crate::memory::frame_roles::{FrameRoleManager, TableIdentity, TableLevel};
use crate::memory::usercopy::{AddressSpaceTeardownReservation, UserPinTracker};
use crate::task::{ProcessKey, ProcessQuiescenceProof};

/// The most tables one teardown step frees (DW2 §10.14 revision 2 item 2).
pub(crate) const TEARDOWN_STEP_TABLES: u32 = 64;

/// The table entries one teardown step reads before it stops, once it has
/// freed a table (DW2 §10.14 revision 2 item 2 and its progress rule).
pub(crate) const TEARDOWN_STEP_ENTRIES: u32 = 512;

/// The most entries a step reads before its first free: every PML4 user
/// entry, then a whole PDPT and a whole PD (the progress rule).
pub(crate) const TEARDOWN_FIRST_FREE_ENTRIES: u32 = 256 + 512 + 512;

/// What one table step of a retiring root did.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TableTeardownStep {
    freed: u32,
    read: u32,
    remaining: bool,
}

impl TableTeardownStep {
    /// Tables freed.
    pub(crate) const fn freed(self) -> u32 {
        self.freed
    }

    /// Table entries read.
    pub(crate) const fn read(self) -> u32 {
        self.read
    }

    /// Whether committed tables remain below the root.
    pub(crate) const fn remaining(self) -> bool {
        self.remaining
    }
}

/// The sealed teardown publisher of DW2 §10.14 revision 2 item 1: it stands
/// for one owned, retiring root with no CPU resident, and publishes nothing.
/// Only [`AddressSpaceRootBindings::retiring_teardown_publisher`] builds one,
/// from a Process quiescence proof, and it borrows the bindings, so it lives
/// no longer than the paging lock hold that checked the root.
pub(crate) struct RetiringRootPublisher<'bindings> {
    address_space: AddressSpaceKey,
    _bindings: core::marker::PhantomData<&'bindings ()>,
}

impl detached_seal::Sealed for RetiringRootPublisher<'_> {}

#[allow(
    unsafe_code,
    reason = "the retiring, zero-resident binding check discharges the detached-teardown contract"
)]
// SAFETY: built only by `retiring_teardown_publisher`, which requires an
// owned binding for this exact key that is retiring with no CPU resident;
// retiring is one way and refuses every later entry, and the borrow of the
// bindings keeps the binding from being retired while this value lives.
unsafe impl DetachedTeardown for RetiringRootPublisher<'_> {
    fn address_space_key(&self) -> AddressSpaceKey {
        self.address_space
    }
}

/// How an owed teardown step found its root (DW2 §10.14 revision 2 item 0,
/// §10.17 B-1): retiring and free to work on, or not yet, with the reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TeardownStepStart {
    /// The root is retiring with no CPU resident: the step does its work.
    Retiring,
    /// A CPU is still resident: the step does nothing; its leave queues the
    /// root again.
    Resident,
    /// A mutation published on the root before it was queued has not
    /// completed: the step does nothing and the root stays queued. The
    /// mutation's initiator completes it on its own CPU, holding only the
    /// shootdown-initiator lock S, so no hold of this CPU is needed for it.
    MutationInFlight,
}

/// One table on the step's path down from the root.
#[derive(Clone, Copy)]
struct Level {
    table: TableIdentity,
    frame: FrameAddress,
    next: usize,
    end: usize,
}

impl<const SPACES: usize, const CPUS: usize> AddressSpaceRootBindings<SPACES, CPUS> {
    /// Moves `process`'s owned root one way into retiring (DW2 §10.14
    /// revision 2 item 0): from then on no CPU may enter it and no mutation
    /// may be prepared on it. It requires zero residents in the same
    /// coherency hold. The primordial root is refused. Repeating it is
    /// accepted.
    pub(crate) fn begin_retiring(
        &self,
        process: ProcessKey,
        address_space: AddressSpaceKey,
    ) -> Result<(), RootBindingError> {
        let binding = self.binding(process, address_space)?;
        match &binding.storage {
            RootStorage::Primordial => return Err(RootBindingError::RootMismatch),
            RootStorage::Owned(_) => {}
        }
        binding.coherency.begin_retiring().map_err(|error| {
            if error == AddressSpaceCoherencyError::TeardownRequiresLeave {
                RootBindingError::Resident
            } else {
                RootBindingError::from(error)
            }
        })
    }

    /// The start of one owed teardown step (§10.17 B-1): moves the root
    /// into retiring if it can, or names what holds it back, a CPU resident
    /// or a mutation still in flight, in which case nothing changes. Any
    /// other refusal is returned as an error.
    pub(crate) fn begin_teardown_step(
        &self,
        process: ProcessKey,
        address_space: AddressSpaceKey,
    ) -> Result<TeardownStepStart, RootBindingError> {
        let begun = self.begin_retiring(process, address_space);
        if begun == Err(RootBindingError::Resident) {
            Ok(TeardownStepStart::Resident)
        } else if begun == Err(RootBindingError::MutationInFlight) {
            Ok(TeardownStepStart::MutationInFlight)
        } else {
            begun.map(|()| TeardownStepStart::Retiring)
        }
    }

    /// Whether `process`'s root is retiring.
    pub(crate) fn is_retiring(
        &self,
        process: ProcessKey,
        address_space: AddressSpaceKey,
    ) -> Result<bool, RootBindingError> {
        Ok(self
            .binding(process, address_space)?
            .coherency
            .is_retiring())
    }

    /// The sealed teardown publisher for `process`'s root (DW2 §10.14
    /// revision 2 item 1), from its quiescence proof: refused for the
    /// primordial root, a root not retiring, or one with a CPU resident.
    pub(crate) fn retiring_teardown_publisher(
        &self,
        process: ProcessKey,
        address_space: AddressSpaceKey,
        proof: &ProcessQuiescenceProof,
    ) -> Result<RetiringRootPublisher<'_>, RootBindingError> {
        if proof.process() != process {
            return Err(RootBindingError::ProcessMismatch);
        }
        self.retiring_binding(process, address_space)?;
        Ok(RetiringRootPublisher {
            address_space,
            _bindings: core::marker::PhantomData,
        })
    }

    /// One table step of a retiring root's teardown (DW2 §10.14 revision 2
    /// item 2, with its progress rule). It rebuilds its place from the
    /// tables: the first non-zero PML4 user entry, then the first non-zero
    /// entry of the PDPT and PD below it. A page table is freed without
    /// being read; a PD or PDPT is read, and freed once every entry is
    /// zero. Each freed table's entry in its parent is cleared. A large
    /// leaf is refused. The step stops after `TEARDOWN_STEP_TABLES` frees,
    /// or once it has read `TEARDOWN_STEP_ENTRIES` entries and freed at
    /// least one table, so it always frees one when any remains, within
    /// `TEARDOWN_FIRST_FREE_ENTRIES` reads, and keeps nothing between
    /// steps. The pin reservation is held for this step only. Charges are
    /// untouched. An error after a free leaves the earlier frees done.
    #[allow(
        unsafe_code,
        reason = "the retiring, zero-resident binding discharges the per-table reclaim contract"
    )]
    pub(crate) fn teardown_tables_step<
        const RANGES: usize,
        const ROLES: usize,
        const PINS: usize,
        T: AtomicPageTableTarget,
    >(
        &self,
        roles: &mut FrameRoleManager<RANGES, ROLES>,
        target: &mut T,
        process: ProcessKey,
        address_space: AddressSpaceKey,
        pins: &UserPinTracker<PINS>,
        reservation: AddressSpaceTeardownReservation<'_, PINS>,
    ) -> Result<TableTeardownStep, RootBindingError> {
        if !pins.owns_teardown_reservation(&reservation) || !reservation.covers(address_space) {
            return Err(RootBindingError::RootMismatch);
        }
        let (binding, root_table) = self.retiring_binding(process, address_space)?;
        let root = binding.identity;
        let limit = root_table.physical_limit();
        let count = |roles: &FrameRoleManager<RANGES, ROLES>| {
            roles
                .hierarchy_table_count(root)
                .map_err(RootBindingError::FrameRole)
        };
        let mut step = TableTeardownStep {
            freed: 0,
            read: 0,
            remaining: count(roles)? != 0,
        };
        if !step.remaining {
            return Ok(step);
        }
        let mut path = [None::<Level>; 3];
        path[0] = Some(Level {
            table: root,
            frame: root_table.frame(),
            next: 0,
            end: 256,
        });
        let mut depth = 0_usize;
        loop {
            if step.freed >= 1
                && (step.freed >= TEARDOWN_STEP_TABLES || step.read >= TEARDOWN_STEP_ENTRIES)
            {
                break;
            }
            let level = path[depth].expect("the step's path is filled to its depth");
            if level.next == level.end {
                let Some(above) = depth.checked_sub(1) else {
                    // Every user entry of the root is zero: no table can
                    // remain unless a record no entry names does.
                    if count(roles)? != 0 {
                        return Err(RootBindingError::RootMismatch);
                    }
                    break;
                };
                let parent = path[above].expect("a table on the path has its parent");
                free_retiring_table(roles, target, root, parent, level.table)?;
                step.freed += 1;
                depth = above;
                if let Some(parent) = path[depth].as_mut() {
                    parent.next += 1;
                }
                continue;
            }
            let entry = target
                .read_entry(level.frame, level.next)
                .map_err(|_| RootBindingError::RootMismatch)?;
            step.read += 1;
            if entry == 0 {
                if let Some(level) = path[depth].as_mut() {
                    level.next += 1;
                }
                continue;
            }
            if entry & HUGE != 0 {
                return Err(RootBindingError::LargeLeaf);
            }
            let child_frame = decode_intermediate(entry, true, limit)
                .map_err(|_| RootBindingError::RootMismatch)?;
            let child_level = level
                .table
                .level()
                .child()
                .ok_or(RootBindingError::RootMismatch)?;
            let child = roles
                .table_identity(root.owner(), child_level, child_frame.address())
                .map_err(RootBindingError::FrameRole)?;
            if child_level == TableLevel::Pt {
                // A page table is freed unread: its leaves name object
                // frames, which their leases' releases own, never it.
                free_retiring_table(roles, target, root, level, child)?;
                step.freed += 1;
                if let Some(level) = path[depth].as_mut() {
                    level.next += 1;
                }
                continue;
            }
            depth += 1;
            path[depth] = Some(Level {
                table: child,
                frame: child_frame,
                next: 0,
                end: 512,
            });
        }
        step.remaining = count(roles)? != 0;
        Ok(step)
    }

    /// The owned, retiring binding of `process` with no CPU resident, and
    /// its root.
    fn retiring_binding(
        &self,
        process: ProcessKey,
        address_space: AddressSpaceKey,
    ) -> Result<(&RootBinding<CPUS>, &PageTableRoot), RootBindingError> {
        let binding = self.binding(process, address_space)?;
        let root = match &binding.storage {
            RootStorage::Primordial => return Err(RootBindingError::RootMismatch),
            RootStorage::Owned(root) => root,
        };
        if !binding.coherency.is_retiring() {
            return Err(RootBindingError::NotRetiring);
        }
        if binding.coherency.resident_cpus().count() != 0 {
            return Err(RootBindingError::Resident);
        }
        Ok((binding, root))
    }
}

/// Frees `table`, the child named by `parent`'s entry `parent.next`, and
/// clears that entry. The role checks run first, so a refusal changes
/// nothing.
#[allow(
    unsafe_code,
    reason = "forwards the retiring-root contract its caller checked to per-table reclaim"
)]
fn free_retiring_table<const RANGES: usize, const ROLES: usize, T: AtomicPageTableTarget>(
    roles: &mut FrameRoleManager<RANGES, ROLES>,
    target: &mut T,
    root: TableIdentity,
    parent: Level,
    table: TableIdentity,
) -> Result<(), RootBindingError> {
    roles
        .check_retiring_table(root, parent.table, table)
        .map_err(RootBindingError::FrameRole)?;
    target
        .apply(&[JournalWrite::new(parent.frame, parent.next, 0)], &[])
        .map_err(|_| RootBindingError::RootMismatch)?;
    // SAFETY: the caller checked, under this borrow of the bindings, that
    // `root`'s binding is owned and retiring with no CPU resident, and
    // retiring refuses every later entry, so no CPU walks the root or holds
    // anything cached from it. The parent's entry naming `table` was
    // cleared just above.
    unsafe { roles.reclaim_retiring_table(root, parent.table, table) }
        .unwrap_or_else(|error| panic!("a checked retiring table's reclaim drifted: {error:?}"));
    Ok(())
}

#[cfg(test)]
#[path = "retiring_root_tests.rs"]
mod tests;
