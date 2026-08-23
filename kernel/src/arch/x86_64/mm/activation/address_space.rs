//! Exact portable-address-space to x86 root bindings.
//!
//! A binding is the architecture proof missing from the portable
//! `AddressSpaceKey`: it couples that unforgeable key and its owning Process to
//! one typed PML4 identity. Root selection publishes residency before the CR3
//! write and retains a move-only token until the old root has been left after
//! local serialization.

use super::super::super::{FrameAddress, HUGE, PageTableRoot, USER, decode_intermediate};
use crate::arch::x86_64::mm::journal::{AtomicPageTableTarget, JournalWrite};
use crate::cpu::CpuIndex;
use crate::memory::address_region::{
    AddressSpaceCoherency, AddressSpaceCoherencyError, AddressSpaceKey, Residency,
};
use crate::memory::frame_roles::{
    EmptyTableHierarchyCandidate, FrameRoleError, FrameRoleManager, TableIdentity, TableLevel,
};
use crate::memory::physical::PhysicalAddressLimit;
use crate::memory::usercopy::{AddressSpaceTeardownReservation, UserPinTracker};
use crate::task::ProcessKey;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RootBindingError {
    Capacity,
    DuplicateAddressSpace,
    DuplicateProcess,
    Missing,
    ProcessMismatch,
    RootMismatch,
    AlreadyActive,
    CpuMismatch,
    Resident,
    MutationInFlight,
    GenerationExhausted,
    FrameRole(FrameRoleError),
}

/// Lifetime-pinned borrow of the primordial root's supervisor-only PML4 half.
///
/// These entries are copied into child-owned PML4 frames. Their descendants
/// remain owned by the primordial table owner and are never walked or reclaimed
/// as child-owned tables. Low-half publishers cannot address these indices.
pub(crate) struct KernelHalfBinding {
    primordial_identity: TableIdentity,
    entries: [u64; 256],
}

impl KernelHalfBinding {
    pub(crate) fn capture<T: AtomicPageTableTarget, const RANGES: usize, const ROLES: usize>(
        target: &mut T,
        roles: &FrameRoleManager<RANGES, ROLES>,
        root: &PageTableRoot,
        identity: TableIdentity,
    ) -> Result<Self, RootBindingError> {
        if identity.level() != TableLevel::Pml4
            || identity.physical_start() != root.frame().address()
        {
            return Err(RootBindingError::RootMismatch);
        }
        roles
            .validate_table_identity(identity)
            .map_err(RootBindingError::FrameRole)?;
        let mut entries = [0_u64; 256];
        for (offset, entry) in entries.iter_mut().enumerate() {
            *entry = target
                .read_entry(root.frame(), 256 + offset)
                .map_err(|_| RootBindingError::RootMismatch)?;
            if *entry & USER != 0 || *entry & HUGE != 0 {
                return Err(RootBindingError::RootMismatch);
            }
        }
        Ok(Self {
            primordial_identity: identity,
            entries,
        })
    }

    pub(crate) fn install<T: AtomicPageTableTarget>(
        &self,
        target: &mut T,
        child: FrameAddress,
    ) -> Result<(), RootBindingError> {
        let mut writes = [JournalWrite::new(child, 256, 0); 256];
        for (offset, entry) in self.entries.iter().copied().enumerate() {
            writes[offset] = JournalWrite::new(child, 256 + offset, entry);
        }
        target
            .apply(&writes, &[])
            .map_err(|_| RootBindingError::RootMismatch)
    }

    pub(crate) const fn primordial_identity(&self) -> TableIdentity {
        self.primordial_identity
    }
}

impl From<AddressSpaceCoherencyError> for RootBindingError {
    fn from(error: AddressSpaceCoherencyError) -> Self {
        match error {
            AddressSpaceCoherencyError::AlreadyResident => Self::AlreadyActive,
            AddressSpaceCoherencyError::MutationInFlight => Self::MutationInFlight,
            _ => Self::RootMismatch,
        }
    }
}

enum RootStorage {
    Primordial,
    Owned(PageTableRoot),
}

/// One architecture-private PML4 retained by exactly one fixed CPU slot.
///
/// It deliberately cannot name a portable address space or Process.  The low
/// half stays empty and its typed kernel half is copied from `KernelHalfBinding`
/// during construction.  Unlike a Process root it has no residency domain and
/// is never passed to usercopy, publishing, teardown, or normal reclamation.
#[derive(Debug)]
pub(crate) struct KernelExecutionRoot {
    cpu: CpuIndex,
    root: PageTableRoot,
    identity: TableIdentity,
}

impl KernelExecutionRoot {
    pub(crate) const fn cpu(&self) -> CpuIndex {
        self.cpu
    }

    pub(crate) const fn root_physical_start(&self) -> u64 {
        self.identity.physical_start()
    }

    pub(crate) const fn identity(&self) -> TableIdentity {
        self.identity
    }
}

/// Fixed, permanently retained execution roots indexed only by `CpuIndex`.
pub(crate) struct KernelExecutionRoots<const CPUS: usize> {
    roots: [Option<KernelExecutionRoot>; CPUS],
}

impl<const CPUS: usize> KernelExecutionRoots<CPUS> {
    pub(crate) const fn new() -> Self {
        assert!(CPUS > 0, "kernel execution-root capacity must be nonzero");
        Self {
            roots: [const { None }; CPUS],
        }
    }

    pub(crate) fn bind(
        &mut self,
        cpu: CpuIndex,
        root: PageTableRoot,
        identity: TableIdentity,
    ) -> Result<(), RootBindingError> {
        if identity.level() != TableLevel::Pml4
            || identity.physical_start() != root.frame().address()
            || cpu.index() >= CPUS
        {
            return Err(RootBindingError::RootMismatch);
        }
        if self
            .roots
            .get(cpu.index())
            .ok_or(RootBindingError::RootMismatch)?
            .is_some()
        {
            return Err(RootBindingError::AlreadyActive);
        }
        if self
            .roots
            .iter()
            .flatten()
            .any(|existing| existing.identity == identity || existing.root.frame() == root.frame())
        {
            return Err(RootBindingError::RootMismatch);
        }
        let slot = self
            .roots
            .get_mut(cpu.index())
            .expect("preflighted kernel execution-root slot disappeared");
        *slot = Some(KernelExecutionRoot {
            cpu,
            root,
            identity,
        });
        Ok(())
    }

    pub(crate) fn get(&self, cpu: CpuIndex) -> Result<&KernelExecutionRoot, RootBindingError> {
        self.roots
            .get(cpu.index())
            .and_then(Option::as_ref)
            .filter(|root| root.cpu == cpu)
            .ok_or(RootBindingError::Missing)
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the bounded recursive walk carries distinct target, role, proof, physical-limit, and atomic-batch authorities"
)]
fn observe_empty_owned_subtree<
    T: AtomicPageTableTarget,
    const RANGES: usize,
    const ROLES: usize,
>(
    target: &mut T,
    roles: &FrameRoleManager<RANGES, ROLES>,
    hierarchy: &mut EmptyTableHierarchyCandidate<ROLES>,
    parent: TableIdentity,
    table: FrameAddress,
    physical_limit: PhysicalAddressLimit,
    disconnects: &mut [JournalWrite; ROLES],
    disconnect_count: &mut usize,
) -> Result<(), RootBindingError> {
    for index in 0..512 {
        let entry = target
            .read_entry(table, index)
            .map_err(|_| RootBindingError::RootMismatch)?;
        if parent.level() == TableLevel::Pt {
            if entry != 0 {
                return Err(RootBindingError::RootMismatch);
            }
            continue;
        }
        if entry == 0 {
            continue;
        }
        let child_frame = decode_intermediate(entry, true, physical_limit)
            .map_err(|_| RootBindingError::RootMismatch)?;
        let child_level = parent
            .level()
            .child()
            .ok_or(RootBindingError::RootMismatch)?;
        let child = roles
            .table_identity(parent.owner(), child_level, child_frame.address())
            .map_err(RootBindingError::FrameRole)?;
        roles
            .observe_empty_table_child(hierarchy, parent, child)
            .map_err(RootBindingError::FrameRole)?;
        observe_empty_owned_subtree(
            target,
            roles,
            hierarchy,
            child,
            child_frame,
            physical_limit,
            disconnects,
            disconnect_count,
        )?;
        let write = disconnects
            .get_mut(*disconnect_count)
            .ok_or(RootBindingError::RootMismatch)?;
        *write = JournalWrite::new(table, index, 0);
        *disconnect_count += 1;
    }
    Ok(())
}

struct RootBinding<const CPUS: usize> {
    address_space: AddressSpaceKey,
    process: ProcessKey,
    identity: TableIdentity,
    storage: RootStorage,
    coherency: AddressSpaceCoherency<CPUS>,
    generation: u64,
}

/// Bounded owner of every live user root on one architecture runtime.
///
/// The primordial root remains linearly owned by `ActiveDeepPaging`; its entry
/// is an explicit marker rather than a copied root token. Child entries own
/// their `PageTableRoot` values directly.
pub(crate) struct AddressSpaceRootBindings<const SPACES: usize, const CPUS: usize> {
    entries: [Option<RootBinding<CPUS>>; SPACES],
    kernel_half: Option<KernelHalfBinding>,
    next_binding_generation: u64,
}

impl<const SPACES: usize, const CPUS: usize> AddressSpaceRootBindings<SPACES, CPUS> {
    pub(crate) const fn new() -> Self {
        assert!(SPACES > 0, "root-binding capacity must be nonzero");
        assert!(CPUS > 0, "root-binding CPU capacity must be nonzero");
        Self {
            entries: [const { None }; SPACES],
            kernel_half: None,
            next_binding_generation: 1,
        }
    }

    fn mint_binding_generation(&mut self) -> Result<u64, RootBindingError> {
        let generation = self.next_binding_generation;
        if generation == 0 {
            return Err(RootBindingError::GenerationExhausted);
        }
        self.next_binding_generation = generation.checked_add(1).unwrap_or(0);
        Ok(generation)
    }

    #[cfg(test)]
    pub(crate) fn set_next_binding_generation_for_test(&mut self, generation: u64) {
        self.next_binding_generation = generation;
    }

    pub(crate) fn install_kernel_half(
        &mut self,
        binding: KernelHalfBinding,
    ) -> Result<(), RootBindingError> {
        if self.kernel_half.is_some() {
            return Err(RootBindingError::DuplicateAddressSpace);
        }
        self.kernel_half = Some(binding);
        Ok(())
    }

    pub(crate) fn preflight_new_binding(
        &self,
        address_space: AddressSpaceKey,
        process: ProcessKey,
    ) -> Result<(), RootBindingError> {
        self.validate_new_binding(address_space, process)?;
        self.free_slot().map(|_| ())
    }

    pub(crate) fn kernel_half(&self) -> Result<&KernelHalfBinding, RootBindingError> {
        self.kernel_half.as_ref().ok_or(RootBindingError::Missing)
    }

    pub(crate) fn bind_primordial<const RANGES: usize, const ROLES: usize>(
        &mut self,
        roles: &FrameRoleManager<RANGES, ROLES>,
        address_space: AddressSpaceKey,
        process: ProcessKey,
        root: &PageTableRoot,
        identity: TableIdentity,
    ) -> Result<(), RootBindingError> {
        self.validate_new_binding(address_space, process)?;
        if identity.level() != TableLevel::Pml4
            || identity.physical_start() != root.frame().address()
        {
            return Err(RootBindingError::RootMismatch);
        }
        roles
            .validate_table_identity(identity)
            .map_err(RootBindingError::FrameRole)?;
        let slot = self.free_slot()?;
        let generation = self.mint_binding_generation()?;
        self.entries[slot] = Some(RootBinding {
            address_space,
            process,
            identity,
            storage: RootStorage::Primordial,
            coherency: AddressSpaceCoherency::new(address_space),
            generation,
        });
        Ok(())
    }

    pub(crate) fn bind_owned<const RANGES: usize, const ROLES: usize>(
        &mut self,
        roles: &FrameRoleManager<RANGES, ROLES>,
        address_space: AddressSpaceKey,
        process: ProcessKey,
        root: PageTableRoot,
        identity: TableIdentity,
    ) -> Result<(), (RootBindingError, PageTableRoot)> {
        if let Err(error) = self.validate_new_binding(address_space, process) {
            return Err((error, root));
        }
        if identity.level() != TableLevel::Pml4
            || identity.physical_start() != root.frame().address()
        {
            return Err((RootBindingError::RootMismatch, root));
        }
        if let Err(error) = roles.validate_table_identity(identity) {
            return Err((RootBindingError::FrameRole(error), root));
        }
        let slot = match self.free_slot() {
            Ok(slot) => slot,
            Err(error) => return Err((error, root)),
        };
        let generation = match self.mint_binding_generation() {
            Ok(generation) => generation,
            Err(error) => return Err((error, root)),
        };
        self.entries[slot] = Some(RootBinding {
            address_space,
            process,
            identity,
            storage: RootStorage::Owned(root),
            coherency: AddressSpaceCoherency::new(address_space),
            generation,
        });
        Ok(())
    }

    pub(crate) fn root_for_process<'a>(
        &'a self,
        primordial: &'a PageTableRoot,
        process: ProcessKey,
    ) -> Result<(&'a PageTableRoot, TableIdentity, AddressSpaceKey), RootBindingError> {
        let binding = self
            .entries
            .iter()
            .flatten()
            .find(|binding| binding.process == process)
            .ok_or(RootBindingError::Missing)?;
        let root = match &binding.storage {
            RootStorage::Primordial => primordial,
            RootStorage::Owned(root) => root,
        };
        if root.frame().address() != binding.identity.physical_start() {
            return Err(RootBindingError::RootMismatch);
        }
        Ok((root, binding.identity, binding.address_space))
    }

    pub(crate) fn active_root_for_process<'a>(
        &'a self,
        primordial: &'a PageTableRoot,
        active: &ActiveRootSelection,
        observed_cpu: CpuIndex,
        observed_root: u64,
        process: ProcessKey,
    ) -> Result<(&'a PageTableRoot, TableIdentity, AddressSpaceKey), RootBindingError> {
        if active.process != process
            || active.residency.cpu() != observed_cpu
            || active.root != observed_root
        {
            return Err(RootBindingError::RootMismatch);
        }
        let binding = self.binding(active.process, active.address_space)?;
        if binding.identity != active.identity
            || binding.identity.physical_start() != active.root
            || binding.generation != active.binding_generation
        {
            return Err(RootBindingError::RootMismatch);
        }
        binding
            .coherency
            .preflight_leave_after_local_flush(&active.residency)?;
        let root = match &binding.storage {
            RootStorage::Primordial => primordial,
            RootStorage::Owned(root) => root,
        };
        Ok((root, binding.identity, binding.address_space))
    }

    pub(crate) fn prepare_selection(
        &self,
        cpu: CpuIndex,
        process: ProcessKey,
        address_space: AddressSpaceKey,
    ) -> Result<PreparedRootSelection, RootBindingError> {
        let binding = self.binding(process, address_space)?;
        let residency = binding.coherency.enter(cpu)?;
        Ok(PreparedRootSelection {
            process,
            address_space,
            root: binding.identity.physical_start(),
            identity: binding.identity,
            residency,
            binding_generation: binding.generation,
        })
    }

    /// Completes A->B after B residency was published by `prepare_selection`.
    /// The target performs one no-PCID, no-global-pages CR3 load/full flush;
    /// only after that local serialization is A residency cleared.
    #[allow(
        clippy::result_large_err,
        reason = "the allocation-free failure path must return both move-only residency owners unchanged"
    )]
    pub(crate) fn activate_selection<T: RootSwitchTarget>(
        &self,
        prepared: PreparedRootSelection,
        previous: Option<ActiveRootSelection>,
        target: &mut T,
    ) -> Result<ActiveRootSelection, RootSelectionFailure> {
        let preflight = || {
            if target.current_cpu() != Some(prepared.residency.cpu()) {
                return Err(RootBindingError::CpuMismatch);
            }
            let next = self.binding(prepared.process, prepared.address_space)?;
            if next.identity != prepared.identity
                || next.identity.physical_start() != prepared.root
                || next.generation != prepared.binding_generation
            {
                return Err(RootBindingError::RootMismatch);
            }
            next.coherency
                .preflight_leave_after_local_flush(&prepared.residency)?;
            if previous
                .as_ref()
                .is_some_and(|active| active.address_space == prepared.address_space)
            {
                return Err(RootBindingError::AlreadyActive);
            }
            match previous.as_ref() {
                Some(previous) => {
                    if previous.residency.cpu() != prepared.residency.cpu() {
                        return Err(RootBindingError::CpuMismatch);
                    }
                    let binding = self.binding(previous.process, previous.address_space)?;
                    if binding.identity != previous.identity
                        || binding.identity.physical_start() != previous.root
                    {
                        return Err(RootBindingError::RootMismatch);
                    }
                    binding
                        .coherency
                        .preflight_leave_after_local_flush(&previous.residency)?;
                    Ok(Some(binding))
                }
                None => Ok(None),
            }
        };
        let previous_binding = match preflight() {
            Ok(binding) => binding,
            Err(error) => {
                return Err(RootSelectionFailure {
                    error,
                    prepared,
                    previous,
                });
            }
        };

        // All recoverable identity, CPU, and residency checks are complete.
        // The sealed target is infallible. The only work after CR3 is clearing
        // the exact preflighted old epoch; drift is an impossible kernel
        // invariant failure and must not be reported as a recoverable switch.
        target.load_cr3_full_flush(prepared.root);
        if let (Some(previous), Some(old)) = (previous, previous_binding) {
            old.coherency
                .leave_after_local_flush(previous.residency)
                .unwrap_or_else(|error| {
                    panic!("preflighted old-root residency drifted after CR3: {error:?}")
                });
        }
        Ok(ActiveRootSelection {
            process: prepared.process,
            address_space: prepared.address_space,
            root: prepared.root,
            identity: prepared.identity,
            residency: prepared.residency,
            binding_generation: prepared.binding_generation,
        })
    }

    /// Switches one CPU from an exact Process root to its retained
    /// architecture-private execution root. The Process residency is cleared
    /// only after the kernel-root CR3 load and local serialization.
    pub(crate) fn activate_kernel_execution_root<T: RootSwitchTarget>(
        &self,
        kernel: &KernelExecutionRoot,
        previous: ActiveRootSelection,
        target: &mut T,
    ) -> Result<ActiveKernelExecutionRoot, (RootBindingError, ActiveRootSelection)> {
        let preflight = || {
            if target.current_cpu() != Some(kernel.cpu) || previous.residency.cpu() != kernel.cpu {
                return Err(RootBindingError::CpuMismatch);
            }
            let binding = self.binding(previous.process, previous.address_space)?;
            if binding.identity != previous.identity
                || binding.identity.physical_start() != previous.root
                || binding.generation != previous.binding_generation
            {
                return Err(RootBindingError::RootMismatch);
            }
            binding
                .coherency
                .preflight_leave_after_local_flush(&previous.residency)?;
            Ok(binding)
        };
        let binding = match preflight() {
            Ok(binding) => binding,
            Err(error) => return Err((error, previous)),
        };
        target.load_cr3_full_flush(kernel.identity.physical_start());
        binding
            .coherency
            .leave_after_local_flush(previous.residency)
            .unwrap_or_else(|error| {
                panic!("preflighted Process residency drifted after kernel-root CR3: {error:?}")
            });
        Ok(ActiveKernelExecutionRoot {
            cpu: kernel.cpu,
            root: kernel.identity.physical_start(),
            identity: kernel.identity,
        })
    }

    /// Switches one CPU from its retained execution root to a prepared Process
    /// root. The prepared Process residency is already published before CR3;
    /// execution roots have no residency and remain permanently retained.
    #[allow(
        clippy::result_large_err,
        reason = "the allocation-free failure path must return both move-only selection tokens"
    )]
    pub(crate) fn activate_from_kernel_execution_root<T: RootSwitchTarget>(
        &self,
        prepared: PreparedRootSelection,
        previous: ActiveKernelExecutionRoot,
        target: &mut T,
    ) -> Result<ActiveRootSelection, KernelRootSelectionFailure> {
        let preflight = || {
            if target.current_cpu() != Some(previous.cpu)
                || prepared.residency.cpu() != previous.cpu
            {
                return Err(RootBindingError::CpuMismatch);
            }
            if target.current_root_physical_start() != Some(previous.root) {
                return Err(RootBindingError::RootMismatch);
            }
            let binding = self.binding(prepared.process, prepared.address_space)?;
            if binding.identity != prepared.identity
                || binding.identity.physical_start() != prepared.root
                || binding.generation != prepared.binding_generation
            {
                return Err(RootBindingError::RootMismatch);
            }
            binding
                .coherency
                .preflight_leave_after_local_flush(&prepared.residency)?;
            Ok(())
        };
        if let Err(error) = preflight() {
            return Err(KernelRootSelectionFailure {
                error,
                prepared,
                previous,
            });
        }
        target.load_cr3_full_flush(prepared.root);
        Ok(ActiveRootSelection {
            process: prepared.process,
            address_space: prepared.address_space,
            root: prepared.root,
            identity: prepared.identity,
            residency: prepared.residency,
            binding_generation: prepared.binding_generation,
        })
    }

    pub(crate) fn abandon_selection(
        &self,
        prepared: PreparedRootSelection,
    ) -> Result<(), RootBindingError> {
        let binding = self.binding(prepared.process, prepared.address_space)?;
        if binding.identity != prepared.identity
            || binding.identity.physical_start() != prepared.root
        {
            return Err(RootBindingError::RootMismatch);
        }
        binding
            .coherency
            .leave_after_local_flush(prepared.residency)
            .map(|_| ())
            .map_err(RootBindingError::from)
    }

    /// Retires and returns one non-primordial, empty, nonresident root.
    #[allow(
        unsafe_code,
        reason = "the completed H0 teardown barrier discharges the empty-root reclaim proof"
    )]
    pub(crate) fn teardown_empty_owned<
        const RANGES: usize,
        const ROLES: usize,
        const PINS: usize,
        T: AtomicPageTableTarget,
    >(
        &mut self,
        roles: &mut FrameRoleManager<RANGES, ROLES>,
        target: &mut T,
        process: ProcessKey,
        address_space: AddressSpaceKey,
        pins: &UserPinTracker<PINS>,
        reservation: AddressSpaceTeardownReservation<'_, PINS>,
    ) -> Result<(), RootBindingError> {
        if !pins.owns_teardown_reservation(&reservation) || !reservation.covers(address_space) {
            return Err(RootBindingError::RootMismatch);
        }
        let slot = self.binding_slot(process, address_space)?;
        let binding = self.entries[slot]
            .as_ref()
            .expect("binding slot remains live");
        let root = match &binding.storage {
            RootStorage::Primordial => return Err(RootBindingError::RootMismatch),
            RootStorage::Owned(root) => root,
        };
        let transaction = binding
            .coherency
            .prepare_uncontended_teardown()
            .map_err(|error| match error {
                AddressSpaceCoherencyError::TeardownRequiresLeave => RootBindingError::Resident,
                error => RootBindingError::from(error),
            })?;

        let mut hierarchy = roles
            .begin_empty_table_hierarchy(binding.identity)
            .map_err(RootBindingError::FrameRole)?;
        let mut disconnects = [JournalWrite::new(root.frame(), 0, 0); ROLES];
        let mut disconnect_count = 0;
        for index in 0..256 {
            let entry = target
                .read_entry(root.frame(), index)
                .map_err(|_| RootBindingError::RootMismatch)?;
            if entry == 0 {
                continue;
            }
            let child_frame = decode_intermediate(entry, true, root.physical_limit())
                .map_err(|_| RootBindingError::RootMismatch)?;
            let child = roles
                .table_identity(
                    binding.identity.owner(),
                    TableLevel::Pdpt,
                    child_frame.address(),
                )
                .map_err(RootBindingError::FrameRole)?;
            roles
                .observe_empty_table_child(&mut hierarchy, binding.identity, child)
                .map_err(RootBindingError::FrameRole)?;
            observe_empty_owned_subtree(
                target,
                roles,
                &mut hierarchy,
                child,
                child_frame,
                root.physical_limit(),
                &mut disconnects,
                &mut disconnect_count,
            )?;
            let write = disconnects
                .get_mut(disconnect_count)
                .ok_or(RootBindingError::RootMismatch)?;
            *write = JournalWrite::new(root.frame(), index, 0);
            disconnect_count += 1;
        }
        let hierarchy = roles
            .finish_empty_table_hierarchy(hierarchy)
            .map_err(RootBindingError::FrameRole)?;
        target
            .apply(&disconnects[..disconnect_count], &[])
            .map_err(|_| RootBindingError::RootMismatch)?;

        // The successful atomic root disconnect is the irreversible boundary.
        // Zero residency and the closed gate make barrier completion infallible;
        // returning a recoverable error after this point would poison teardown.
        let barrier = transaction.publish();
        let _permit = barrier
            .try_complete()
            .unwrap_or_else(|_| panic!("zero-resident teardown barrier became incomplete"));
        let empty_root = unsafe { roles.reclaim_preflighted_empty_table_hierarchy(hierarchy) };
        unsafe {
            roles.reclaim_preflighted_empty_table_root(empty_root);
        }
        self.entries[slot] = None;
        Ok(())
    }

    fn binding(
        &self,
        process: ProcessKey,
        address_space: AddressSpaceKey,
    ) -> Result<&RootBinding<CPUS>, RootBindingError> {
        let slot = self.binding_slot(process, address_space)?;
        Ok(self.entries[slot]
            .as_ref()
            .expect("binding slot remains live"))
    }

    fn binding_slot(
        &self,
        process: ProcessKey,
        address_space: AddressSpaceKey,
    ) -> Result<usize, RootBindingError> {
        let Some((slot, binding)) = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(slot, binding)| binding.as_ref().map(|binding| (slot, binding)))
            .find(|(_, binding)| binding.address_space == address_space)
        else {
            return Err(RootBindingError::Missing);
        };
        if binding.process != process {
            return Err(RootBindingError::ProcessMismatch);
        }
        Ok(slot)
    }

    fn validate_new_binding(
        &self,
        address_space: AddressSpaceKey,
        process: ProcessKey,
    ) -> Result<(), RootBindingError> {
        if self
            .entries
            .iter()
            .flatten()
            .any(|binding| binding.address_space == address_space)
        {
            return Err(RootBindingError::DuplicateAddressSpace);
        }
        if self
            .entries
            .iter()
            .flatten()
            .any(|binding| binding.process == process)
        {
            return Err(RootBindingError::DuplicateProcess);
        }
        Ok(())
    }

    fn free_slot(&self) -> Result<usize, RootBindingError> {
        self.entries
            .iter()
            .position(Option::is_none)
            .ok_or(RootBindingError::Capacity)
    }
}

#[must_use = "prepared root residency must be activated or explicitly abandoned"]
#[derive(Debug)]
pub(crate) struct PreparedRootSelection {
    process: ProcessKey,
    address_space: AddressSpaceKey,
    root: u64,
    identity: TableIdentity,
    residency: Residency,
    binding_generation: u64,
}

impl PreparedRootSelection {
    pub(crate) const fn cpu(&self) -> CpuIndex {
        self.residency.cpu()
    }

    pub(crate) const fn binding_generation(&self) -> u64 {
        self.binding_generation
    }
}

/// Recoverable pre-CR3 rejection with every move-only residency token returned
/// unchanged. No `RootSelectionFailure` can be constructed after CR3.
#[must_use = "failed root selection retains the prepared and previous residency owners"]
pub(crate) struct RootSelectionFailure {
    error: RootBindingError,
    prepared: PreparedRootSelection,
    previous: Option<ActiveRootSelection>,
}

impl RootSelectionFailure {
    pub(crate) const fn error(&self) -> RootBindingError {
        self.error
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        RootBindingError,
        PreparedRootSelection,
        Option<ActiveRootSelection>,
    ) {
        (self.error, self.prepared, self.previous)
    }
}

#[must_use = "active root residency must be carried across the next switch"]
#[derive(Debug)]
pub(crate) struct ActiveRootSelection {
    process: ProcessKey,
    address_space: AddressSpaceKey,
    root: u64,
    identity: TableIdentity,
    residency: Residency,
    binding_generation: u64,
}

/// CPU-private token proving that this CPU is executing its retained kernel
/// execution root. It has no portable address-space identity or residency.
#[must_use = "kernel execution-root selection must be carried into the next switch"]
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ActiveKernelExecutionRoot {
    cpu: CpuIndex,
    root: u64,
    identity: TableIdentity,
}

impl ActiveKernelExecutionRoot {
    pub(crate) const fn cpu(&self) -> CpuIndex {
        self.cpu
    }

    pub(crate) const fn root_physical_start(&self) -> u64 {
        self.root
    }
}

#[cfg(test)]
impl KernelExecutionRoot {
    pub(super) const fn test_assume_active(&self) -> ActiveKernelExecutionRoot {
        ActiveKernelExecutionRoot {
            cpu: self.cpu,
            root: self.identity.physical_start(),
            identity: self.identity,
        }
    }
}

/// Recoverable kernel->Process pre-CR3 failure retaining both selections.
#[must_use = "failed kernel-to-process switch retains both selection tokens"]
pub(crate) struct KernelRootSelectionFailure {
    error: RootBindingError,
    prepared: PreparedRootSelection,
    previous: ActiveKernelExecutionRoot,
}

impl KernelRootSelectionFailure {
    pub(crate) const fn error(&self) -> RootBindingError {
        self.error
    }

    pub(crate) fn into_parts(
        self,
    ) -> (
        RootBindingError,
        PreparedRootSelection,
        ActiveKernelExecutionRoot,
    ) {
        (self.error, self.prepared, self.previous)
    }
}

impl ActiveRootSelection {
    pub(crate) const fn process(&self) -> ProcessKey {
        self.process
    }

    pub(crate) const fn address_space(&self) -> AddressSpaceKey {
        self.address_space
    }

    pub(crate) const fn root_physical_start(&self) -> u64 {
        self.root
    }

    pub(crate) const fn identity(&self) -> TableIdentity {
        self.identity
    }

    pub(crate) const fn binding_generation(&self) -> u64 {
        self.binding_generation
    }

    /// Derives a stop identity from the current active selection rather than
    /// accepting a caller-supplied root epoch.
    pub(crate) fn stop_identity(
        &self,
        cpu_online_generation: u64,
        claim: crate::task::SchedulerExecutionClaim,
    ) -> Result<
        crate::arch::x86_64::rendezvous::StopIdentity,
        crate::arch::x86_64::rendezvous::StopIdentityError,
    > {
        if claim.cpu() != self.cpu() {
            return Err(crate::arch::x86_64::rendezvous::StopIdentityError::InvalidCpu);
        }
        crate::arch::x86_64::rendezvous::StopIdentity::from_scheduler_claim(
            cpu_online_generation,
            claim,
            self.binding_generation,
        )
    }

    pub(crate) const fn cpu(&self) -> CpuIndex {
        self.residency.cpu()
    }

    pub(crate) fn selects_exact(
        &self,
        cpu: CpuIndex,
        process: ProcessKey,
        address_space: AddressSpaceKey,
    ) -> bool {
        self.residency.cpu() == cpu
            && self.process == process
            && self.address_space == address_space
    }
}

#[cfg(test)]
impl PreparedRootSelection {
    pub(super) fn test_assume_active(self) -> ActiveRootSelection {
        ActiveRootSelection {
            process: self.process,
            address_space: self.address_space,
            root: self.root,
            identity: self.identity,
            residency: self.residency,
            binding_generation: self.binding_generation,
        }
    }
}

#[cfg(test)]
impl ActiveRootSelection {
    pub(super) fn test_with_address_space(mut self, address_space: AddressSpaceKey) -> Self {
        self.address_space = address_space;
        self
    }

    pub(super) fn test_with_root(mut self, root: u64) -> Self {
        self.root = root;
        self
    }
}

pub(super) mod root_switch_seal {
    pub trait Sealed {}
}

/// Injected architecture seam for the exact full-flush CR3 publication.
///
/// # Safety
///
/// Implementations must load the supplied physical PML4 as CR3, provide the
/// local serialization/full flush required by the no-PCID/no-global-pages
/// profile, and return only after the new root is usable on this CPU.
#[allow(
    unsafe_code,
    reason = "CR3 publication and local TLB serialization are architecture facts"
)]
pub(crate) unsafe trait RootSwitchTarget: root_switch_seal::Sealed {
    /// Returns the architecture/carrier CPU on which `load_cr3_full_flush`
    /// would execute. `None` is a fail-closed unbound carrier.
    fn current_cpu(&self) -> Option<CpuIndex>;

    /// Returns the currently active CR3 PML4 frame when it can be observed.
    /// Kernel-root token consumption requires this exact check before its next
    /// Process switch; an unknown value is fail-closed for that transition.
    fn current_root_physical_start(&self) -> Option<u64>;

    fn load_cr3_full_flush(&mut self, root_physical_start: u64);
}
