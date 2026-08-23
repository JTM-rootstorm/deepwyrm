//! Bounded, target-independent address-space residency and shootdown state.
//!
//! The state machine closes the enter-vs-mutation race without holding a lock
//! across page-table publication:
//!
//! 1. mutation preparation closes the residency gate so no new CPU can start
//!    using the old mappings;
//! 2. the architecture publisher commits page-table writes;
//! 3. successful publication snapshots the remaining residents and
//!    Release-publishes the new nonzero generation;
//! 4. targets invalidate and acknowledge that exact generation; and
//! 5. only a completed [`ReclaimPermit`] lets the enclosing mapping transaction
//!    commit lease release or reclaim backing.
//!
//! A CPU entering after step 3 Acquire-observes the published generation before
//! its caller may load the root into CR3. A CPU leaving during steps 1-4 first
//! switches away and performs local serialization, then its ordered leave both
//! acknowledges any snapshotted request and clears residency.

use super::{AddressSpaceKey, AddressSpacePublisher, Mapping, RegionKey, publisher_seal};
use crate::cpu::CpuIndex;
use crate::sync::IrqSpinMutex;
use core::marker::PhantomData;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CpuSet<const CPUS: usize> {
    members: [bool; CPUS],
}

impl<const CPUS: usize> CpuSet<CPUS> {
    const EMPTY: Self = Self {
        members: [false; CPUS],
    };

    pub(crate) const fn contains(self, cpu: CpuIndex) -> bool {
        cpu.index() < CPUS && self.members[cpu.index()]
    }

    pub(crate) fn count(self) -> usize {
        self.members.iter().filter(|member| **member).count()
    }

    pub(crate) fn iter(self) -> impl Iterator<Item = CpuIndex> {
        self.members
            .into_iter()
            .enumerate()
            .filter(|(_, member)| *member)
            .map(|(index, _)| CpuIndex::new(index).unwrap())
    }
}

/// The mapping operation whose page-table visibility is being synchronized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MappingMutation {
    Map,
    Protect,
    Unmap,
    Teardown,
}

/// The invalidation required by one mutation generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum InvalidationScope {
    Pages { start: u64, byte_len: u64 },
    FullAddressSpace,
}

impl InvalidationScope {
    pub(crate) fn pages(start: u64, byte_len: u64) -> Result<Self, AddressSpaceCoherencyError> {
        if start == 0
            || byte_len == 0
            || !start.is_multiple_of(super::PAGE_SIZE)
            || !byte_len.is_multiple_of(super::PAGE_SIZE)
            || start.checked_add(byte_len).is_none()
        {
            return Err(AddressSpaceCoherencyError::InvalidScope);
        }
        Ok(Self::Pages { start, byte_len })
    }
}

/// Exact mailbox payload acquired by a target CPU before invalidation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ShootdownRequest {
    address_space: AddressSpaceKey,
    generation: u64,
    mutation: MappingMutation,
    scope: InvalidationScope,
}

impl ShootdownRequest {
    pub(crate) const fn address_space(self) -> AddressSpaceKey {
        self.address_space
    }

    pub(crate) const fn generation(self) -> u64 {
        self.generation
    }

    pub(crate) const fn mutation(self) -> MappingMutation {
        self.mutation
    }

    pub(crate) const fn scope(self) -> InvalidationScope {
        self.scope
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AddressSpaceCoherencyError {
    CpuOutOfRange,
    AlreadyResident,
    NotResident,
    StaleResidency,
    MutationInFlight,
    GenerationExhausted,
    InvalidScope,
    StaleRequest,
    NotTarget,
    TeardownRequiresLeave,
    Retired,
}

/// Move-only proof that one CPU is published resident in this exact root.
///
/// Leaking this token leaks residency and therefore conservatively prevents
/// reclaim. The live execution carrier owns it from pre-CR3 publication until
/// post-CR3 local serialization.
#[must_use = "a live residency must be released only after switching away and locally serializing"]
pub(crate) struct Residency {
    cpu: CpuIndex,
    epoch: u64,
    observed_shootdown_generation: u64,
}

impl Residency {
    pub(crate) const fn cpu(&self) -> CpuIndex {
        self.cpu
    }

    pub(crate) const fn observed_shootdown_generation(&self) -> u64 {
        self.observed_shootdown_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LeavePublication {
    acknowledged_generation: Option<u64>,
}

impl LeavePublication {
    pub(crate) const fn acknowledged_generation(self) -> Option<u64> {
        self.acknowledged_generation
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShootdownAcknowledgement {
    Recorded,
    Duplicate,
}

#[derive(Clone, Copy)]
struct RequestState<const CPUS: usize> {
    request: ShootdownRequest,
    targets: CpuSet<CPUS>,
    acknowledged: CpuSet<CPUS>,
}

#[derive(Clone, Copy)]
enum MutationPhase<const CPUS: usize> {
    Idle,
    Prepared(RequestState<CPUS>),
    Published(RequestState<CPUS>),
    Retired,
}

struct CoherencyState<const CPUS: usize> {
    residents: CpuSet<CPUS>,
    residency_epochs: [u64; CPUS],
    shootdown_generation: u64,
    phase: MutationPhase<CPUS>,
}

impl<const CPUS: usize> CoherencyState<CPUS> {
    const fn new() -> Self {
        Self {
            residents: CpuSet::EMPTY,
            residency_epochs: [0; CPUS],
            shootdown_generation: 0,
            phase: MutationPhase::Idle,
        }
    }
}

/// One exact address-space residency set and shootdown generation domain.
pub(crate) struct AddressSpaceCoherency<const CPUS: usize> {
    address_space: AddressSpaceKey,
    state: IrqSpinMutex<CoherencyState<CPUS>>,
}

impl<const CPUS: usize> AddressSpaceCoherency<CPUS> {
    pub(crate) const fn new(address_space: AddressSpaceKey) -> Self {
        assert!(CPUS > 0, "address-space coherency requires CPU capacity");
        assert!(
            address_space.domain != 0 && address_space.raw != 0,
            "address-space coherency requires an authority-issued root identity"
        );
        Self {
            address_space,
            state: IrqSpinMutex::new(CoherencyState::new()),
        }
    }

    pub(crate) const fn address_space_key(&self) -> AddressSpaceKey {
        self.address_space
    }

    /// Release-publishes potential use of this root before the caller loads CR3.
    ///
    /// A prepared mutation rejects entry so the caller must retry. Entry during
    /// a published mutation is safe: acquiring the state observes the committed
    /// page tables and generation, and the caller is not an old-mapping target.
    /// The execution carrier pins the root before calling this method and must
    /// not hold a scheduler lock while taking this coherency lock.
    pub(crate) fn enter(&self, cpu: CpuIndex) -> Result<Residency, AddressSpaceCoherencyError> {
        let index = self.checked_cpu(cpu)?;
        let mut state = self.state.lock();
        match state.phase {
            MutationPhase::Prepared(_)
            | MutationPhase::Published(RequestState {
                request:
                    ShootdownRequest {
                        mutation: MappingMutation::Teardown,
                        ..
                    },
                ..
            }) => return Err(AddressSpaceCoherencyError::MutationInFlight),
            MutationPhase::Retired => return Err(AddressSpaceCoherencyError::Retired),
            MutationPhase::Idle | MutationPhase::Published(_) => {}
        }
        if state.residents.members[index] {
            return Err(AddressSpaceCoherencyError::AlreadyResident);
        }
        let epoch = state.residency_epochs[index]
            .checked_add(1)
            .filter(|epoch| *epoch != 0)
            .ok_or(AddressSpaceCoherencyError::GenerationExhausted)?;
        state.residency_epochs[index] = epoch;
        state.residents.members[index] = true;
        Ok(Residency {
            cpu,
            epoch,
            observed_shootdown_generation: state.shootdown_generation,
        })
    }

    /// Release-clears residency after CR3 switch-away and local serialization.
    ///
    /// If this CPU was snapshotted by a published mutation, that same
    /// serialization also satisfies its exact request before residency is
    /// cleared. Leaving during preparation removes the CPU before the later
    /// snapshot. A stale residency token cannot clear a later entry epoch.
    /// The caller releases its root pin only after this method returns.
    pub(crate) fn leave_after_local_flush(
        &self,
        residency: Residency,
    ) -> Result<LeavePublication, AddressSpaceCoherencyError> {
        let index = self.checked_cpu(residency.cpu)?;
        let mut state = self.state.lock();
        if !state.residents.members[index] {
            return Err(AddressSpaceCoherencyError::NotResident);
        }
        if state.residency_epochs[index] != residency.epoch {
            return Err(AddressSpaceCoherencyError::StaleResidency);
        }
        let acknowledged_generation = match &mut state.phase {
            MutationPhase::Published(request) if request.targets.members[index] => {
                request.acknowledged.members[index] = true;
                Some(request.request.generation)
            }
            _ => None,
        };
        state.residents.members[index] = false;
        Ok(LeavePublication {
            acknowledged_generation,
        })
    }

    /// Closes the residency gate before writes. The eventual successful
    /// publication snapshots the residents which can still use the root.
    ///
    /// Lock order is mapping/root transaction authority, then this short
    /// IRQ-safe coherency lock. The method releases the coherency lock before
    /// architecture page-table publication. No caller may acquire mapping,
    /// object, scheduler, or finalization state from a shootdown handler.
    pub(crate) fn prepare_mutation(
        &self,
        mutation: MappingMutation,
        scope: InvalidationScope,
    ) -> Result<MutationTransaction<'_, CPUS>, AddressSpaceCoherencyError> {
        self.validate_scope(scope)?;
        let mut state = self.state.lock();
        match state.phase {
            MutationPhase::Idle => {}
            MutationPhase::Retired => return Err(AddressSpaceCoherencyError::Retired),
            MutationPhase::Prepared(_) | MutationPhase::Published(_) => {
                return Err(AddressSpaceCoherencyError::MutationInFlight);
            }
        }
        let generation = state
            .shootdown_generation
            .checked_add(1)
            .filter(|generation| *generation != 0)
            .ok_or(AddressSpaceCoherencyError::GenerationExhausted)?;
        state.phase = MutationPhase::Prepared(RequestState {
            request: ShootdownRequest {
                address_space: self.address_space,
                generation,
                mutation,
                scope,
            },
            targets: CpuSet::EMPTY,
            acknowledged: CpuSet::EMPTY,
        });
        Ok(MutationTransaction {
            coherency: self,
            generation,
            active: true,
            _cpu_local: PhantomData,
        })
    }

    /// Acquire-loads this CPU's pending request for the vector `0xe2` handler.
    pub(crate) fn request_for_cpu(&self, cpu: CpuIndex) -> Option<ShootdownRequest> {
        let index = self.checked_cpu(cpu).ok()?;
        let state = self.state.lock();
        match state.phase {
            MutationPhase::Published(request)
                if request.targets.members[index] && !request.acknowledged.members[index] =>
            {
                Some(request.request)
            }
            _ => None,
        }
    }

    /// Release-publishes completion after invalidating this exact request.
    pub(crate) fn acknowledge(
        &self,
        cpu: CpuIndex,
        request: ShootdownRequest,
    ) -> Result<ShootdownAcknowledgement, AddressSpaceCoherencyError> {
        let index = self.checked_cpu(cpu)?;
        let mut state = self.state.lock();
        let MutationPhase::Published(active) = &mut state.phase else {
            return Err(AddressSpaceCoherencyError::StaleRequest);
        };
        if request != active.request {
            return Err(AddressSpaceCoherencyError::StaleRequest);
        }
        if !active.targets.members[index] {
            return Err(AddressSpaceCoherencyError::NotTarget);
        }
        if active.request.mutation == MappingMutation::Teardown {
            return Err(AddressSpaceCoherencyError::TeardownRequiresLeave);
        }
        if active.acknowledged.members[index] {
            return Ok(ShootdownAcknowledgement::Duplicate);
        }
        active.acknowledged.members[index] = true;
        Ok(ShootdownAcknowledgement::Recorded)
    }

    pub(crate) fn resident_cpus(&self) -> CpuSet<CPUS> {
        self.state.lock().residents
    }

    pub(crate) fn published_generation(&self) -> u64 {
        self.state.lock().shootdown_generation
    }

    fn checked_cpu(&self, cpu: CpuIndex) -> Result<usize, AddressSpaceCoherencyError> {
        (cpu.index() < CPUS)
            .then_some(cpu.index())
            .ok_or(AddressSpaceCoherencyError::CpuOutOfRange)
    }

    fn validate_scope(&self, scope: InvalidationScope) -> Result<(), AddressSpaceCoherencyError> {
        match scope {
            InvalidationScope::Pages { start, byte_len } => {
                InvalidationScope::pages(start, byte_len).map(|_| ())
            }
            InvalidationScope::FullAddressSpace => Ok(()),
        }
    }
}

/// Prepared mapping mutation. Dropping it before publication reopens entry.
#[must_use = "the prepared mutation must be published after page-table commit or cancelled"]
pub(crate) struct MutationTransaction<'a, const CPUS: usize> {
    coherency: &'a AddressSpaceCoherency<CPUS>,
    generation: u64,
    active: bool,
    _cpu_local: PhantomData<*mut ()>,
}

impl<'a, const CPUS: usize> MutationTransaction<'a, CPUS> {
    /// Release-publishes the request after page-table writes have completed.
    pub(crate) fn publish(mut self) -> ShootdownBarrier<'a, CPUS> {
        let mut state = self.coherency.state.lock();
        let MutationPhase::Prepared(mut request) = state.phase else {
            panic!("prepared shootdown transaction lost its generation");
        };
        if request.request.generation != self.generation {
            panic!("prepared shootdown generation changed");
        }
        request.targets = state.residents;
        state.shootdown_generation = self.generation;
        state.phase = MutationPhase::Published(request);
        self.active = false;
        ShootdownBarrier {
            coherency: self.coherency,
            request: request.request,
            targets: request.targets,
        }
    }
}

impl<const CPUS: usize> Drop for MutationTransaction<'_, CPUS> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.coherency.state.lock();
        if matches!(
            state.phase,
            MutationPhase::Prepared(request) if request.request.generation == self.generation
        ) {
            state.phase = MutationPhase::Idle;
        }
    }
}

/// Move-only barrier for one exact published request and resident snapshot.
#[must_use = "mapping lease release and root/backing reclaim require a completed barrier"]
pub(crate) struct ShootdownBarrier<'a, const CPUS: usize> {
    coherency: &'a AddressSpaceCoherency<CPUS>,
    request: ShootdownRequest,
    targets: CpuSet<CPUS>,
}

impl<const CPUS: usize> core::fmt::Debug for ShootdownBarrier<'_, CPUS> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("ShootdownBarrier")
            .field("request", &self.request)
            .field("targets", &self.targets)
            .finish_non_exhaustive()
    }
}

impl<const CPUS: usize> ShootdownBarrier<'_, CPUS> {
    pub(crate) const fn request(&self) -> ShootdownRequest {
        self.request
    }

    pub(crate) const fn targets(&self) -> CpuSet<CPUS> {
        self.targets
    }

    pub(crate) fn pending_targets(&self) -> CpuSet<CPUS> {
        let state = self.coherency.state.lock();
        match state.phase {
            MutationPhase::Published(active) if active.request == self.request => {
                let mut pending = active.targets;
                for index in 0..CPUS {
                    pending.members[index] &= !active.acknowledged.members[index];
                }
                pending
            }
            _ => self.targets,
        }
    }

    /// Acquire-observes every required acknowledgement before issuing reclaim.
    /// The coherency lock is released before the returned permit is consumed by
    /// mapping-lease release, page-table reclamation, or object finalization.
    pub(crate) fn try_complete(self) -> Result<ReclaimPermit, Self> {
        let mut state = self.coherency.state.lock();
        let MutationPhase::Published(active) = state.phase else {
            return Err(self);
        };
        if active.request != self.request {
            return Err(self);
        }
        for index in 0..CPUS {
            if active.targets.members[index] && !active.acknowledged.members[index] {
                return Err(self);
            }
        }
        state.phase = if self.request.mutation == MappingMutation::Teardown {
            if state.residents.count() != 0 {
                return Err(self);
            }
            MutationPhase::Retired
        } else {
            MutationPhase::Idle
        };
        Ok(ReclaimPermit {
            request: self.request,
            target_count: self.targets.count(),
        })
    }
}

/// Proof that the exact snapshotted CPUs acknowledged one mutation generation.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ReclaimPermit {
    request: ShootdownRequest,
    target_count: usize,
}

impl ReclaimPermit {
    pub(crate) const fn request(&self) -> ShootdownRequest {
        self.request
    }

    pub(crate) const fn target_count(&self) -> usize {
        self.target_count
    }
}

/// Injected live/host seam: send `0xe2`, then let targets service mailboxes.
pub(crate) trait ShootdownDriver<const CPUS: usize> {
    fn initiating_cpu(&self) -> CpuIndex;

    fn notify_remote(
        &mut self,
        coherency: &AddressSpaceCoherency<CPUS>,
        target: CpuIndex,
        request: ShootdownRequest,
    );

    fn wait_step(&mut self, coherency: &AddressSpaceCoherency<CPUS>);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CoherentPublishError<E> {
    Identity,
    InvalidBatch,
    Coherency(AddressSpaceCoherencyError),
    Publish(E),
}

/// AddressRegion publisher adapter that binds model commit to shootdown ack.
///
/// `P` still owns atomic page-table publication and initiating-CPU local
/// invalidations. This adapter reserves the root mutation first, publishes the
/// request only after `P` succeeds, acknowledges the initiating CPU, delivers
/// remote notifications, and does not return until it owns a reclaim permit.
pub(crate) struct CoherentAddressSpacePublisher<
    'a,
    P,
    D,
    const CPUS: usize,
    const WAIT_STEPS: usize,
> {
    publisher: &'a mut P,
    coherency: &'a AddressSpaceCoherency<CPUS>,
    driver: &'a mut D,
}

impl<'a, P, D, const CPUS: usize, const WAIT_STEPS: usize>
    CoherentAddressSpacePublisher<'a, P, D, CPUS, WAIT_STEPS>
{
    pub(crate) const fn new(
        publisher: &'a mut P,
        coherency: &'a AddressSpaceCoherency<CPUS>,
        driver: &'a mut D,
    ) -> Self {
        Self {
            publisher,
            coherency,
            driver,
        }
    }
}

impl<P, D, const CPUS: usize, const WAIT_STEPS: usize> publisher_seal::Sealed
    for CoherentAddressSpacePublisher<'_, P, D, CPUS, WAIT_STEPS>
{
}

#[allow(
    unsafe_code,
    reason = "the adapter preserves the sealed publisher identity and completes exact-generation invalidation before success"
)]
unsafe impl<P, D, const CPUS: usize, const WAIT_STEPS: usize> AddressSpacePublisher
    for CoherentAddressSpacePublisher<'_, P, D, CPUS, WAIT_STEPS>
where
    P: AddressSpacePublisher,
    D: ShootdownDriver<CPUS>,
{
    type Error = CoherentPublishError<P::Error>;

    fn address_space_key(&self) -> AddressSpaceKey {
        self.coherency.address_space_key()
    }

    fn publish_replace(
        &mut self,
        address_space: AddressSpaceKey,
        region: RegionKey,
        before: &[Mapping],
        after: &[Mapping],
    ) -> Result<(), Self::Error> {
        if address_space != self.coherency.address_space_key()
            || address_space != self.publisher.address_space_key()
        {
            return Err(CoherentPublishError::Identity);
        }
        if before == after {
            return self
                .publisher
                .publish_replace(address_space, region, before, after)
                .map_err(CoherentPublishError::Publish);
        }
        let initiating_cpu = self.driver.initiating_cpu();
        self.coherency
            .checked_cpu(initiating_cpu)
            .map_err(CoherentPublishError::Coherency)?;
        let (mutation, scope) = mutation_scope(before, after)?;
        let transaction = self
            .coherency
            .prepare_mutation(mutation, scope)
            .map_err(CoherentPublishError::Coherency)?;
        self.publisher
            .publish_replace(address_space, region, before, after)
            .map_err(CoherentPublishError::Publish)?;

        let mut barrier = transaction.publish();
        let request = barrier.request();
        if barrier.targets().contains(initiating_cpu) {
            self.coherency
                .acknowledge(initiating_cpu, request)
                .expect("initiating CPU owns the published shootdown target");
        }
        for target in barrier.targets().iter() {
            if target != initiating_cpu && self.coherency.request_for_cpu(target).is_some() {
                self.driver.notify_remote(self.coherency, target, request);
            }
        }

        match barrier.try_complete() {
            Ok(_permit) => return Ok(()),
            Err(pending) => barrier = pending,
        }
        for _ in 0..WAIT_STEPS {
            self.driver.wait_step(self.coherency);
            match barrier.try_complete() {
                Ok(_permit) => return Ok(()),
                Err(pending) => barrier = pending,
            }
        }
        panic!("address-space shootdown acknowledgement timeout");
    }
}

fn mutation_scope<E>(
    before: &[Mapping],
    after: &[Mapping],
) -> Result<(MappingMutation, InvalidationScope), CoherentPublishError<E>> {
    let before_bytes = mapping_bytes(before)?;
    let after_bytes = mapping_bytes(after)?;
    let mutation = match after_bytes.cmp(&before_bytes) {
        core::cmp::Ordering::Greater => MappingMutation::Map,
        core::cmp::Ordering::Less => MappingMutation::Unmap,
        core::cmp::Ordering::Equal => MappingMutation::Protect,
    };
    let mut start = u64::MAX;
    let mut end = 0_u64;
    for mapping in before.iter().chain(after) {
        start = start.min(mapping.virtual_start());
        end = end.max(
            mapping
                .virtual_start()
                .checked_add(mapping.byte_len())
                .ok_or(CoherentPublishError::InvalidBatch)?,
        );
    }
    if start == u64::MAX {
        return Err(CoherentPublishError::InvalidBatch);
    }
    let scope = InvalidationScope::pages(
        start,
        end.checked_sub(start)
            .ok_or(CoherentPublishError::InvalidBatch)?,
    )
    .map_err(CoherentPublishError::Coherency)?;
    Ok((mutation, scope))
}

fn mapping_bytes<E>(mappings: &[Mapping]) -> Result<u64, CoherentPublishError<E>> {
    mappings.iter().try_fold(0_u64, |total, mapping| {
        total
            .checked_add(mapping.byte_len())
            .ok_or(CoherentPublishError::InvalidBatch)
    })
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::boxed::Box;

    #[allow(
        unsafe_code,
        reason = "each leaked test authority uniquely owns its synthetic address-space identity"
    )]
    fn coherency<const CPUS: usize>() -> &'static AddressSpaceCoherency<CPUS> {
        let authority = Box::leak(Box::new(unsafe {
            super::super::AddressSpaceAuthority::<1, 1>::new()
        }));
        let space = authority.create_address_space().unwrap();
        Box::leak(Box::new(AddressSpaceCoherency::new(space)))
    }

    #[test]
    fn map_barrier_waits_for_every_snapshotted_cpu() {
        let coherency = coherency::<4>();
        let cpu0 = CpuIndex::new(0).unwrap();
        let cpu1 = CpuIndex::new(1).unwrap();
        let _cpu0_residency = coherency.enter(cpu0).unwrap();
        let _cpu1_residency = coherency.enter(cpu1).unwrap();

        let mutation = coherency
            .prepare_mutation(
                MappingMutation::Map,
                InvalidationScope::pages(super::super::PAGE_SIZE, super::super::PAGE_SIZE).unwrap(),
            )
            .unwrap();
        assert_eq!(
            coherency.enter(CpuIndex::new(2).unwrap()).err(),
            Some(AddressSpaceCoherencyError::MutationInFlight)
        );
        let barrier = mutation.publish();
        let request = barrier.request();
        assert_eq!(request.generation(), 1);
        assert_eq!(barrier.targets().count(), 2);
        assert_eq!(
            coherency.acknowledge(cpu0, request),
            Ok(ShootdownAcknowledgement::Recorded)
        );
        let barrier = barrier
            .try_complete()
            .expect_err("CPU 1 has not acknowledged");
        assert_eq!(barrier.pending_targets().count(), 1);
        assert_eq!(coherency.request_for_cpu(cpu1), Some(request));
        coherency.acknowledge(cpu1, request).unwrap();
        let permit = barrier.try_complete().unwrap();
        assert_eq!(permit.request(), request);
        assert_eq!(permit.target_count(), 2);
    }

    #[test]
    fn ordered_leave_and_post_publish_enter_close_snapshot_races() {
        let coherency = coherency::<4>();
        let cpu0 = CpuIndex::new(0).unwrap();
        let cpu1 = CpuIndex::new(1).unwrap();
        let cpu2 = CpuIndex::new(2).unwrap();
        let _resident0 = coherency.enter(cpu0).unwrap();
        let resident1 = coherency.enter(cpu1).unwrap();
        let mutation = coherency
            .prepare_mutation(
                MappingMutation::Protect,
                InvalidationScope::pages(super::super::PAGE_SIZE, super::super::PAGE_SIZE).unwrap(),
            )
            .unwrap();

        let leave = coherency.leave_after_local_flush(resident1).unwrap();
        assert_eq!(leave.acknowledged_generation(), None);
        let barrier = mutation.publish();
        let joining = coherency.enter(cpu2).unwrap();
        assert_eq!(joining.observed_shootdown_generation(), 1);
        assert!(!barrier.targets().contains(cpu2));
        coherency.acknowledge(cpu0, barrier.request()).unwrap();
        assert_eq!(barrier.try_complete().unwrap().target_count(), 1);
        assert!(coherency.resident_cpus().contains(cpu2));
    }

    #[test]
    fn stale_ack_cannot_complete_a_later_unmap_generation() {
        let coherency = coherency::<2>();
        let cpu0 = CpuIndex::new(0).unwrap();
        let _resident = coherency.enter(cpu0).unwrap();
        let first = coherency
            .prepare_mutation(
                MappingMutation::Map,
                InvalidationScope::pages(super::super::PAGE_SIZE, super::super::PAGE_SIZE).unwrap(),
            )
            .unwrap()
            .publish();
        let old_request = first.request();
        coherency.acknowledge(cpu0, old_request).unwrap();
        first.try_complete().unwrap();

        let second = coherency
            .prepare_mutation(
                MappingMutation::Unmap,
                InvalidationScope::pages(super::super::PAGE_SIZE, super::super::PAGE_SIZE).unwrap(),
            )
            .unwrap()
            .publish();
        assert_eq!(
            coherency.acknowledge(cpu0, old_request),
            Err(AddressSpaceCoherencyError::StaleRequest)
        );
        let second = second
            .try_complete()
            .expect_err("a stale acknowledgement must not release reclaim");
        coherency.acknowledge(cpu0, second.request()).unwrap();
        assert_eq!(second.try_complete().unwrap().request().generation(), 2);
    }

    #[test]
    fn teardown_reclaim_waits_for_exit_flushes() {
        let coherency = coherency::<4>();
        let cpu0 = CpuIndex::new(0).unwrap();
        let cpu1 = CpuIndex::new(1).unwrap();
        let resident0 = coherency.enter(cpu0).unwrap();
        let resident1 = coherency.enter(cpu1).unwrap();
        let barrier = coherency
            .prepare_mutation(
                MappingMutation::Teardown,
                InvalidationScope::FullAddressSpace,
            )
            .unwrap()
            .publish();
        let request = barrier.request();
        assert_eq!(
            coherency.acknowledge(cpu0, request),
            Err(AddressSpaceCoherencyError::TeardownRequiresLeave)
        );
        assert_eq!(
            coherency
                .leave_after_local_flush(resident0)
                .unwrap()
                .acknowledged_generation(),
            Some(request.generation())
        );
        let barrier = barrier
            .try_complete()
            .expect_err("the second resident still owns the root");
        coherency.leave_after_local_flush(resident1).unwrap();
        let permit = barrier.try_complete().unwrap();
        assert_eq!(permit.request().mutation(), MappingMutation::Teardown);
        assert_eq!(
            permit.request().scope(),
            InvalidationScope::FullAddressSpace
        );
        assert_eq!(coherency.resident_cpus().count(), 0);
        assert_eq!(
            coherency.enter(cpu0).err(),
            Some(AddressSpaceCoherencyError::Retired)
        );
    }

    #[test]
    fn cancelled_and_exhausted_mutations_fail_closed_without_generation_publish() {
        let coherency = coherency::<2>();
        let cpu0 = CpuIndex::new(0).unwrap();
        let prepared = coherency
            .prepare_mutation(
                MappingMutation::Protect,
                InvalidationScope::pages(super::super::PAGE_SIZE, super::super::PAGE_SIZE).unwrap(),
            )
            .unwrap();
        assert_eq!(
            coherency.enter(cpu0).err(),
            Some(AddressSpaceCoherencyError::MutationInFlight)
        );
        drop(prepared);
        let _resident = coherency.enter(cpu0).unwrap();
        assert_eq!(coherency.published_generation(), 0);

        let mut state = coherency.state.lock();
        state.shootdown_generation = u64::MAX;
        drop(state);
        assert!(matches!(
            coherency.prepare_mutation(MappingMutation::Unmap, InvalidationScope::FullAddressSpace),
            Err(AddressSpaceCoherencyError::GenerationExhausted)
        ));
        assert!(coherency.resident_cpus().contains(cpu0));
    }
}
