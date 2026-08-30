use core::sync::atomic::{AtomicU64, Ordering};

use deepwyrm_abi::DwDeviceResourceKind;

use crate::object::{InternalRef, ObjectId};
use crate::sync::SpinMutex;
#[cfg(deepwyrm_integrated)]
use crate::task::TaskGroupKey;

pub(crate) const MAX_BOOT_RESOURCE_GRANTS: usize = 8;

static NEXT_GRANT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Immutable, copied device authority admitted from the boot-device carrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BootResourceDescriptor {
    pub(crate) resource_id: u64,
    pub(crate) device_correlation_id: u64,
    pub(crate) kind: DwDeviceResourceKind,
    pub(crate) pio_base: u16,
    pub(crate) pio_length: u16,
    pub(crate) interrupt_source: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootResourceGrantState {
    Available,
    Reserved {
        lease_generation: u64,
    },
    Leased {
        object: ObjectId,
        lease_generation: u64,
    },
}

/// One kernel-internal grant. D5 supplies its owner and lease transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BootResourceGrant {
    descriptor: BootResourceDescriptor,
    grant_generation: u64,
    state: BootResourceGrantState,
}

impl BootResourceGrant {
    #[cfg(any(test, deepwyrm_dw1d_evidence))]
    #[allow(
        dead_code,
        reason = "selector-30 consumes this only in the target runtime"
    )]
    pub(crate) const fn descriptor(self) -> BootResourceDescriptor {
        self.descriptor
    }

    #[cfg(test)]
    pub(crate) const fn grant_generation(self) -> u64 {
        self.grant_generation
    }

    #[cfg(test)]
    pub(crate) const fn state(self) -> BootResourceGrantState {
        self.state
    }
}

/// Fixed-capacity, validate-all/publish-all boot grant snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BootResourceGrants {
    grants: [Option<BootResourceGrant>; MAX_BOOT_RESOURCE_GRANTS],
    count: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BootResourceGrantError {
    Capacity,
    GenerationExhausted,
}

impl BootResourceGrants {
    pub(crate) const fn empty() -> Self {
        Self {
            grants: [None; MAX_BOOT_RESOURCE_GRANTS],
            count: 0,
        }
    }

    /// Mints generations only after the caller has validated every descriptor.
    pub(crate) fn materialize(
        descriptors: &[BootResourceDescriptor],
    ) -> Result<Self, BootResourceGrantError> {
        if descriptors.len() > MAX_BOOT_RESOURCE_GRANTS {
            return Err(BootResourceGrantError::Capacity);
        }
        if descriptors.is_empty() {
            return Ok(Self::empty());
        }

        let generation_count =
            u64::try_from(descriptors.len()).map_err(|_| BootResourceGrantError::Capacity)?;
        let first_generation = NEXT_GRANT_GENERATION
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
                if next == 0 {
                    return None;
                }
                next.checked_add(generation_count)
            })
            .map_err(|_| BootResourceGrantError::GenerationExhausted)?;

        let mut grants = [None; MAX_BOOT_RESOURCE_GRANTS];
        for (index, descriptor) in descriptors.iter().copied().enumerate() {
            let offset = u64::try_from(index).map_err(|_| BootResourceGrantError::Capacity)?;
            let grant_generation = first_generation
                .checked_add(offset)
                .ok_or(BootResourceGrantError::GenerationExhausted)?;
            grants[index] = Some(BootResourceGrant {
                descriptor,
                grant_generation,
                state: BootResourceGrantState::Available,
            });
        }

        Ok(Self {
            grants,
            count: descriptors.len(),
        })
    }

    #[cfg(any(test, deepwyrm_dw1d_evidence))]
    #[allow(
        dead_code,
        reason = "selector-30 consumes this only in the target runtime"
    )]
    pub(crate) const fn len(self) -> usize {
        self.count
    }

    pub(crate) const fn is_empty(self) -> bool {
        self.count == 0
    }

    #[cfg(any(test, deepwyrm_dw1d_evidence))]
    #[allow(
        dead_code,
        reason = "selector-30 consumes this only in the target runtime"
    )]
    pub(crate) fn grant(self, index: usize) -> Option<BootResourceGrant> {
        if index >= self.count {
            return None;
        }
        self.grants[index]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    dead_code,
    reason = "owner binding is consumed by the freestanding primordial profile"
)]
#[cfg(deepwyrm_integrated)]
pub(crate) enum BootResourceLeaseError {
    OwnerAlreadyBound,
    OwnerNotBound,
    GrantNotAvailable,
    UnknownResource,
    AlreadyLeased,
    GenerationExhausted,
    StaleReservation,
    FinalizationMismatch,
}

#[must_use = "a reserved boot-resource grant must be committed or cancelled"]
#[cfg(deepwyrm_integrated)]
pub(crate) struct BootResourceLeaseReservation {
    resource_id: u64,
    grant_generation: u64,
    lease_generation: u64,
}

#[cfg(deepwyrm_integrated)]
impl BootResourceLeaseReservation {
    pub(crate) const fn grant_generation(&self) -> u64 {
        self.grant_generation
    }

    pub(crate) const fn lease_generation(&self) -> u64 {
        self.lease_generation
    }
}

#[cfg(deepwyrm_integrated)]
struct BootResourceGrantAuthorityState {
    grants: BootResourceGrants,
    owner: Option<(TaskGroupKey, InternalRef)>,
    next_lease_generation: u64,
}

/// Kernel-lifetime owner of validated boot grants and their exact leases.
#[cfg(deepwyrm_integrated)]
pub(crate) struct BootResourceGrantAuthority {
    state: SpinMutex<BootResourceGrantAuthorityState>,
}

#[cfg(deepwyrm_integrated)]
impl BootResourceGrantAuthority {
    #[allow(
        dead_code,
        reason = "constructed by the freestanding primordial runtime and focused host tests"
    )]
    pub(crate) fn new(grants: BootResourceGrants) -> Self {
        Self {
            state: SpinMutex::new(BootResourceGrantAuthorityState {
                grants,
                owner: None,
                next_lease_generation: 1,
            }),
        }
    }

    #[allow(
        dead_code,
        reason = "consumed by the freestanding primordial profile selector"
    )]
    pub(crate) fn has_grants(&self) -> bool {
        !self.state.lock().grants.is_empty()
    }

    #[allow(
        dead_code,
        reason = "bound by the freestanding primordial resource-domain constructor"
    )]
    pub(crate) fn bind_owner(
        &self,
        key: TaskGroupKey,
        owner: InternalRef,
    ) -> Result<(), (BootResourceLeaseError, InternalRef)> {
        if owner.id() != key.object_id()
            || owner.object_type() != deepwyrm_abi::DW_OBJECT_TYPE_TASK_GROUP
        {
            return Err((BootResourceLeaseError::FinalizationMismatch, owner));
        }
        let mut state = self.state.lock();
        if state.owner.is_some() {
            return Err((BootResourceLeaseError::OwnerAlreadyBound, owner));
        }
        state.owner = Some((key, owner));
        Ok(())
    }

    pub(crate) fn owner_key(&self) -> Result<TaskGroupKey, BootResourceLeaseError> {
        self.state
            .lock()
            .owner
            .as_ref()
            .map(|(key, _)| *key)
            .ok_or(BootResourceLeaseError::OwnerNotBound)
    }

    /// Returns the one-shot resource-domain owner only after every boot grant
    /// has completed its typed finalization and returned to `Available`.
    #[allow(
        dead_code,
        reason = "terminal owner release is consumed by the freestanding primordial runtime"
    )]
    pub(crate) fn take_owner_if_all_grants_available(
        &self,
    ) -> Result<InternalRef, BootResourceLeaseError> {
        let mut state = self.state.lock();
        if state.grants.grants[..state.grants.count]
            .iter()
            .flatten()
            .any(|grant| grant.state != BootResourceGrantState::Available)
        {
            return Err(BootResourceLeaseError::GrantNotAvailable);
        }
        state
            .owner
            .take()
            .map(|(_, owner)| owner)
            .ok_or(BootResourceLeaseError::OwnerNotBound)
    }

    pub(crate) fn reserve(
        &self,
        resource_id: u64,
    ) -> Result<(BootResourceDescriptor, BootResourceLeaseReservation), BootResourceLeaseError>
    {
        let mut state = self.state.lock();
        if state.owner.is_none() {
            return Err(BootResourceLeaseError::OwnerNotBound);
        }
        let index = (0..state.grants.count)
            .find(|index| {
                state.grants.grants[*index]
                    .is_some_and(|grant| grant.descriptor.resource_id == resource_id)
            })
            .ok_or(BootResourceLeaseError::UnknownResource)?;
        let grant = state.grants.grants[index]
            .as_ref()
            .expect("matched boot-resource grant remains populated");
        if grant.state != BootResourceGrantState::Available {
            return Err(BootResourceLeaseError::AlreadyLeased);
        }
        let descriptor = grant.descriptor;
        let grant_generation = grant.grant_generation;
        let lease_generation = state.next_lease_generation;
        if lease_generation == 0 {
            return Err(BootResourceLeaseError::GenerationExhausted);
        }
        state.next_lease_generation = lease_generation
            .checked_add(1)
            .filter(|next| *next != 0)
            .ok_or(BootResourceLeaseError::GenerationExhausted)?;
        state.grants.grants[index]
            .as_mut()
            .expect("matched boot-resource grant remains populated")
            .state = BootResourceGrantState::Reserved { lease_generation };
        Ok((
            descriptor,
            BootResourceLeaseReservation {
                resource_id,
                grant_generation,
                lease_generation,
            },
        ))
    }

    pub(crate) fn cancel(
        &self,
        reservation: BootResourceLeaseReservation,
    ) -> Result<(), BootResourceLeaseError> {
        let mut state = self.state.lock();
        let grant = exact_grant_mut(&mut state.grants, &reservation)
            .ok_or(BootResourceLeaseError::StaleReservation)?;
        if grant.state
            != (BootResourceGrantState::Reserved {
                lease_generation: reservation.lease_generation,
            })
        {
            return Err(BootResourceLeaseError::StaleReservation);
        }
        grant.state = BootResourceGrantState::Available;
        Ok(())
    }

    /// Infallible after exact reservation validation at the claim commit point.
    pub(crate) fn commit(&self, reservation: BootResourceLeaseReservation, object: ObjectId) {
        let mut state = self.state.lock();
        let grant = exact_grant_mut(&mut state.grants, &reservation)
            .expect("boot-resource lease reservation remained exact until commit");
        assert_eq!(
            grant.state,
            BootResourceGrantState::Reserved {
                lease_generation: reservation.lease_generation,
            },
            "boot-resource lease reservation drifted before commit"
        );
        grant.state = BootResourceGrantState::Leased {
            object,
            lease_generation: reservation.lease_generation,
        };
    }

    pub(crate) fn release_lease(
        &self,
        resource_id: u64,
        grant_generation: u64,
        object: ObjectId,
        lease_generation: u64,
    ) -> Result<(), BootResourceLeaseError> {
        let mut state = self.state.lock();
        let count = state.grants.count;
        let grant = state.grants.grants[..count]
            .iter_mut()
            .flatten()
            .find(|grant| {
                grant.descriptor.resource_id == resource_id
                    && grant.grant_generation == grant_generation
            })
            .ok_or(BootResourceLeaseError::FinalizationMismatch)?;
        if grant.state
            != (BootResourceGrantState::Leased {
                object,
                lease_generation,
            })
        {
            return Err(BootResourceLeaseError::FinalizationMismatch);
        }
        grant.state = BootResourceGrantState::Available;
        Ok(())
    }

    #[cfg(any(test, deepwyrm_dw1d_evidence))]
    #[allow(
        dead_code,
        reason = "selector-30 consumes this only in the target runtime"
    )]
    pub(crate) fn state_for(&self, resource_id: u64) -> Option<(u64, BootResourceGrantState)> {
        let state = self.state.lock();
        state.grants.grants[..state.grants.count]
            .iter()
            .flatten()
            .find(|grant| grant.descriptor.resource_id == resource_id)
            .map(|grant| (grant.grant_generation, grant.state))
    }
}

#[cfg(deepwyrm_integrated)]
fn exact_grant_mut<'a>(
    grants: &'a mut BootResourceGrants,
    reservation: &BootResourceLeaseReservation,
) -> Option<&'a mut BootResourceGrant> {
    grants.grants[..grants.count]
        .iter_mut()
        .flatten()
        .find(|grant| {
            grant.descriptor.resource_id == reservation.resource_id
                && grant.grant_generation == reservation.grant_generation
        })
}

#[cfg(test)]
mod tests {
    use crate::object::ObjectRegistry;
    use crate::task::TaskAuthority;
    use deepwyrm_abi::{
        DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT, DW_OBJECT_TYPE_EVENT,
    };

    use super::*;

    fn descriptor(resource_id: u64) -> BootResourceDescriptor {
        BootResourceDescriptor {
            resource_id,
            device_correlation_id: resource_id,
            kind: DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
            pio_base: 0x2f8,
            pio_length: 8,
            interrupt_source: 3,
        }
    }

    #[test]
    fn materializes_available_grants_with_distinct_nonzero_generations() {
        let grants =
            BootResourceGrants::materialize(&[descriptor(1), descriptor(2)]).expect("valid grants");

        assert_eq!(grants.len(), 2);
        let first = grants.grant(0).expect("first grant");
        let second = grants.grant(1).expect("second grant");
        assert_eq!(first.descriptor(), descriptor(1));
        assert_eq!(first.state(), BootResourceGrantState::Available);
        assert_ne!(first.grant_generation(), 0);
        assert_ne!(second.grant_generation(), 0);
        assert_ne!(first.grant_generation(), second.grant_generation());
        assert_eq!(grants.grant(2), None);
    }

    #[test]
    fn empty_snapshot_mints_no_grants() {
        let grants = BootResourceGrants::materialize(&[]).expect("empty grant set");
        assert!(grants.is_empty());
        assert_eq!(grants.grant(0), None);
    }

    #[test]
    fn exact_owner_lease_reclaims_and_mints_a_fresh_generation() {
        let grants = BootResourceGrants::materialize(&[descriptor(7)]).unwrap();
        let authority = BootResourceGrantAuthority::new(grants);
        let mut registry = ObjectRegistry::<4>::new();
        let mut tasks = TaskAuthority::<2, 1, 1, 1>::new();
        let (domain, owner) = tasks.create_root_group(&mut registry).unwrap();
        authority.bind_owner(domain, owner).unwrap();

        let (_descriptor, first) = authority.reserve(7).unwrap();
        let first_generation = first.lease_generation();
        let grant_generation = first.grant_generation();
        assert_eq!(
            authority.state_for(7),
            Some((
                grant_generation,
                BootResourceGrantState::Reserved {
                    lease_generation: first_generation,
                },
            ))
        );
        let creation = registry.create(DW_OBJECT_TYPE_EVENT).unwrap();
        let object = creation.id();
        authority.commit(first, object);
        assert_eq!(
            authority.reserve(7).err(),
            Some(BootResourceLeaseError::AlreadyLeased)
        );
        authority
            .release_lease(7, grant_generation, object, first_generation)
            .unwrap();
        registry.cancel_creation(creation).unwrap();

        let (_, second) = authority.reserve(7).unwrap();
        assert_ne!(second.lease_generation(), first_generation);
        authority.cancel(second).unwrap();
        assert_eq!(
            authority.state_for(7),
            Some((grant_generation, BootResourceGrantState::Available))
        );
    }

    #[test]
    fn stale_or_wrong_finalization_cannot_free_a_live_lease() {
        let authority = BootResourceGrantAuthority::new(
            BootResourceGrants::materialize(&[descriptor(9)]).unwrap(),
        );
        let mut registry = ObjectRegistry::<4>::new();
        let mut tasks = TaskAuthority::<1, 1, 1, 1>::new();
        let (domain, owner) = tasks.create_root_group(&mut registry).unwrap();
        authority.bind_owner(domain, owner).unwrap();
        let (_, reservation) = authority.reserve(9).unwrap();
        let grant_generation = reservation.grant_generation();
        let lease_generation = reservation.lease_generation();
        let creation = registry.create(DW_OBJECT_TYPE_EVENT).unwrap();
        let object = creation.id();
        authority.commit(reservation, object);
        assert_eq!(
            authority.release_lease(9, grant_generation, object, lease_generation + 1),
            Err(BootResourceLeaseError::FinalizationMismatch)
        );
        assert_eq!(
            authority.reserve(9).err(),
            Some(BootResourceLeaseError::AlreadyLeased)
        );
        authority
            .release_lease(9, grant_generation, object, lease_generation)
            .unwrap();
        registry.cancel_creation(creation).unwrap();
    }

    #[test]
    fn terminal_owner_release_waits_for_available_grants_and_restores_capacity() {
        let authority = BootResourceGrantAuthority::new(
            BootResourceGrants::materialize(&[descriptor(11)]).unwrap(),
        );
        let mut registry = ObjectRegistry::<4>::new();
        let mut tasks = TaskAuthority::<2, 1, 1, 1>::new();
        let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
        let (domain, domain_handle) = tasks
            .create_child_group(&mut registry, &root_owner)
            .unwrap();
        let domain_owner = registry
            .retain_internal_from_handle(&domain_handle)
            .unwrap();
        authority.bind_owner(domain, domain_owner).unwrap();

        let (_, reservation) = authority.reserve(11).unwrap();
        assert_eq!(
            authority.take_owner_if_all_grants_available().err(),
            Some(BootResourceLeaseError::GrantNotAvailable)
        );
        authority.cancel(reservation).unwrap();

        assert!(registry.release_handle(domain_handle).unwrap().is_none());
        assert!(registry.release_internal(root_owner).unwrap().is_none());
        let domain_owner = authority.take_owner_if_all_grants_available().unwrap();
        let mut pending = registry.release_internal(domain_owner).unwrap();
        while let Some(release) = pending.take() {
            let finalization = tasks.take_finalization(release).unwrap();
            pending = crate::task::complete_task_finalization(&mut registry, finalization);
        }
        assert_eq!(
            authority.take_owner_if_all_grants_available().err(),
            Some(BootResourceLeaseError::OwnerNotBound)
        );

        let mut probes = [const { None }; 4];
        for probe in &mut probes {
            *probe = Some(registry.create(DW_OBJECT_TYPE_EVENT).unwrap());
        }
        for probe in probes.into_iter().flatten() {
            registry.cancel_creation(probe).unwrap();
        }
    }
}
