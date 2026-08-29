use std::collections::{BTreeMap, BTreeSet};

const READ: u64 = 0x001;
const WRITE: u64 = 0x002;
const WAIT: u64 = 0x010;
const DUPLICATE: u64 = 0x040;
const TRANSFER: u64 = 0x080;
const INSPECT: u64 = 0x100;
const MODIFY: u64 = 0x200;
const RESOURCE: u64 = 0x400;

const TASK_GROUP_CUSTODY_RIGHTS: u64 = RESOURCE | MODIFY | DUPLICATE | TRANSFER | INSPECT;
const TASK_GROUP_CLAIM_RIGHTS: u64 = RESOURCE | INSPECT;
const DEVICE_RESOURCE_RIGHTS: u64 = READ | WRITE | MODIFY | DUPLICATE | TRANSFER | INSPECT;
const DRIVER_RESOURCE_RIGHTS: u64 = READ | WRITE | INSPECT;
const INTERRUPT_RIGHTS: u64 = WAIT | MODIFY | TRANSFER | INSPECT;
const DRIVER_INTERRUPT_RIGHTS: u64 = WAIT | MODIFY | INSPECT;

const COM1_BASE: u16 = 0x3f8;
const COM1_LENGTH: u16 = 8;
const COM1_IRQ: u32 = 4;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct Group(u64);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Actor {
    group: Group,
    active: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ClaimCapability {
    domain: Group,
    rights: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClaimFailurePoint {
    GrantLookup,
    ClaimAuthority,
    GrantReserve,
    ObjectReserve,
    PayloadBind,
    HandleReserve,
    Publication,
    PostPublication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelError {
    AccessDenied,
    BadState,
    InvalidArgument,
    AlreadyLeased,
    NoResources,
    StaleGeneration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResourceHandle {
    owner: &'static str,
    rights: u64,
    lease_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ResourceHandleId {
    slot: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InterruptState {
    Armed,
    Pending { coalesced: bool },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Interrupt {
    owner: &'static str,
    rights: u64,
    object_generation: u64,
    binding_generation: u64,
    state: InterruptState,
    public_handle: bool,
    wait_pin: bool,
    bound: bool,
    masked: bool,
}

#[derive(Debug)]
struct Lease {
    generation: u64,
    next_handle_slot: u64,
    handles: BTreeMap<ResourceHandleId, ResourceHandle>,
    parent_pins: u32,
    interrupt: Option<Interrupt>,
}

#[derive(Debug)]
enum GrantState {
    Available,
    Reserved,
    Leased(Lease),
}

#[derive(Debug)]
struct CustodyModel {
    parents: BTreeMap<Group, Option<Group>>,
    active_groups: BTreeSet<Group>,
    actors: BTreeMap<&'static str, Actor>,
    owner_domain: Group,
    grant: GrantState,
    next_lease_generation: u64,
    next_interrupt_generation: u64,
    next_binding_generation: u64,
    bound_source_generation: Option<u64>,
    reserved_objects: u32,
    reserved_handles: u32,
    release_count: u32,
    unbind_count: u32,
}

impl CustodyModel {
    fn new() -> Self {
        let root = Group(1);
        let domain = Group(2);
        let devmgr_one = Group(3);
        let driver_one = Group(4);
        let devmgr_two = Group(5);
        let sibling = Group(6);
        Self {
            parents: BTreeMap::from([
                (root, None),
                (domain, Some(root)),
                (devmgr_one, Some(domain)),
                (driver_one, Some(devmgr_one)),
                (devmgr_two, Some(domain)),
                (sibling, Some(root)),
            ]),
            active_groups: BTreeSet::from([
                root, domain, devmgr_one, driver_one, devmgr_two, sibling,
            ]),
            actors: BTreeMap::from([
                (
                    "init",
                    Actor {
                        group: root,
                        active: true,
                    },
                ),
                (
                    "devmgr-1",
                    Actor {
                        group: devmgr_one,
                        active: true,
                    },
                ),
                (
                    "driver-1",
                    Actor {
                        group: driver_one,
                        active: true,
                    },
                ),
                (
                    "devmgr-2",
                    Actor {
                        group: devmgr_two,
                        active: true,
                    },
                ),
                (
                    "sibling",
                    Actor {
                        group: sibling,
                        active: true,
                    },
                ),
            ]),
            owner_domain: domain,
            grant: GrantState::Available,
            next_lease_generation: 1,
            next_interrupt_generation: 1,
            next_binding_generation: 1,
            bound_source_generation: None,
            reserved_objects: 0,
            reserved_handles: 0,
            release_count: 0,
            unbind_count: 0,
        }
    }

    fn belongs_to(&self, actor: Actor, domain: Group) -> bool {
        if !actor.active || !self.active_groups.contains(&domain) {
            return false;
        }
        let mut current = Some(actor.group);
        for _ in 0..self.parents.len() {
            let Some(group) = current else {
                return false;
            };
            if group == domain {
                return self.active_groups.contains(&group);
            }
            if !self.active_groups.contains(&group) {
                return false;
            }
            current = self.parents.get(&group).copied().flatten();
        }
        false
    }

    fn claim(
        &mut self,
        actor_name: &'static str,
        capability: ClaimCapability,
        requested_rights: u64,
        fail_at: Option<ClaimFailurePoint>,
    ) -> Result<(u64, ResourceHandleId), ModelError> {
        if requested_rights == 0 || requested_rights & !DEVICE_RESOURCE_RIGHTS != 0 {
            return Err(ModelError::InvalidArgument);
        }
        if capability.rights & RESOURCE == 0 || capability.domain != self.owner_domain {
            return Err(ModelError::AccessDenied);
        }
        let actor = *self.actors.get(actor_name).expect("known actor");
        if !self.belongs_to(actor, self.owner_domain) {
            return Err(ModelError::AccessDenied);
        }
        if fail_at == Some(ClaimFailurePoint::GrantLookup)
            || fail_at == Some(ClaimFailurePoint::ClaimAuthority)
        {
            return Err(ModelError::NoResources);
        }
        if !matches!(self.grant, GrantState::Available) {
            return Err(ModelError::AlreadyLeased);
        }
        let generation = self.next_lease_generation;
        self.next_lease_generation += 1;
        self.grant = GrantState::Reserved;
        if fail_at == Some(ClaimFailurePoint::GrantReserve) {
            self.grant = GrantState::Available;
            return Err(ModelError::NoResources);
        }

        self.reserved_objects += 1;
        if fail_at == Some(ClaimFailurePoint::ObjectReserve) {
            self.reserved_objects -= 1;
            self.grant = GrantState::Available;
            return Err(ModelError::NoResources);
        }
        if fail_at == Some(ClaimFailurePoint::PayloadBind) {
            self.reserved_objects -= 1;
            self.grant = GrantState::Available;
            return Err(ModelError::NoResources);
        }

        self.reserved_handles += 1;
        if fail_at == Some(ClaimFailurePoint::HandleReserve)
            || fail_at == Some(ClaimFailurePoint::Publication)
        {
            self.reserved_handles -= 1;
            self.reserved_objects -= 1;
            self.grant = GrantState::Available;
            return Err(ModelError::NoResources);
        }

        let handle_id = ResourceHandleId {
            slot: 1,
            generation,
        };
        let handle = ResourceHandle {
            owner: actor_name,
            rights: requested_rights,
            lease_generation: generation,
        };
        self.reserved_handles -= 1;
        self.reserved_objects -= 1;
        self.grant = GrantState::Leased(Lease {
            generation,
            next_handle_slot: 2,
            handles: BTreeMap::from([(handle_id, handle)]),
            parent_pins: 0,
            interrupt: None,
        });
        if fail_at == Some(ClaimFailurePoint::PostPublication) {
            self.close_resource(handle_id)
                .expect("post-publication cleanup uses ordinary close/finalization");
            return Err(ModelError::NoResources);
        }
        Ok((generation, handle_id))
    }

    fn duplicate_resource(
        &mut self,
        source: ResourceHandleId,
        rights: u64,
    ) -> Result<ResourceHandleId, ModelError> {
        let lease = self.lease_mut()?;
        let original = *lease
            .handles
            .get(&source)
            .ok_or(ModelError::StaleGeneration)?;
        if original.rights & DUPLICATE == 0
            || rights == 0
            || rights & !original.rights != 0
            || rights & !DEVICE_RESOURCE_RIGHTS != 0
        {
            return Err(ModelError::AccessDenied);
        }
        let id = ResourceHandleId {
            slot: lease.next_handle_slot,
            generation: lease.generation,
        };
        lease.next_handle_slot += 1;
        lease
            .handles
            .insert(id, ResourceHandle { rights, ..original });
        Ok(id)
    }

    fn move_resource(
        &mut self,
        source: ResourceHandleId,
        receiver: &'static str,
        rights: u64,
        commit: bool,
    ) -> Result<(), ModelError> {
        let lease = self.lease_mut()?;
        let original = lease
            .handles
            .get(&source)
            .ok_or(ModelError::StaleGeneration)?;
        if original.rights & TRANSFER == 0 || rights == 0 || rights & !original.rights != 0 {
            return Err(ModelError::AccessDenied);
        }
        if commit {
            let handle = lease.handles.get_mut(&source).expect("validated source");
            handle.owner = receiver;
            handle.rights = rights;
        }
        Ok(())
    }

    fn create_interrupt(
        &mut self,
        resource: ResourceHandleId,
        requested_rights: u64,
    ) -> Result<(u64, u64), ModelError> {
        let (object_generation, binding_generation) =
            (self.next_interrupt_generation, self.next_binding_generation);
        let lease = self.lease_mut()?;
        let handle = *lease
            .handles
            .get(&resource)
            .ok_or(ModelError::StaleGeneration)?;
        if handle.rights & MODIFY == 0
            || requested_rights == 0
            || requested_rights & !INTERRUPT_RIGHTS != 0
        {
            return Err(ModelError::AccessDenied);
        }
        if lease.interrupt.is_some() {
            return Err(ModelError::AlreadyLeased);
        }
        lease.parent_pins += 1;
        lease.interrupt = Some(Interrupt {
            owner: handle.owner,
            rights: requested_rights,
            object_generation,
            binding_generation,
            state: InterruptState::Armed,
            public_handle: true,
            wait_pin: false,
            bound: true,
            masked: false,
        });
        self.next_interrupt_generation += 1;
        self.next_binding_generation += 1;
        self.bound_source_generation = Some(binding_generation);
        Ok((object_generation, binding_generation))
    }

    fn move_interrupt(
        &mut self,
        receiver: &'static str,
        rights: u64,
        commit: bool,
    ) -> Result<(), ModelError> {
        let interrupt = self
            .lease_mut()?
            .interrupt
            .as_mut()
            .ok_or(ModelError::BadState)?;
        if interrupt.rights & TRANSFER == 0 || rights == 0 || rights & !interrupt.rights != 0 {
            return Err(ModelError::AccessDenied);
        }
        if commit {
            interrupt.owner = receiver;
            interrupt.rights = rights;
        }
        Ok(())
    }

    fn deliver(&mut self, binding_generation: u64) -> Result<bool, ModelError> {
        if self.bound_source_generation != Some(binding_generation) {
            return Ok(false);
        }
        let interrupt = self
            .lease_mut()?
            .interrupt
            .as_mut()
            .ok_or(ModelError::BadState)?;
        interrupt.masked = true;
        interrupt.state = match interrupt.state {
            InterruptState::Armed => InterruptState::Pending { coalesced: false },
            InterruptState::Pending { .. } => InterruptState::Pending { coalesced: true },
        };
        Ok(true)
    }

    fn ack(&mut self, racing_delivery: bool) -> Result<(), ModelError> {
        let interrupt = self
            .lease_mut()?
            .interrupt
            .as_mut()
            .ok_or(ModelError::BadState)?;
        if interrupt.rights & MODIFY == 0 {
            return Err(ModelError::AccessDenied);
        }
        match interrupt.state {
            InterruptState::Armed => Err(ModelError::BadState),
            InterruptState::Pending { coalesced: true } => {
                interrupt.state = InterruptState::Pending { coalesced: false };
                Ok(())
            }
            InterruptState::Pending { coalesced: false } => {
                interrupt.masked = false;
                interrupt.state = if racing_delivery {
                    interrupt.masked = true;
                    InterruptState::Pending { coalesced: false }
                } else {
                    InterruptState::Armed
                };
                Ok(())
            }
        }
    }

    fn register_wait(&mut self) -> Result<(), ModelError> {
        let interrupt = self
            .lease_mut()?
            .interrupt
            .as_mut()
            .ok_or(ModelError::BadState)?;
        if interrupt.rights & WAIT == 0 {
            return Err(ModelError::AccessDenied);
        }
        interrupt.wait_pin = true;
        Ok(())
    }

    fn close_interrupt(&mut self) -> Result<(), ModelError> {
        let wait_pin = {
            let interrupt = self
                .lease_mut()?
                .interrupt
                .as_mut()
                .ok_or(ModelError::BadState)?;
            interrupt.public_handle = false;
            interrupt.wait_pin
        };
        if !wait_pin {
            self.finalize_interrupt()?;
        }
        Ok(())
    }

    fn release_wait_pin(&mut self) -> Result<(), ModelError> {
        let should_finalize = {
            let interrupt = self
                .lease_mut()?
                .interrupt
                .as_mut()
                .ok_or(ModelError::BadState)?;
            interrupt.wait_pin = false;
            !interrupt.public_handle
        };
        if should_finalize {
            self.finalize_interrupt()?;
        }
        Ok(())
    }

    fn finalize_interrupt(&mut self) -> Result<(), ModelError> {
        let binding = {
            let lease = self.lease_mut()?;
            let interrupt = lease.interrupt.as_mut().ok_or(ModelError::BadState)?;
            interrupt.masked = true;
            interrupt.bound = false;
            interrupt.binding_generation
        };
        self.bound_source_generation = None;
        self.unbind_count += 1;
        let lease = self.lease_mut()?;
        assert_eq!(
            lease.interrupt.as_ref().unwrap().binding_generation,
            binding
        );
        lease.interrupt = None;
        lease.parent_pins -= 1;
        self.maybe_release();
        Ok(())
    }

    fn close_resource(&mut self, handle: ResourceHandleId) -> Result<(), ModelError> {
        let lease = self.lease_mut()?;
        lease
            .handles
            .remove(&handle)
            .ok_or(ModelError::StaleGeneration)?;
        self.maybe_release();
        Ok(())
    }

    fn terminate_actor(&mut self, actor: &'static str) -> Result<(), ModelError> {
        self.actors.get_mut(actor).expect("known actor").active = false;
        let handles = match &self.grant {
            GrantState::Available | GrantState::Reserved => Vec::new(),
            GrantState::Leased(lease) => lease
                .handles
                .iter()
                .filter_map(|(&id, handle)| (handle.owner == actor).then_some(id))
                .collect(),
        };
        for handle in handles {
            self.close_resource(handle)?;
        }
        let closes_interrupt = matches!(
            &self.grant,
            GrantState::Leased(lease)
                if lease.interrupt.as_ref().is_some_and(|interrupt| {
                    interrupt.owner == actor && interrupt.public_handle
                })
        );
        if closes_interrupt {
            self.close_interrupt()?;
        }
        Ok(())
    }

    fn terminate_domain(&mut self) {
        let domain = self.owner_domain;
        let groups = self
            .active_groups
            .iter()
            .copied()
            .filter(|group| {
                let mut current = Some(*group);
                while let Some(candidate) = current {
                    if candidate == domain {
                        return true;
                    }
                    current = self.parents.get(&candidate).copied().flatten();
                }
                false
            })
            .collect::<Vec<_>>();
        for group in groups {
            self.active_groups.remove(&group);
        }
        for actor in self.actors.values_mut() {
            if !self.active_groups.contains(&actor.group) {
                actor.active = false;
            }
        }
    }

    fn maybe_release(&mut self) {
        let releasable = matches!(
            &self.grant,
            GrantState::Leased(lease)
                if lease.handles.is_empty()
                    && lease.parent_pins == 0
                    && lease.interrupt.is_none()
        );
        if releasable {
            self.grant = GrantState::Available;
            self.release_count += 1;
        }
    }

    fn lease(&self) -> Result<&Lease, ModelError> {
        match &self.grant {
            GrantState::Available | GrantState::Reserved => Err(ModelError::BadState),
            GrantState::Leased(lease) => Ok(lease),
        }
    }

    fn lease_mut(&mut self) -> Result<&mut Lease, ModelError> {
        match &mut self.grant {
            GrantState::Available | GrantState::Reserved => Err(ModelError::BadState),
            GrantState::Leased(lease) => Ok(lease),
        }
    }
}

#[test]
fn custody_survives_owner_death_and_reclaims_one_fresh_generation() {
    let mut model = CustodyModel::new();
    let domain = model.owner_domain;
    let custody = ClaimCapability {
        domain,
        rights: TASK_GROUP_CUSTODY_RIGHTS,
    };
    let claim = ClaimCapability {
        domain,
        rights: TASK_GROUP_CLAIM_RIGHTS,
    };

    assert_eq!(
        model.claim("init", custody, DEVICE_RESOURCE_RIGHTS, None),
        Err(ModelError::AccessDenied)
    );
    assert_eq!(
        model.claim("sibling", claim, DEVICE_RESOURCE_RIGHTS, None),
        Err(ModelError::AccessDenied)
    );
    assert_eq!(
        model.claim(
            "devmgr-1",
            ClaimCapability {
                domain,
                rights: INSPECT
            },
            DEVICE_RESOURCE_RIGHTS,
            None,
        ),
        Err(ModelError::AccessDenied)
    );

    let (lease_one, devmgr_resource) = model
        .claim("devmgr-1", claim, DEVICE_RESOURCE_RIGHTS, None)
        .unwrap();
    assert_eq!(lease_one, 1);
    assert_eq!(model.lease().unwrap().generation, lease_one);
    assert_eq!(
        model.claim("devmgr-2", claim, DEVICE_RESOURCE_RIGHTS, None),
        Err(ModelError::AlreadyLeased)
    );

    let driver_resource = model
        .duplicate_resource(devmgr_resource, DEVICE_RESOURCE_RIGHTS)
        .unwrap();
    assert_eq!(
        model.duplicate_resource(driver_resource, DEVICE_RESOURCE_RIGHTS | RESOURCE),
        Err(ModelError::AccessDenied)
    );
    assert!(
        model
            .move_resource(driver_resource, "driver-1", DRIVER_RESOURCE_RIGHTS, false)
            .is_ok()
    );
    assert_eq!(
        model.lease().unwrap().handles[&driver_resource].owner,
        "devmgr-1",
        "failed MOVE preserves sender ownership"
    );
    model
        .move_resource(driver_resource, "driver-1", DRIVER_RESOURCE_RIGHTS, true)
        .unwrap();

    let (_, binding_one) = model
        .create_interrupt(devmgr_resource, INTERRUPT_RIGHTS)
        .unwrap();
    model
        .move_interrupt("driver-1", DRIVER_INTERRUPT_RIGHTS, false)
        .unwrap();
    assert_eq!(
        model.lease().unwrap().interrupt.unwrap().owner,
        "devmgr-1",
        "failed Interrupt MOVE preserves sender ownership"
    );
    model
        .move_interrupt("driver-1", DRIVER_INTERRUPT_RIGHTS, true)
        .unwrap();

    model.terminate_actor("devmgr-1").unwrap();
    assert!(matches!(model.grant, GrantState::Leased(_)));
    assert_eq!(model.lease().unwrap().parent_pins, 1);

    model.close_resource(driver_resource).unwrap();
    assert!(matches!(model.grant, GrantState::Leased(_)));
    assert!(model.deliver(binding_one).unwrap());
    assert!(model.deliver(binding_one).unwrap());
    assert_eq!(
        model.lease().unwrap().interrupt.unwrap().state,
        InterruptState::Pending { coalesced: true }
    );
    model.ack(false).unwrap();
    assert_eq!(
        model.lease().unwrap().interrupt.unwrap().state,
        InterruptState::Pending { coalesced: false }
    );
    model.ack(true).unwrap();
    assert_eq!(
        model.lease().unwrap().interrupt.unwrap().state,
        InterruptState::Pending { coalesced: false },
        "delivery racing rearm remains pending"
    );
    model.ack(false).unwrap();
    assert_eq!(
        model.lease().unwrap().interrupt.unwrap().state,
        InterruptState::Armed
    );
    assert_eq!(model.ack(false), Err(ModelError::BadState));

    model.terminate_actor("driver-1").unwrap();
    assert!(matches!(model.grant, GrantState::Available));
    assert_eq!(model.unbind_count, 1);
    assert_eq!(model.release_count, 1);
    assert!(!model.deliver(binding_one).unwrap());

    let (lease_two, replacement_resource) = model
        .claim("devmgr-2", claim, DEVICE_RESOURCE_RIGHTS, None)
        .unwrap();
    assert_ne!(lease_two, lease_one);
    assert_eq!(replacement_resource.slot, devmgr_resource.slot);
    assert_ne!(replacement_resource.generation, devmgr_resource.generation);
    assert_eq!(
        model.lease().unwrap().handles[&replacement_resource].lease_generation,
        lease_two
    );
    assert_eq!(
        model.close_resource(devmgr_resource),
        Err(ModelError::StaleGeneration)
    );
}

#[test]
fn claim_failures_restore_available_and_domain_teardown_is_terminal() {
    for point in [
        ClaimFailurePoint::GrantLookup,
        ClaimFailurePoint::ClaimAuthority,
        ClaimFailurePoint::GrantReserve,
        ClaimFailurePoint::ObjectReserve,
        ClaimFailurePoint::PayloadBind,
        ClaimFailurePoint::HandleReserve,
        ClaimFailurePoint::Publication,
        ClaimFailurePoint::PostPublication,
    ] {
        let mut model = CustodyModel::new();
        let claim = ClaimCapability {
            domain: model.owner_domain,
            rights: TASK_GROUP_CLAIM_RIGHTS,
        };
        assert_eq!(
            model.claim("devmgr-1", claim, DEVICE_RESOURCE_RIGHTS, Some(point)),
            Err(ModelError::NoResources)
        );
        assert!(matches!(model.grant, GrantState::Available));
        assert_eq!(model.reserved_objects, 0);
        assert_eq!(model.reserved_handles, 0);
        assert_eq!(
            model.release_count,
            u32::from(point == ClaimFailurePoint::PostPublication)
        );
        let (generation, _) = model
            .claim("devmgr-1", claim, DEVICE_RESOURCE_RIGHTS, None)
            .unwrap();
        let expected_generation = if matches!(
            point,
            ClaimFailurePoint::GrantLookup | ClaimFailurePoint::ClaimAuthority
        ) {
            1
        } else {
            2
        };
        assert_eq!(generation, expected_generation);
    }

    let mut model = CustodyModel::new();
    let claim = ClaimCapability {
        domain: model.owner_domain,
        rights: TASK_GROUP_CLAIM_RIGHTS,
    };
    model.terminate_domain();
    assert_eq!(
        model.claim("devmgr-2", claim, DEVICE_RESOURCE_RIGHTS, None),
        Err(ModelError::AccessDenied)
    );
    assert!(matches!(model.grant, GrantState::Available));

    let mut leased = CustodyModel::new();
    let claim = ClaimCapability {
        domain: leased.owner_domain,
        rights: TASK_GROUP_CLAIM_RIGHTS,
    };
    leased
        .claim("devmgr-1", claim, DEVICE_RESOURCE_RIGHTS, None)
        .unwrap();
    leased.terminate_domain();
    assert!(matches!(leased.grant, GrantState::Leased(_)));
    assert_eq!(
        leased.claim("devmgr-2", claim, DEVICE_RESOURCE_RIGHTS, None),
        Err(ModelError::AccessDenied)
    );
    leased.terminate_actor("devmgr-1").unwrap();
    assert!(matches!(leased.grant, GrantState::Available));
    assert_eq!(
        leased.claim("devmgr-2", claim, DEVICE_RESOURCE_RIGHTS, None),
        Err(ModelError::AccessDenied),
        "a terminated resource domain is never rebound in the same boot"
    );
}

#[test]
fn waiter_pin_defers_interrupt_unbind_and_parent_release() {
    let mut model = CustodyModel::new();
    let claim = ClaimCapability {
        domain: model.owner_domain,
        rights: TASK_GROUP_CLAIM_RIGHTS,
    };
    let (_, resource) = model
        .claim("devmgr-1", claim, DEVICE_RESOURCE_RIGHTS, None)
        .unwrap();
    model.create_interrupt(resource, INTERRUPT_RIGHTS).unwrap();
    model.register_wait().unwrap();
    model.close_resource(resource).unwrap();
    model.close_interrupt().unwrap();

    assert!(matches!(model.grant, GrantState::Leased(_)));
    assert_eq!(model.unbind_count, 0);
    assert_eq!(model.lease().unwrap().parent_pins, 1);

    model.release_wait_pin().unwrap();
    assert!(matches!(model.grant, GrantState::Available));
    assert_eq!(model.unbind_count, 1);
    assert_eq!(model.release_count, 1);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BootResource {
    resource_id: u64,
    pio_base: u16,
    pio_length: u16,
    interrupt_source: u32,
}

fn validate_boot_resources(resources: &[BootResource]) -> Result<(), ModelError> {
    if resources.is_empty() || resources.len() > 8 {
        return Err(ModelError::InvalidArgument);
    }
    for (index, resource) in resources.iter().enumerate() {
        if resource.resource_id == 0 || resource.pio_length == 0 || resource.interrupt_source == 0 {
            return Err(ModelError::InvalidArgument);
        }
        let end = u32::from(resource.pio_base)
            .checked_add(u32::from(resource.pio_length))
            .filter(|end| *end <= 0x1_0000)
            .ok_or(ModelError::InvalidArgument)?;
        let com1_end = u32::from(COM1_BASE) + u32::from(COM1_LENGTH);
        if u32::from(resource.pio_base) < com1_end && u32::from(COM1_BASE) < end {
            return Err(ModelError::AccessDenied);
        }
        if resource.interrupt_source == COM1_IRQ {
            return Err(ModelError::AccessDenied);
        }
        for other in &resources[..index] {
            let other_end = u32::from(other.pio_base) + u32::from(other.pio_length);
            if resource.resource_id == other.resource_id
                || resource.interrupt_source == other.interrupt_source
                || (u32::from(resource.pio_base) < other_end && u32::from(other.pio_base) < end)
            {
                return Err(ModelError::AlreadyLeased);
            }
        }
    }
    Ok(())
}

fn checked_port(base: u16, length: u16, offset: u32, width: u32) -> Result<u16, ModelError> {
    if !matches!(width, 1 | 2 | 4) {
        return Err(ModelError::InvalidArgument);
    }
    let end = offset
        .checked_add(width)
        .ok_or(ModelError::InvalidArgument)?;
    if end > u32::from(length) {
        return Err(ModelError::InvalidArgument);
    }
    let port = u32::from(base)
        .checked_add(offset)
        .filter(|port| port.checked_add(width).is_some_and(|end| end <= 0x1_0000))
        .ok_or(ModelError::InvalidArgument)?;
    u16::try_from(port).map_err(|_| ModelError::InvalidArgument)
}

#[test]
fn boot_grant_and_pio_ranges_are_bounded_and_protect_com1() {
    let com2 = BootResource {
        resource_id: 1,
        pio_base: 0x2f8,
        pio_length: 8,
        interrupt_source: 3,
    };
    assert_eq!(validate_boot_resources(&[com2]), Ok(()));
    assert_eq!(
        checked_port(com2.pio_base, com2.pio_length, 7, 1),
        Ok(0x2ff)
    );
    assert_eq!(
        checked_port(com2.pio_base, com2.pio_length, 7, 2),
        Err(ModelError::InvalidArgument)
    );
    assert_eq!(
        checked_port(com2.pio_base, com2.pio_length, 8, 1),
        Err(ModelError::InvalidArgument)
    );
    assert_eq!(
        checked_port(com2.pio_base, com2.pio_length, u32::MAX, 4),
        Err(ModelError::InvalidArgument)
    );

    for protected in [
        BootResource {
            pio_base: 0x3f8,
            ..com2
        },
        BootResource {
            pio_base: 0x3f7,
            pio_length: 2,
            ..com2
        },
        BootResource {
            pio_base: 0x3ff,
            pio_length: 2,
            ..com2
        },
        BootResource {
            pio_base: 0x3f0,
            pio_length: 32,
            ..com2
        },
        BootResource {
            interrupt_source: 4,
            ..com2
        },
    ] {
        assert!(validate_boot_resources(&[protected]).is_err());
    }

    let duplicate_id = BootResource {
        pio_base: 0x2e8,
        interrupt_source: 5,
        ..com2
    };
    assert_eq!(
        validate_boot_resources(&[com2, duplicate_id]),
        Err(ModelError::AlreadyLeased)
    );
}
