use super::*;

impl<const OBJECTS: usize, const LEASES: usize> MemoryObjectAuthority<OBJECTS, LEASES> {
    pub(in super::super) fn prepare_replace<
        'a,
        const BATCH: usize,
        const REGISTRY_OBJECTS: usize,
    >(
        &'a mut self,
        registry: &'a mut ObjectRegistry<REGISTRY_OBJECTS>,
        address_space: AddressSpaceKey,
        region: RegionKey,
        released: &[MappingLease],
        requested: &[LeaseRequest],
        authorization: Option<MapAuthorization>,
    ) -> Result<
        PreparedReplace<'a, OBJECTS, LEASES, BATCH, REGISTRY_OBJECTS>,
        PrepareReplaceError<REGISTRY_OBJECTS>,
    > {
        let plan = match self.plan_replace(
            address_space,
            region,
            released,
            requested,
            authorization.as_ref(),
        ) {
            Ok(plan) => plan,
            Err(error) => {
                let mut final_releases = MappingFinalReleases::empty();
                if let Some(authorization) = authorization {
                    release_map_authorization(registry, authorization, &mut final_releases);
                }
                return Err(PrepareReplaceError {
                    error,
                    final_releases,
                });
            }
        };

        let mut extra_pins: [Option<InternalRef>; BATCH] = core::array::from_fn(|_| None);
        for extra_index in 0..plan.extra_len {
            let source =
                match plan.extra_sources[extra_index].expect("planned extra pin has a source") {
                    ExistingPinSource::Released(position) => {
                        let slot = plan.released[position];
                        &self.leases[slot]
                            .record
                            .as_ref()
                            .expect("validated released lease still exists")
                            .pin
                    }
                    ExistingPinSource::Authorization => {
                        &authorization
                            .as_ref()
                            .expect("planned authorization source remains present")
                            .pin
                    }
                };
            match registry.retain_internal(source) {
                Ok(pin) => extra_pins[extra_index] = Some(pin),
                Err(_) => {
                    let mut final_releases = MappingFinalReleases::empty();
                    for pin in extra_pins.iter_mut().filter_map(Option::take) {
                        release_internal_pin(registry, pin, &mut final_releases);
                    }
                    if let Some(authorization) = authorization {
                        release_map_authorization(registry, authorization, &mut final_releases);
                    }
                    return Err(PrepareReplaceError {
                        error: MemoryObjectError::ObjectReference,
                        final_releases,
                    });
                }
            }
        }

        Ok(PreparedReplace {
            authority: self,
            registry,
            plan,
            extra_pins,
            authorization,
            finished: false,
        })
    }

    fn plan_replace<const BATCH: usize>(
        &self,
        address_space: AddressSpaceKey,
        region: RegionKey,
        released: &[MappingLease],
        requested: &[LeaseRequest],
        authorization: Option<&MapAuthorization>,
    ) -> Result<ReplacePlan<BATCH>, MemoryObjectError> {
        if !address_space.same_domain(region) {
            return Err(MemoryObjectError::ForeignLease);
        }
        if released.is_empty() && requested.is_empty() {
            return Err(MemoryObjectError::Empty);
        }
        if released.len() > BATCH || requested.len() > BATCH {
            return Err(MemoryObjectError::LeaseCapacity);
        }

        let mut release_slots = [usize::MAX; BATCH];
        for (position, lease) in released.iter().copied().enumerate() {
            let slot = self.lease_slot(lease)?;
            let record = self.leases[slot]
                .record
                .as_ref()
                .expect("validated lease slot has a record");
            if record.metadata.address_space != address_space || record.metadata.region != region {
                return Err(MemoryObjectError::ForeignLease);
            }
            if release_slots[..position].contains(&slot) {
                return Err(MemoryObjectError::DuplicateLease);
            }
            release_slots[position] = slot;
        }

        let mut writable = [false; OBJECTS];
        let mut executable = [false; OBJECTS];
        for (slot, lease) in self.leases.iter().enumerate() {
            let Some(record) = lease.record.as_ref() else {
                continue;
            };
            if release_slots[..released.len()].contains(&slot) {
                continue;
            }
            writable[record.metadata.object_slot] |= record.metadata.protection.writable();
            executable[record.metadata.object_slot] |= record.metadata.protection.executable();
        }

        let reusable_slots = self
            .leases
            .iter()
            .enumerate()
            .filter(|(slot, lease)| {
                lease.record.is_none() || release_slots[..released.len()].contains(slot)
            })
            .count();
        if requested.len() > reusable_slots {
            return Err(MemoryObjectError::LeaseCapacity);
        }

        let mut pending: [Option<PendingLease>; BATCH] = core::array::from_fn(|_| None);
        let mut tickets = [None; BATCH];
        let mut extra_sources: [Option<ExistingPinSource>; BATCH] = core::array::from_fn(|_| None);
        let mut extra_len = 0;
        let mut released_used = [false; BATCH];
        let mut authorization_used = false;
        let mut candidate_cursor = 0;

        for (position, request) in requested.iter().copied().enumerate() {
            if request.address_space != address_space || request.region != region {
                return Err(MemoryObjectError::ForeignLease);
            }
            let object_key = request.mapping_authority.object();
            let object_slot = self.object_slot(object_key)?;
            let object = self.objects[object_slot]
                .record
                .expect("validated object slot has a record");
            MemoryProtection::mapping(request.protection.0)?;
            MemoryProtection::ceiling(request.mapping_authority.ceiling().0)?;
            if !object
                .protection_ceiling
                .contains(request.mapping_authority.ceiling())
                || !request
                    .mapping_authority
                    .ceiling()
                    .contains(request.protection)
            {
                return Err(MemoryObjectError::ProtectionCeiling);
            }
            if matches!(object.kind, MemoryObjectKind::ImmutableBootModule)
                && request.protection.writable()
            {
                return Err(MemoryObjectError::ProtectionCeiling);
            }
            let range = object_range(object, request.object_offset, request.byte_len)?;
            if (request.protection.writable() && executable[object_slot])
                || (request.protection.executable() && writable[object_slot])
            {
                return Err(MemoryObjectError::WritableExecutableAlias);
            }
            writable[object_slot] |= request.protection.writable();
            executable[object_slot] |= request.protection.executable();

            let object_id = object.object;
            let released_source = (0..released.len()).find(|released_position| {
                !released_used[*released_position]
                    && self.leases[release_slots[*released_position]]
                        .record
                        .as_ref()
                        .is_some_and(|record| record.pin.id() == object_id)
            });
            let pin_source = if let Some(released_position) = released_source {
                released_used[released_position] = true;
                PendingPinSource::Released(released_position)
            } else if !authorization_used
                && authorization.is_some_and(|authorization| authorization.object_id() == object_id)
            {
                authorization_used = true;
                PendingPinSource::Authorization
            } else {
                let source = (0..released.len())
                    .find(|released_position| {
                        self.leases[release_slots[*released_position]]
                            .record
                            .as_ref()
                            .is_some_and(|record| record.pin.id() == object_id)
                    })
                    .map(ExistingPinSource::Released)
                    .or_else(|| {
                        authorization
                            .filter(|authorization| authorization.object_id() == object_id)
                            .map(|_| ExistingPinSource::Authorization)
                    })
                    .ok_or(MemoryObjectError::ObjectReference)?;
                if extra_len == BATCH {
                    return Err(MemoryObjectError::LeaseCapacity);
                }
                extra_sources[extra_len] = Some(source);
                let source_index = extra_len;
                extra_len += 1;
                PendingPinSource::Extra(source_index)
            };
            let slot = loop {
                let slot = candidate_cursor;
                candidate_cursor += 1;
                if self.leases[slot].record.is_none()
                    || release_slots[..released.len()].contains(&slot)
                {
                    break slot;
                }
            };
            let generation = next_generation(self.leases[slot].generation)?;
            let lease = MappingLease {
                domain: self.domain,
                raw: encode_raw_key(slot, generation),
            };
            let metadata = LeaseMetadata {
                address_space,
                region,
                object_slot,
                range,
                protection: request.protection,
                mapping_authority: request.mapping_authority,
            };
            pending[position] = Some(PendingLease {
                slot,
                generation,
                metadata,
                pin_source,
            });
            tickets[position] = Some(LeaseTicket {
                lease,
                object: object_key,
                range,
                protection: request.protection,
                mapping_authority: request.mapping_authority,
            });
        }

        if authorization.is_some() && !authorization_used {
            return Err(MemoryObjectError::ObjectReference);
        }

        Ok(ReplacePlan {
            released: release_slots,
            released_len: released.len(),
            pending,
            pending_len: requested.len(),
            tickets,
            extra_sources,
            extra_len,
        })
    }
}

impl<const OBJECTS: usize, const LEASES: usize, const BATCH: usize, const REGISTRY_OBJECTS: usize>
    PreparedReplace<'_, OBJECTS, LEASES, BATCH, REGISTRY_OBJECTS>
{
    pub(in super::super) fn tickets(&self) -> &[Option<LeaseTicket>] {
        &self.plan.tickets[..self.plan.pending_len]
    }

    /// Finalizes reference ownership only after page-table publication.
    /// Existing pins transfer where possible; surplus pins are released only
    /// after every replacement lease has acquired its exact lifetime owner.
    pub(in super::super) fn commit(mut self) -> MappingFinalReleases<REGISTRY_OBJECTS> {
        let mut released_records: [Option<LeaseRecord>; BATCH] = core::array::from_fn(|_| None);
        for (position, record) in released_records
            .iter_mut()
            .enumerate()
            .take(self.plan.released_len)
        {
            let slot = self.plan.released[position];
            *record = self.authority.leases[slot].record.take();
        }

        for position in 0..self.plan.pending_len {
            let pending = self.plan.pending[position]
                .take()
                .expect("planned mapping lease is present");
            let pin = match pending.pin_source {
                PendingPinSource::Released(released_position) => {
                    released_records[released_position]
                        .take()
                        .expect("reused released lease pin remains available")
                        .pin
                }
                PendingPinSource::Authorization => {
                    self.authorization
                        .take()
                        .expect("planned authorization pin remains available")
                        .pin
                }
                PendingPinSource::Extra(extra_index) => self.extra_pins[extra_index]
                    .take()
                    .expect("planned extra mapping pin remains available"),
            };
            self.authority.leases[pending.slot] = LeaseSlot {
                generation: pending.generation,
                record: Some(LeaseRecord {
                    metadata: pending.metadata,
                    pin,
                }),
            };
        }

        let mut final_releases = MappingFinalReleases::empty();
        for record in released_records.into_iter().flatten() {
            release_internal_pin(self.registry, record.pin, &mut final_releases);
        }
        if let Some(authorization) = self.authorization.take() {
            release_map_authorization(self.registry, authorization, &mut final_releases);
        }
        for pin in self.extra_pins.iter_mut().filter_map(Option::take) {
            release_internal_pin(self.registry, pin, &mut final_releases);
        }
        self.finished = true;
        final_releases
    }

    /// Aborts a prepared replacement before page-table publication.
    /// Committed old leases remain untouched; only speculative extra and
    /// authorization pins are released.
    pub(in super::super) fn rollback(mut self) -> MappingFinalReleases<REGISTRY_OBJECTS> {
        let mut final_releases = MappingFinalReleases::empty();
        for pin in self.extra_pins.iter_mut().filter_map(Option::take) {
            release_internal_pin(self.registry, pin, &mut final_releases);
        }
        if let Some(authorization) = self.authorization.take() {
            release_map_authorization(self.registry, authorization, &mut final_releases);
        }
        self.finished = true;
        final_releases
    }
}

impl<const OBJECTS: usize, const LEASES: usize, const BATCH: usize, const REGISTRY_OBJECTS: usize>
    Drop for PreparedReplace<'_, OBJECTS, LEASES, BATCH, REGISTRY_OBJECTS>
{
    fn drop(&mut self) {
        assert!(
            self.finished,
            "prepared mapping reference transaction dropped without commit/rollback"
        );
    }
}
