use super::*;

impl<const OBJECTS: usize, const LEASES: usize> MemoryObjectAuthority<OBJECTS, LEASES> {
    #[allow(
        clippy::result_large_err,
        reason = "the error returns the final releases of the pins it let go; the kernel has no heap to box them into"
    )]
    #[allow(
        clippy::too_many_arguments,
        reason = "the transaction borrows the registry and the caller's plan beside its own description"
    )]
    pub(in super::super) fn prepare_replace<
        'a,
        const BATCH: usize,
        const REGISTRY_OBJECTS: usize,
    >(
        &'a mut self,
        registry: &'a mut ObjectRegistry<REGISTRY_OBJECTS>,
        plan: &'a mut ReplacePlan<BATCH>,
        address_space: AddressSpaceKey,
        region: RegionKey,
        released: &[MappingLease],
        requested: &[LeaseRequest],
        removed: &[RemovedRange],
        authorization: Option<MapAuthorization>,
    ) -> Result<PreparedReplace<'a, OBJECTS, LEASES, BATCH, REGISTRY_OBJECTS>, PrepareReplaceError>
    {
        const {
            assert!(
                BATCH <= MAX_MAPPING_BATCH,
                "a replace batch must fit one final-release batch"
            );
        }
        match self.plan_replace(
            plan,
            address_space,
            region,
            released,
            requested,
            authorization.as_ref(),
        ) {
            Ok(()) => {}
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

        // Removed translations of on-demand objects (DW2 §10.9 items 1, 3):
        // the hull for the record, and a coverage pin for each object no
        // removed lease's pin stays held for, retained while failure is
        // still allowed. Each object needs at most max(its held pins, 1)
        // entries, at most its released leases, so `UnmappedLeasePins`
        // keeps its bound.
        let mut coverage_pins: [Option<InternalRef>; BATCH] = core::array::from_fn(|_| None);
        let coverage = self
            .plan_removed(plan, released.len(), removed)
            .and_then(|()| {
                for index in 0..plan.removed_len {
                    let (object_slot, _, _) = plan.removed[index].expect("planned removal");
                    let Some(source) = self.unreused_or_any_released_pin(plan, object_slot) else {
                        return Err(MemoryObjectError::ObjectReference);
                    };
                    let Some(source) = source else {
                        continue;
                    };
                    let pin = registry
                        .retain_internal(source)
                        .map_err(|_| MemoryObjectError::ObjectReference)?;
                    coverage_pins[index] = Some(pin);
                }
                Ok(())
            });
        if let Err(error) = coverage {
            let mut final_releases = MappingFinalReleases::empty();
            for pin in extra_pins
                .iter_mut()
                .chain(coverage_pins.iter_mut())
                .filter_map(Option::take)
            {
                release_internal_pin(registry, pin, &mut final_releases);
            }
            if let Some(authorization) = authorization {
                release_map_authorization(registry, authorization, &mut final_releases);
            }
            return Err(PrepareReplaceError {
                error,
                final_releases,
            });
        }

        Ok(PreparedReplace {
            authority: self,
            registry,
            plan,
            extra_pins,
            coverage_pins,
            authorization,
            finished: false,
        })
    }

    /// Fills `plan.removed` with one hull per on-demand object of `removed`.
    fn plan_removed<const BATCH: usize>(
        &self,
        plan: &mut ReplacePlan<BATCH>,
        released_len: usize,
        removed: &[RemovedRange],
    ) -> Result<(), MemoryObjectError> {
        plan.removed.fill(None);
        plan.removed_len = 0;
        for range in removed {
            if range.first_page >= range.end_page {
                continue;
            }
            let object_slot = self.object_slot(range.object)?;
            let record = self.objects[object_slot]
                .record
                .expect("validated object slot has a record");
            if record.kind != MemoryObjectKind::OnDemand {
                continue;
            }
            // Only an object some released lease belonged to can lose a
            // translation.
            if !plan.released[..released_len].iter().any(|&slot| {
                self.leases[slot]
                    .record
                    .as_ref()
                    .is_some_and(|lease| lease.metadata.object_slot == object_slot)
            }) {
                return Err(MemoryObjectError::ObjectReference);
            }
            if let Some(entry) = plan.removed[..plan.removed_len]
                .iter_mut()
                .flatten()
                .find(|(slot, _, _)| *slot == object_slot)
            {
                entry.1 = entry.1.min(range.first_page);
                entry.2 = entry.2.max(range.end_page);
                continue;
            }
            if plan.removed_len == BATCH {
                return Err(MemoryObjectError::LeaseCapacity);
            }
            plan.removed[plan.removed_len] = Some((object_slot, range.first_page, range.end_page));
            plan.removed_len += 1;
        }
        Ok(())
    }

    /// For an object losing translations: `Some(None)` when one of its
    /// released leases' pins is not reused, so commit holds it anyway;
    /// `Some(Some(pin))` naming a released lease's pin to retain a
    /// coverage pin from; `None` if no released lease is the object's.
    fn unreused_or_any_released_pin<const BATCH: usize>(
        &self,
        plan: &ReplacePlan<BATCH>,
        object_slot: usize,
    ) -> Option<Option<&InternalRef>> {
        let mut any = None;
        for (position, &slot) in plan.released[..plan.released_len].iter().enumerate() {
            let Some(record) = self.leases[slot].record.as_ref() else {
                continue;
            };
            if record.metadata.object_slot != object_slot {
                continue;
            }
            let reused = plan.pending[..plan.pending_len].iter().flatten().any(|pending| {
                matches!(pending.pin_source, PendingPinSource::Released(used) if used == position)
            });
            if !reused {
                return Some(None);
            }
            any = Some(&record.pin);
        }
        any.map(Some)
    }

    /// Validates a replacement and fills `plan` in place.
    fn plan_replace<const BATCH: usize>(
        &self,
        plan: &mut ReplacePlan<BATCH>,
        address_space: AddressSpaceKey,
        region: RegionKey,
        released: &[MappingLease],
        requested: &[LeaseRequest],
        authorization: Option<&MapAuthorization>,
    ) -> Result<(), MemoryObjectError> {
        if !address_space.same_domain(region) {
            return Err(MemoryObjectError::ForeignLease);
        }
        if released.is_empty() && requested.is_empty() {
            return Err(MemoryObjectError::Empty);
        }
        if released.len() > BATCH || requested.len() > BATCH {
            return Err(MemoryObjectError::LeaseCapacity);
        }

        let ReplacePlan {
            released: release_slots,
            released_len: plan_released_len,
            pending,
            pending_len: plan_pending_len,
            tickets,
            extra_sources,
            extra_len: plan_extra_len,
            ..
        } = plan;
        release_slots.fill(usize::MAX);
        pending.fill(None);
        tickets.fill(None);
        extra_sources.fill(None);
        *plan_released_len = 0;
        *plan_pending_len = 0;
        *plan_extra_len = 0;
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
                (lease.record.is_none() || release_slots[..released.len()].contains(slot))
                    && next_generation(lease.generation).is_ok()
            })
            .count();
        if requested.len() > reusable_slots {
            return Err(MemoryObjectError::LeaseCapacity);
        }

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
            // The map's authorization goes to the first lease of its object,
            // so it is used even when the new piece merges into an existing
            // mapping (DW2 M4b); a pin it displaces is surplus. Pins of one
            // object are interchangeable.
            let pin_source = if !authorization_used
                && authorization.is_some_and(|authorization| authorization.object_id() == object_id)
            {
                authorization_used = true;
                PendingPinSource::Authorization
            } else if let Some(released_position) = released_source {
                released_used[released_position] = true;
                PendingPinSource::Released(released_position)
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
                if candidate_cursor == LEASES {
                    return Err(MemoryObjectError::LeaseCapacity);
                }
                let slot = candidate_cursor;
                candidate_cursor += 1;
                if (self.leases[slot].record.is_none()
                    || release_slots[..released.len()].contains(&slot))
                    && next_generation(self.leases[slot].generation).is_ok()
                {
                    break slot;
                }
            };
            let generation = next_generation(self.leases[slot].generation)
                .expect("candidate lease generation was prevalidated");
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

        *plan_released_len = released.len();
        *plan_pending_len = requested.len();
        *plan_extra_len = extra_len;
        Ok(())
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
    /// The pins of removed leases come back unreleased, as
    /// [`super::UnmappedLeasePins`]: remote TLBs may still map their frames
    /// until the shootdown settles.
    pub(in super::super) fn commit(mut self) -> MappingFinalReleases {
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
        // Removed leases keep their pins until the removal is acknowledged
        // (H0 §12.6): the caller releases them on the settlement.
        for record in released_records.into_iter().flatten() {
            final_releases.push_unmapped(record.pin);
        }
        for pin in self.coverage_pins.iter_mut().filter_map(Option::take) {
            final_releases.push_unmapped(pin);
        }
        for (object_slot, first, end) in self.plan.removed[..self.plan.removed_len]
            .iter()
            .flatten()
            .copied()
        {
            let record = self.authority.objects[object_slot]
                .record
                .as_mut()
                .expect("a planned on-demand object outlives its transaction");
            record.released = Some(match record.released {
                Some((low, high)) => (low.min(first), high.max(end)),
                None => (first, end),
            });
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
    pub(in super::super) fn rollback(mut self) -> MappingFinalReleases {
        let mut final_releases = MappingFinalReleases::empty();
        for pin in self
            .extra_pins
            .iter_mut()
            .chain(self.coverage_pins.iter_mut())
            .filter_map(Option::take)
        {
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
