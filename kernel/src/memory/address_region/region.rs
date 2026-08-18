use super::*;

impl<const SLOTS: usize> AddressRegion<SLOTS> {
    pub(crate) const fn address_space_key(&self) -> AddressSpaceKey {
        self.address_space
    }

    pub(crate) const fn region_key(&self) -> RegionKey {
        self.region
    }
    pub(super) const fn new(
        address_space: AddressSpaceKey,
        region: RegionKey,
        start: u64,
        byte_len: u64,
    ) -> Self {
        Self {
            address_space,
            region,
            start,
            byte_len,
            mappings: [None; SLOTS],
        }
    }

    pub(super) const fn validate_region_interval(
        start: u64,
        byte_len: u64,
    ) -> Result<(), AddressRegionError> {
        if byte_len == 0 {
            return Err(AddressRegionError::Empty);
        }
        if start == 0 {
            return Err(AddressRegionError::PageZero);
        }
        if !start.is_multiple_of(PAGE_SIZE) || !byte_len.is_multiple_of(PAGE_SIZE) {
            return Err(AddressRegionError::Unaligned);
        }
        let end = match start.checked_add(byte_len) {
            Some(end) => end,
            None => return Err(AddressRegionError::Overflow),
        };
        if start >= USER_CANONICAL_END || end > USER_CANONICAL_END {
            return Err(AddressRegionError::OutsideRegion);
        }
        Ok(())
    }

    pub(crate) const fn mappings(&self) -> &[Option<Mapping>; SLOTS] {
        &self.mappings
    }

    /// Consumes one D3-resolved handle into a one-shot authorization bound to
    /// this exact region. The lookup pin becomes the mapping pre-publication
    /// lifetime owner; validation failure returns the resolved handle intact.
    pub(crate) fn authorize_map<const OBJECTS: usize, const LEASES: usize>(
        &self,
        authority: &MemoryObjectAuthority<OBJECTS, LEASES>,
        resolved: ResolvedHandle,
        ceiling: Protection,
    ) -> Result<MapAuthorization, MapAuthorizationCreateError> {
        authority.issue_map_authorization(resolved, self.address_space, self.region, ceiling)
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the mapping contract keeps virtual address, backing range, effective protection, and captured source ceiling explicit at the authority boundary"
    )]
    pub(crate) fn map<
        const OBJECTS: usize,
        const LEASES: usize,
        const REGISTRY_OBJECTS: usize,
        P: AddressSpacePublisher,
    >(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        publisher: &mut P,
        virtual_start: u64,
        authorization: MapAuthorization,
        object_offset: u64,
        byte_len: u64,
        protection: Protection,
    ) -> Result<
        MappingFinalReleases<REGISTRY_OBJECTS>,
        AddressSpaceTransactionFailure<P::Error, REGISTRY_OBJECTS>,
    > {
        let mapping_authority = match authorization.capture(self.address_space, self.region) {
            Ok(authority) => authority,
            Err(error) => {
                return Err(authorization_failure(
                    registry,
                    authorization,
                    AddressRegionError::Object(error),
                ));
            }
        };
        if let Err(error) = self.validate_interval(virtual_start, byte_len) {
            return Err(authorization_failure(registry, authorization, error));
        }
        if let Err(error) = MemoryProtection::mapping(protection.bits()) {
            return Err(authorization_failure(
                registry,
                authorization,
                protection_error(error),
            ));
        }
        let mut staged = self.current_specs();
        let length = self.mapping_count();
        if length == SLOTS {
            return Err(authorization_failure(
                registry,
                authorization,
                AddressRegionError::Capacity,
            ));
        }
        let candidate = MappingSpec {
            address_space: self.address_space,
            region: self.region,
            virtual_start,
            byte_len,
            object: mapping_authority.object(),
            object_offset,
            protection,
            mapping_authority,
        };
        if staged[..length]
            .iter()
            .flatten()
            .any(|current| intersects_specs(*current, candidate))
        {
            return Err(authorization_failure(
                registry,
                authorization,
                AddressRegionError::Overlap,
            ));
        }
        staged[length] = Some(candidate);
        self.commit_specs(
            authority,
            registry,
            publisher,
            &staged,
            length + 1,
            Some(authorization),
        )
    }

    /// Maps at the lowest available page-aligned address in this region.
    ///
    /// This is the `flags = 0` allocator-chosen placement path. It advances
    /// only past existing mappings, so it considers no more than `SLOTS`
    /// occupied intervals and never searches page-by-page.
    #[allow(
        clippy::too_many_arguments,
        reason = "the allocator-chosen variant intentionally mirrors the explicit fixed-map authority contract"
    )]
    pub(crate) fn map_anywhere<
        const OBJECTS: usize,
        const LEASES: usize,
        const REGISTRY_OBJECTS: usize,
        P: AddressSpacePublisher,
    >(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        publisher: &mut P,
        authorization: MapAuthorization,
        object_offset: u64,
        byte_len: u64,
        protection: Protection,
    ) -> Result<
        (u64, MappingFinalReleases<REGISTRY_OBJECTS>),
        AddressSpaceTransactionFailure<P::Error, REGISTRY_OBJECTS>,
    > {
        if byte_len == 0 {
            return Err(authorization_failure(
                registry,
                authorization,
                AddressRegionError::Empty,
            ));
        }
        if !byte_len.is_multiple_of(PAGE_SIZE) {
            return Err(authorization_failure(
                registry,
                authorization,
                AddressRegionError::Unaligned,
            ));
        }
        if let Err(error) = MemoryProtection::mapping(protection.bits()) {
            return Err(authorization_failure(
                registry,
                authorization,
                protection_error(error),
            ));
        }
        let region_end = match self.start.checked_add(self.byte_len) {
            Some(end) => end,
            None => {
                return Err(authorization_failure(
                    registry,
                    authorization,
                    AddressRegionError::Overflow,
                ));
            }
        };
        let mut candidate = self.start;
        for _ in 0..SLOTS {
            let candidate_end = match candidate.checked_add(byte_len) {
                Some(end) => end,
                None => {
                    return Err(authorization_failure(
                        registry,
                        authorization,
                        AddressRegionError::NoSpace,
                    ));
                }
            };
            if candidate_end > region_end {
                return Err(authorization_failure(
                    registry,
                    authorization,
                    AddressRegionError::NoSpace,
                ));
            }

            let mut next_candidate = candidate;
            for mapping in self.mappings.iter().flatten().copied() {
                if candidate < mapping.end() && mapping.virtual_start < candidate_end {
                    next_candidate = next_candidate.max(mapping.end());
                }
            }
            if next_candidate == candidate {
                let final_releases = self.map(
                    authority,
                    registry,
                    publisher,
                    candidate,
                    authorization,
                    object_offset,
                    byte_len,
                    protection,
                )?;
                return Ok((candidate, final_releases));
            }
            candidate = next_candidate;
        }
        Err(authorization_failure(
            registry,
            authorization,
            AddressRegionError::NoSpace,
        ))
    }

    pub(crate) fn unmap<
        const OBJECTS: usize,
        const LEASES: usize,
        const REGISTRY_OBJECTS: usize,
        P: AddressSpacePublisher,
    >(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        publisher: &mut P,
        start: u64,
        byte_len: u64,
    ) -> Result<
        MappingFinalReleases<REGISTRY_OBJECTS>,
        AddressSpaceTransactionFailure<P::Error, REGISTRY_OBJECTS>,
    > {
        let end = self
            .checked_interval_end(start, byte_len)
            .map_err(model_failure)?;
        self.require_covered(start, end).map_err(model_failure)?;
        self.rebuild(authority, registry, publisher, start, end, None)
    }

    pub(crate) fn protect<
        const OBJECTS: usize,
        const LEASES: usize,
        const REGISTRY_OBJECTS: usize,
        P: AddressSpacePublisher,
    >(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        publisher: &mut P,
        start: u64,
        byte_len: u64,
        protection: Protection,
    ) -> Result<
        MappingFinalReleases<REGISTRY_OBJECTS>,
        AddressSpaceTransactionFailure<P::Error, REGISTRY_OBJECTS>,
    > {
        MemoryProtection::mapping(protection.bits())
            .map_err(|error| model_failure(protection_error(error)))?;
        let end = self
            .checked_interval_end(start, byte_len)
            .map_err(model_failure)?;
        self.require_covered(start, end).map_err(model_failure)?;
        self.rebuild(authority, registry, publisher, start, end, Some(protection))
    }

    fn rebuild<
        const OBJECTS: usize,
        const LEASES: usize,
        const REGISTRY_OBJECTS: usize,
        P: AddressSpacePublisher,
    >(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        publisher: &mut P,
        start: u64,
        end: u64,
        replacement_protection: Option<Protection>,
    ) -> Result<
        MappingFinalReleases<REGISTRY_OBJECTS>,
        AddressSpaceTransactionFailure<P::Error, REGISTRY_OBJECTS>,
    > {
        let mut staged = [None; SLOTS];
        let mut staged_len = 0;
        for mapping in self.mappings.iter().flatten().copied() {
            let spec = mapping.spec();
            if spec.end() <= start || spec.virtual_start >= end {
                push_spec(&mut staged, &mut staged_len, spec).map_err(model_failure)?;
                continue;
            }
            if spec.virtual_start < start {
                let slice = spec
                    .slice(
                        spec.virtual_start,
                        start - spec.virtual_start,
                        spec.protection,
                    )
                    .map_err(model_failure)?;
                push_spec(&mut staged, &mut staged_len, slice).map_err(model_failure)?;
            }
            let overlap_start = spec.virtual_start.max(start);
            let overlap_end = spec.end().min(end);
            if let Some(protection) = replacement_protection {
                let slice = spec
                    .slice(overlap_start, overlap_end - overlap_start, protection)
                    .map_err(model_failure)?;
                push_spec(&mut staged, &mut staged_len, slice).map_err(model_failure)?;
            }
            if spec.end() > end {
                let slice = spec
                    .slice(end, spec.end() - end, spec.protection)
                    .map_err(model_failure)?;
                push_spec(&mut staged, &mut staged_len, slice).map_err(model_failure)?;
            }
        }
        self.commit_specs(authority, registry, publisher, &staged, staged_len, None)
    }

    fn commit_specs<
        const OBJECTS: usize,
        const LEASES: usize,
        const REGISTRY_OBJECTS: usize,
        P: AddressSpacePublisher,
    >(
        &mut self,
        authority: &mut MemoryObjectAuthority<OBJECTS, LEASES>,
        registry: &mut ObjectRegistry<REGISTRY_OBJECTS>,
        publisher: &mut P,
        specs: &[Option<MappingSpec>; SLOTS],
        spec_len: usize,
        authorization: Option<MapAuthorization>,
    ) -> Result<
        MappingFinalReleases<REGISTRY_OBJECTS>,
        AddressSpaceTransactionFailure<P::Error, REGISTRY_OBJECTS>,
    > {
        let old_len = self.mapping_count();
        let mut released = [EMPTY_LEASE; SLOTS];
        let mut old = [EMPTY_MAPPING; SLOTS];
        for (index, mapping) in self.mappings.iter().flatten().copied().enumerate() {
            released[index] = mapping.lease;
            old[index] = mapping;
        }
        let mut requests = [LeaseRequest::EMPTY; SLOTS];
        for (index, spec) in specs[..spec_len].iter().flatten().copied().enumerate() {
            requests[index] = LeaseRequest::new(
                spec.address_space,
                spec.region,
                spec.mapping_authority,
                spec.object_offset,
                spec.byte_len,
                spec.protection,
            );
        }
        let prepared = match authority.prepare_replace::<SLOTS, REGISTRY_OBJECTS>(
            registry,
            self.address_space,
            self.region,
            &released[..old_len],
            &requests[..spec_len],
            authorization,
        ) {
            Ok(prepared) => prepared,
            Err(error) => {
                let model_error = error.error();
                return Err(AddressSpaceTransactionFailure {
                    error: AddressSpaceTransactionError::Model(AddressRegionError::Object(
                        model_error,
                    )),
                    final_releases: error.into_final_releases(),
                });
            }
        };
        let mut next_dense = [EMPTY_MAPPING; SLOTS];
        let mut next = [None; SLOTS];
        for (index, (spec, ticket)) in specs[..spec_len]
            .iter()
            .flatten()
            .copied()
            .zip(prepared.tickets().iter().flatten().copied())
            .enumerate()
        {
            let mapping = Mapping {
                address_space: spec.address_space,
                region: spec.region,
                virtual_start: spec.virtual_start,
                byte_len: spec.byte_len,
                object: ticket.object(),
                backing: ticket.range(),
                protection: ticket.protection(),
                mapping_authority: ticket.mapping_authority(),
                lease: ticket.lease(),
            };
            next_dense[index] = mapping;
            next[index] = Some(mapping);
        }
        if publisher.address_space_key() != self.address_space {
            let final_releases = prepared.rollback();
            return Err(AddressSpaceTransactionFailure {
                error: AddressSpaceTransactionError::Model(AddressRegionError::PublisherIdentity),
                final_releases,
            });
        }
        if let Err(error) = publisher.publish_replace(
            self.address_space,
            self.region,
            &old[..old_len],
            &next_dense[..spec_len],
        ) {
            let final_releases = prepared.rollback();
            return Err(AddressSpaceTransactionFailure {
                error: AddressSpaceTransactionError::Publish(error),
                final_releases,
            });
        }

        // Publication succeeded. From this point the reference transaction is
        // infallible except for fail-stop invariant corruption.
        self.mappings = next;
        Ok(prepared.commit())
    }

    fn mapping_count(&self) -> usize {
        self.mappings.iter().flatten().count()
    }

    fn current_specs(&self) -> [Option<MappingSpec>; SLOTS] {
        let mut specs = [None; SLOTS];
        for (index, mapping) in self.mappings.iter().flatten().copied().enumerate() {
            specs[index] = Some(mapping.spec());
        }
        specs
    }

    fn checked_interval_end(&self, start: u64, byte_len: u64) -> Result<u64, AddressRegionError> {
        self.validate_interval(start, byte_len)?;
        start
            .checked_add(byte_len)
            .ok_or(AddressRegionError::Overflow)
    }

    fn validate_interval(&self, start: u64, byte_len: u64) -> Result<(), AddressRegionError> {
        if byte_len == 0 {
            return Err(AddressRegionError::Empty);
        }
        if start == 0 {
            return Err(AddressRegionError::PageZero);
        }
        if !start.is_multiple_of(PAGE_SIZE) || !byte_len.is_multiple_of(PAGE_SIZE) {
            return Err(AddressRegionError::Unaligned);
        }
        let end = start
            .checked_add(byte_len)
            .ok_or(AddressRegionError::Overflow)?;
        let region_end = self
            .start
            .checked_add(self.byte_len)
            .ok_or(AddressRegionError::Overflow)?;
        if start < self.start || end > region_end || end > USER_CANONICAL_END {
            return Err(AddressRegionError::OutsideRegion);
        }
        Ok(())
    }

    fn require_covered(&self, start: u64, end: u64) -> Result<(), AddressRegionError> {
        let mut cursor = start;
        while cursor < end {
            let mapping = self
                .mappings
                .iter()
                .flatten()
                .find(|mapping| mapping.virtual_start <= cursor && cursor < mapping.end())
                .ok_or(AddressRegionError::Unmapped)?;
            cursor = mapping.end().min(end);
        }
        Ok(())
    }
}
