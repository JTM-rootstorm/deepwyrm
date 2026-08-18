use super::*;

impl<const SPACES: usize, const REGIONS: usize> AddressSpaceAuthority<SPACES, REGIONS> {
    /// Creates a root/region registry with a process-lifetime-unique domain.
    ///
    /// # Safety
    ///
    /// The caller must install this as the sole registry for every
    /// architecture page-table root registered through it, must never
    /// register the same root through another authority, and must retain this
    /// authority for at least as long as every region and publisher identity
    /// it issues. Target integration confines this boundary to the global
    /// address-space owner.
    #[allow(
        unsafe_code,
        reason = "physical page-table-root uniqueness and registry lifetime are architecture facts"
    )]
    pub(crate) unsafe fn new() -> Self {
        Self {
            domain: mint_authority_domain(),
            spaces: [EMPTY_ADDRESS_SPACE_SLOT; SPACES],
            regions: [EMPTY_REGION_SLOT; REGIONS],
        }
    }

    /// Registers one architecture-owned page-table root identity.
    pub(crate) fn create_address_space(&mut self) -> Result<AddressSpaceKey, AddressRegionError> {
        let slot = self
            .spaces
            .iter()
            .position(|space| !space.active)
            .ok_or(AddressRegionError::Capacity)?;
        let generation = next_generation(self.spaces[slot].generation)?;
        self.spaces[slot] = AddressSpaceSlot {
            generation,
            active: true,
        };
        Ok(AddressSpaceKey {
            domain: self.domain,
            raw: encode_key(slot, generation),
        })
    }

    /// Creates one nonoverlapping sibling region in `address_space`.
    pub(crate) fn create_region<const SLOTS: usize>(
        &mut self,
        address_space: AddressSpaceKey,
        start: u64,
        byte_len: u64,
    ) -> Result<AddressRegion<SLOTS>, AddressRegionError> {
        let address_space_slot = self.address_space_slot(address_space)?;
        AddressRegion::<SLOTS>::validate_region_interval(start, byte_len)?;
        let end = start
            .checked_add(byte_len)
            .ok_or(AddressRegionError::Overflow)?;
        if self
            .regions
            .iter()
            .filter_map(|slot| slot.record)
            .any(|record| {
                record.address_space_slot == address_space_slot
                    && start < record.start + record.byte_len
                    && record.start < end
            })
        {
            return Err(AddressRegionError::Overlap);
        }
        let slot = self
            .regions
            .iter()
            .position(|region| region.record.is_none())
            .ok_or(AddressRegionError::Capacity)?;
        let generation = next_generation(self.regions[slot].generation)?;
        self.regions[slot] = RegionSlot {
            generation,
            record: Some(RegionRecord {
                address_space_slot,
                start,
                byte_len,
            }),
        };
        Ok(AddressRegion::new(
            address_space,
            RegionKey {
                domain: self.domain,
                raw: encode_key(slot, generation),
            },
            start,
            byte_len,
        ))
    }

    pub(super) fn release_region<const SLOTS: usize>(
        &mut self,
        region: &AddressRegion<SLOTS>,
    ) -> Result<(), AddressRegionError> {
        if region.mappings().iter().any(Option::is_some) {
            return Err(AddressRegionError::LiveMappings);
        }
        let address_space_slot = self.address_space_slot(region.address_space_key())?;
        if region.region_key().domain == 0 || region.region_key().domain != self.domain {
            return Err(AddressRegionError::OutsideRegion);
        }
        let (slot, generation) =
            decode_key(region.region_key().raw).ok_or(AddressRegionError::OutsideRegion)?;
        let entry = self
            .regions
            .get_mut(slot)
            .ok_or(AddressRegionError::OutsideRegion)?;
        if entry.generation != generation
            || entry.record
                != Some(RegionRecord {
                    address_space_slot,
                    start: region.start,
                    byte_len: region.byte_len,
                })
        {
            return Err(AddressRegionError::OutsideRegion);
        }
        entry.record = None;
        Ok(())
    }

    pub(super) fn release_address_space(
        &mut self,
        key: AddressSpaceKey,
    ) -> Result<(), AddressRegionError> {
        let slot = self.address_space_slot(key)?;
        if self
            .regions
            .iter()
            .filter_map(|region| region.record)
            .any(|region| region.address_space_slot == slot)
        {
            return Err(AddressRegionError::LiveRegions);
        }
        self.spaces[slot].active = false;
        Ok(())
    }

    fn address_space_slot(&self, key: AddressSpaceKey) -> Result<usize, AddressRegionError> {
        if key.domain == 0 || key.domain != self.domain {
            return Err(AddressRegionError::OutsideRegion);
        }
        let (slot, generation) = decode_key(key.raw).ok_or(AddressRegionError::OutsideRegion)?;
        let entry = self
            .spaces
            .get(slot)
            .ok_or(AddressRegionError::OutsideRegion)?;
        if !entry.active || entry.generation != generation {
            return Err(AddressRegionError::OutsideRegion);
        }
        Ok(slot)
    }
}
