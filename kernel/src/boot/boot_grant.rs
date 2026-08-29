use core::sync::atomic::{AtomicU64, Ordering};

use deepwyrm_abi::DwDeviceResourceKind;

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
}

/// One kernel-internal grant. D5 supplies its owner and lease transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BootResourceGrant {
    descriptor: BootResourceDescriptor,
    grant_generation: u64,
    state: BootResourceGrantState,
}

impl BootResourceGrant {
    #[cfg(test)]
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

    #[cfg(test)]
    pub(crate) const fn len(self) -> usize {
        self.count
    }

    #[cfg(test)]
    pub(crate) const fn is_empty(self) -> bool {
        self.count == 0
    }

    #[cfg(test)]
    pub(crate) fn grant(self, index: usize) -> Option<BootResourceGrant> {
        if index >= self.count {
            return None;
        }
        self.grants[index]
    }
}

#[cfg(test)]
mod tests {
    use deepwyrm_abi::DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT;

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
}
