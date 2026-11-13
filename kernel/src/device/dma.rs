//! IOMMU DMA domains for claimed PCI functions (storage K4).
//!
//! `DW2_PCI_DEVICE_DMA_CONTRACT.md` §5. Each live PCI_FUNCTION DeviceResource
//! that maps memory gets one domain: a second-level table, a domain ID, and a
//! context entry for its bus-0 device/function. Every mapping holds a
//! reference on its MemoryObject, so the object's frames cannot be freed
//! while the device can reach them; the reference is handed back only after
//! the leaves are cleared and the IOTLB invalidated.
//!
//! The logic here is written against [`DmaHardware`], so host tests drive it
//! through a table and invalidation model; the live binding is in
//! [`live`].

use crate::arch::x86_64::vtd::tables::{
    self, DeviceAccess, TableError, TableMemory, clear_context_entry, context_entry_present,
    install_context_entry,
};
use crate::object::{InternalRef, ObjectId};

const PAGE_BYTES: u64 = 4096;
/// IOVAs start at 1 MiB, so a device that DMAs to a small or null address
/// faults instead of reaching a mapping.
pub(crate) const IOVA_BASE: u64 = 1 << 20;

/// Frames in the VT-d table pool: the root table, the bus-0 context table,
/// and every domain's second-level tables. Each frame takes one permanent
/// kernel UC leaf, so `mm::activation` sizes its leaf window from this.
pub(crate) const VTD_TABLE_POOL_FRAMES: usize = 64;

/// Domains that may exist at once (claimed functions doing DMA).
pub(crate) const DMA_DOMAINS: usize = 8;
/// Live mappings per domain.
pub(crate) const DMA_MAPPINGS_PER_DOMAIN: usize = 64;

/// The remapping hardware one set of domains drives: the table pool plus the
/// invalidations every unit must see.
pub(crate) trait DmaHardware: TableMemory {
    /// The bus-0 context table, linked into the root table at boot.
    fn context_table(&self) -> u64;
    /// One past the highest IOVA every unit translates.
    fn iova_end(&self) -> u64;
    /// The highest usable domain ID (IDs start at 1).
    fn max_domain_id(&self) -> u16;
    /// After entries go from not-present to present.
    fn after_install(&mut self, domain_id: u16);
    /// After leaves are removed: the domain's IOTLB entries, with draining.
    fn invalidate_domain(&mut self, domain_id: u16);
    /// After a context entry changes.
    fn invalidate_context(&mut self);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DmaError {
    /// Zero length, or an address that is not page-aligned.
    InvalidRange,
    /// No IOMMU, or one that cannot give this function a domain.
    NotSupported,
    /// No free domain, mapping slot or table frame.
    NoResources,
    /// No free IOVA range of the requested length.
    NoAddressSpace,
    /// No live mapping has exactly this IOVA and length.
    NotFound,
    /// Another live resource already owns a domain on this function.
    FunctionBusy,
}

struct Mapping {
    iova: u64,
    pages: u64,
    pin: InternalRef,
}

impl Mapping {
    fn end(&self) -> u64 {
        self.iova + self.pages * PAGE_BYTES
    }
}

struct Domain<const MAPPINGS: usize> {
    resource: ObjectId,
    /// The process that created the domain (its first `dma_map`). Only it
    /// may use the domain; any other process that drives the function first
    /// has the domain revoked, so a replacement driver never inherits its
    /// predecessor's IOVAs or the buffers they pin.
    owner: ObjectId,
    devfn: u8,
    domain_id: u16,
    root: u64,
    mappings: [Option<Mapping>; MAPPINGS],
}

/// The MemoryObject references a torn-down domain held, released by the
/// caller after teardown returns.
#[must_use = "each pin is a MemoryObject reference that must be released"]
pub(crate) struct DomainPins<const MAPPINGS: usize> {
    pins: [Option<InternalRef>; MAPPINGS],
}

impl<const MAPPINGS: usize> DomainPins<MAPPINGS> {
    fn empty() -> Self {
        Self {
            pins: core::array::from_fn(|_| None),
        }
    }

    pub(crate) fn into_pins(self) -> impl Iterator<Item = InternalRef> {
        self.pins.into_iter().flatten()
    }
}

pub(crate) struct DmaDomains<const DOMAINS: usize, const MAPPINGS: usize> {
    domains: [Option<Domain<MAPPINGS>>; DOMAINS],
}

impl<const DOMAINS: usize, const MAPPINGS: usize> DmaDomains<DOMAINS, MAPPINGS> {
    pub(crate) const fn new() -> Self {
        Self {
            domains: [const { None }; DOMAINS],
        }
    }

    fn domain_slot(&self, resource: ObjectId) -> Option<usize> {
        self.domains
            .iter()
            .position(|domain| domain.as_ref().is_some_and(|d| d.resource == resource))
    }

    /// Maps `pages` physically contiguous pages starting at `physical`.
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn map<H: DmaHardware>(
        &mut self,
        hardware: &mut H,
        resource: ObjectId,
        owner: ObjectId,
        devfn: u8,
        physical: u64,
        pages: u64,
        access: DeviceAccess,
        pin: InternalRef,
    ) -> Result<u64, (DmaError, InternalRef)> {
        let mut page_at = |page: u64| physical.checked_add(page.checked_mul(PAGE_BYTES)?);
        self.map_pages(
            hardware,
            resource,
            owner,
            devfn,
            &mut page_at,
            pages,
            access,
            pin,
        )
    }

    /// Maps `pages` pages for `resource`'s function on behalf of process
    /// `owner` onto one contiguous IOVA range, and returns its start.
    /// `page_at(i)` is the physical address of page `i`; the pages need not
    /// be contiguous (DW2 M3 §6.4). On success `pin` stays with the mapping;
    /// on failure it comes back unchanged. A domain another process owns is
    /// `FunctionBusy`: the caller revokes it first.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn map_pages<H: DmaHardware>(
        &mut self,
        hardware: &mut H,
        resource: ObjectId,
        owner: ObjectId,
        devfn: u8,
        page_at: &mut dyn FnMut(u64) -> Option<u64>,
        pages: u64,
        access: DeviceAccess,
        pin: InternalRef,
    ) -> Result<u64, (DmaError, InternalRef)> {
        // The first page is checked before any domain work, so a malformed
        // request changes nothing; a later bad page rolls the call back.
        if pages == 0
            || !(access.read || access.write)
            || !page_at(0).is_some_and(|physical| physical.is_multiple_of(PAGE_BYTES))
        {
            return Err((DmaError::InvalidRange, pin));
        }
        let Some(byte_len) = pages.checked_mul(PAGE_BYTES) else {
            return Err((DmaError::InvalidRange, pin));
        };

        let context_table = hardware.context_table();
        // Find the domain, or prepare a new one without publishing it.
        let (slot, fresh) = match self.domain_slot(resource) {
            Some(slot)
                if self.domains[slot]
                    .as_ref()
                    .is_some_and(|d| d.owner != owner) =>
            {
                return Err((DmaError::FunctionBusy, pin));
            }
            Some(slot) => (slot, false),
            None => {
                if self
                    .domains
                    .iter()
                    .flatten()
                    .any(|domain| domain.devfn == devfn)
                    || context_entry_present(hardware, context_table, devfn)
                {
                    return Err((DmaError::FunctionBusy, pin));
                }
                let Some(slot) = self.domains.iter().position(Option::is_none) else {
                    return Err((DmaError::NoResources, pin));
                };
                let Ok(domain_id) = u16::try_from(slot + 1) else {
                    return Err((DmaError::NoResources, pin));
                };
                if domain_id > hardware.max_domain_id() {
                    return Err((DmaError::NoResources, pin));
                }
                let Some(root) = hardware.allocate() else {
                    return Err((DmaError::NoResources, pin));
                };
                self.domains[slot] = Some(Domain {
                    resource,
                    owner,
                    devfn,
                    domain_id,
                    root,
                    mappings: core::array::from_fn(|_| None),
                });
                (slot, true)
            }
        };
        let domain = self.domains[slot].as_mut().expect("selected domain exists");

        let result = (|| {
            let mapping_slot = domain
                .mappings
                .iter()
                .position(Option::is_none)
                .ok_or(DmaError::NoResources)?;
            let iova = free_range(&domain.mappings, byte_len, hardware.iova_end())
                .ok_or(DmaError::NoAddressSpace)?;
            for page in 0..pages {
                let offset = page * PAGE_BYTES;
                let mapped = match page_at(page) {
                    Some(physical) if physical.is_multiple_of(PAGE_BYTES) => {
                        tables::map_page(hardware, domain.root, iova + offset, physical, access)
                    }
                    _ => Err(TableError::InvalidAddress),
                };
                if let Err(error) = mapped {
                    for undo in 0..page {
                        tables::unmap_page(hardware, domain.root, iova + undo * PAGE_BYTES)
                            .expect("a leaf this call installed is still mapped");
                    }
                    return Err(match error {
                        TableError::NoTables => DmaError::NoResources,
                        TableError::InvalidAddress => DmaError::InvalidRange,
                        TableError::Occupied | TableError::NotMapped => {
                            panic!("a free IOVA range had a mapped page")
                        }
                    });
                }
            }
            Ok((mapping_slot, iova))
        })();

        match result {
            Ok((mapping_slot, iova)) => {
                if fresh {
                    install_context_entry(
                        hardware,
                        context_table,
                        devfn,
                        domain.root,
                        domain.domain_id,
                    );
                    hardware.invalidate_context();
                }
                hardware.after_install(domain.domain_id);
                domain.mappings[mapping_slot] = Some(Mapping { iova, pages, pin });
                Ok(iova)
            }
            Err(error) => {
                if fresh {
                    // Never published: no context entry names these tables.
                    tables::free_tree(hardware, domain.root);
                    self.domains[slot] = None;
                } else {
                    // A device may have used a leaf this call installed
                    // before it was cleared again.
                    hardware.invalidate_domain(domain.domain_id);
                }
                Err((error, pin))
            }
        }
    }

    /// Removes `owner`'s mapping at exactly `iova` with `pages` pages,
    /// invalidates the IOTLB, and returns the MemoryObject reference it held.
    pub(crate) fn unmap<H: DmaHardware>(
        &mut self,
        hardware: &mut H,
        resource: ObjectId,
        owner: ObjectId,
        iova: u64,
        pages: u64,
    ) -> Result<InternalRef, DmaError> {
        let slot = self.domain_slot(resource).ok_or(DmaError::NotFound)?;
        let domain = self.domains[slot].as_mut().expect("selected domain exists");
        if domain.owner != owner {
            return Err(DmaError::NotFound);
        }
        let index = domain
            .mappings
            .iter()
            .position(|m| {
                m.as_ref()
                    .is_some_and(|m| m.iova == iova && m.pages == pages)
            })
            .ok_or(DmaError::NotFound)?;
        for page in 0..pages {
            tables::unmap_page(hardware, domain.root, iova + page * PAGE_BYTES)
                .expect("a recorded mapping has every leaf present");
        }
        hardware.invalidate_domain(domain.domain_id);
        let mapping = domain.mappings[index]
            .take()
            .expect("selected mapping exists");
        Ok(mapping.pin)
    }

    /// The process that owns `resource`'s domain, if it has one.
    pub(crate) fn owner(&self, resource: ObjectId) -> Option<ObjectId> {
        self.domain_slot(resource)
            .and_then(|slot| self.domains[slot].as_ref())
            .map(|domain| domain.owner)
    }

    /// The PCI device/function `resource`'s domain covers, if it has one.
    pub(crate) fn devfn(&self, resource: ObjectId) -> Option<u8> {
        self.domain_slot(resource)
            .and_then(|slot| self.domains[slot].as_ref())
            .map(|domain| domain.devfn)
    }

    /// Tears `resource`'s domain down: the context entry goes first, so the
    /// function loses every translation at once; then the context cache and
    /// the domain's IOTLB are invalidated, and only then are the tables freed
    /// and the MemoryObject references handed back. The caller clears bus
    /// mastering before this.
    pub(crate) fn teardown<H: DmaHardware>(
        &mut self,
        hardware: &mut H,
        resource: ObjectId,
    ) -> DomainPins<MAPPINGS> {
        let Some(slot) = self.domain_slot(resource) else {
            return DomainPins::empty();
        };
        let domain = self.domains[slot].take().expect("selected domain exists");
        let context_table = hardware.context_table();
        clear_context_entry(hardware, context_table, domain.devfn);
        hardware.invalidate_context();
        hardware.invalidate_domain(domain.domain_id);
        tables::free_tree(hardware, domain.root);
        let mut pins = DomainPins::empty();
        for (pin, mapping) in pins.pins.iter_mut().zip(domain.mappings) {
            *pin = mapping.map(|mapping| mapping.pin);
        }
        pins
    }

    #[cfg(test)]
    pub(crate) fn live_domains(&self) -> usize {
        self.domains.iter().flatten().count()
    }
}

/// What the device syscalls need from the domains.
pub(crate) trait DmaService {
    /// Revokes `resource`'s domain when a process other than `process` owns
    /// it: bus mastering off first, then the domain torn down (see
    /// [`DmaDomains::teardown`]); each released MemoryObject reference goes
    /// to `release`. Every syscall that drives a function (bus mastering,
    /// BAR objects, DMA mappings) calls this first. Only a caller whose
    /// handle may drive DMA (`may_revoke`) takes a domain over; for any other
    /// caller a foreign domain is `FunctionBusy` and stays untouched.
    fn revoke_foreign(
        &mut self,
        resource: ObjectId,
        process: ObjectId,
        may_revoke: bool,
        release: &mut dyn FnMut(InternalRef),
    ) -> Result<(), DmaError>;
    /// Maps `pages` pages, page `i` at physical `page_at(i)`, onto one
    /// contiguous IOVA range (see [`DmaDomains::map_pages`]).
    #[allow(clippy::too_many_arguments)]
    fn map(
        &mut self,
        resource: ObjectId,
        owner: ObjectId,
        devfn: u8,
        page_at: &mut dyn FnMut(u64) -> Option<u64>,
        pages: u64,
        access: DeviceAccess,
        pin: InternalRef,
    ) -> Result<u64, (DmaError, InternalRef)>;
    fn unmap(
        &mut self,
        resource: ObjectId,
        owner: ObjectId,
        iova: u64,
        pages: u64,
    ) -> Result<InternalRef, DmaError>;
}

/// Domains bound to one piece of hardware, for host tests of the syscalls.
#[cfg(test)]
pub(crate) struct DmaEngine<'a, H: DmaHardware, const DOMAINS: usize, const MAPPINGS: usize> {
    pub(crate) hardware: &'a mut H,
    pub(crate) domains: &'a mut DmaDomains<DOMAINS, MAPPINGS>,
}

#[cfg(test)]
impl<H: DmaHardware, const DOMAINS: usize, const MAPPINGS: usize> DmaService
    for DmaEngine<'_, H, DOMAINS, MAPPINGS>
{
    fn revoke_foreign(
        &mut self,
        resource: ObjectId,
        process: ObjectId,
        may_revoke: bool,
        release: &mut dyn FnMut(InternalRef),
    ) -> Result<(), DmaError> {
        if self
            .domains
            .owner(resource)
            .is_some_and(|owner| owner != process)
        {
            if !may_revoke {
                return Err(DmaError::FunctionBusy);
            }
            // Host tests have no command register; the live service clears
            // bus mastering here first.
            for pin in self.domains.teardown(self.hardware, resource).into_pins() {
                release(pin);
            }
        }
        Ok(())
    }

    fn map(
        &mut self,
        resource: ObjectId,
        owner: ObjectId,
        devfn: u8,
        page_at: &mut dyn FnMut(u64) -> Option<u64>,
        pages: u64,
        access: DeviceAccess,
        pin: InternalRef,
    ) -> Result<u64, (DmaError, InternalRef)> {
        self.domains.map_pages(
            self.hardware,
            resource,
            owner,
            devfn,
            page_at,
            pages,
            access,
            pin,
        )
    }

    fn unmap(
        &mut self,
        resource: ObjectId,
        owner: ObjectId,
        iova: u64,
        pages: u64,
    ) -> Result<InternalRef, DmaError> {
        self.domains
            .unmap(self.hardware, resource, owner, iova, pages)
    }
}

/// Tears down the finalizing DeviceResource's domain, if it has one, and
/// returns the MemoryObject references its mappings held.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) fn release_domain(resource: ObjectId) -> DomainPins<DMA_MAPPINGS_PER_DOMAIN> {
    live::teardown(resource)
}

/// Host builds have no live IOMMU, so no resource ever has a domain.
#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
pub(crate) fn release_domain(_resource: ObjectId) -> DomainPins<DMA_MAPPINGS_PER_DOMAIN> {
    DomainPins::empty()
}

/// The lowest IOVA at or above [`IOVA_BASE`] where `byte_len` bytes overlap
/// no mapping and end at or below `end`.
fn free_range(mappings: &[Option<Mapping>], byte_len: u64, end: u64) -> Option<u64> {
    let mut candidate = IOVA_BASE;
    loop {
        let candidate_end = candidate.checked_add(byte_len)?;
        if candidate_end > end {
            return None;
        }
        match mappings
            .iter()
            .flatten()
            .filter(|m| m.iova < candidate_end && candidate < m.end())
            .map(Mapping::end)
            .max()
        {
            Some(next) => candidate = next,
            None => return Some(candidate),
        }
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub(crate) mod live;

#[cfg(test)]
mod tests;
