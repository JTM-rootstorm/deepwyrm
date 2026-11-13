//! `dma_map` and `dma_unmap` (storage K4) through the real handle, rights and
//! MemoryObject checks, with the domains replaced by a recording fake; the
//! domain logic itself is tested in `device::dma`.

use super::*;
use crate::arch::x86_64::vtd::tables::DeviceAccess;
use crate::device::dma::{DmaError, DmaService};
use crate::device::{DeviceResourceAuthority, DeviceResourceDescriptor};
use crate::object::ObjectId;
use deepwyrm_abi::{
    DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION, DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
    DW_DMA_ACCESS_DEVICE_READ, DW_DMA_ACCESS_DEVICE_WRITE, DW_RIGHT_MAP, DW_RIGHT_READ,
    DW_RIGHT_WRITE, DW_STATUS_NO_MEMORY, DW_STATUS_NOT_FOUND,
};

const IOVA: u64 = 0x10_0000;
const OUT: u64 = BASE + 0x200;

#[derive(Default)]
struct FakeDma {
    mappings: std::vec::Vec<(ObjectId, u8, u64, u64, DeviceAccess, InternalRef)>,
    fail_with: Option<DmaError>,
    /// Each `revoke_foreign` call: the resource and the calling process.
    revoke_checks: std::vec::Vec<(ObjectId, ObjectId)>,
    /// Whether another process owns the domain, so a caller that may not
    /// revoke it is refused.
    foreign_domain: bool,
    /// The process every mapping was made for.
    owners: std::vec::Vec<ObjectId>,
    /// Pins a revocation hands back, as a foreign owner's would.
    revoked: std::vec::Vec<InternalRef>,
}

impl DmaService for FakeDma {
    fn revoke_foreign(
        &mut self,
        resource: ObjectId,
        process: ObjectId,
        may_revoke: bool,
        release: &mut dyn FnMut(InternalRef),
    ) -> Result<(), DmaError> {
        self.revoke_checks.push((resource, process));
        if self.foreign_domain && !may_revoke {
            return Err(DmaError::FunctionBusy);
        }
        self.foreign_domain = false;
        for pin in self.revoked.drain(..) {
            release(pin);
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
        if let Some(error) = self.fail_with {
            return Err((error, pin));
        }
        // Records the first page; every page must resolve, one after another.
        let Some(physical) = page_at(0) else {
            return Err((DmaError::InvalidRange, pin));
        };
        for page in 1..pages {
            if page_at(page) != Some(physical + page * 4096) {
                return Err((DmaError::InvalidRange, pin));
            }
        }
        let iova = IOVA + (self.mappings.len() as u64) * 0x10_0000;
        self.owners.push(owner);
        self.mappings
            .push((resource, devfn, physical, pages, access, pin));
        Ok(iova)
    }

    fn unmap(
        &mut self,
        resource: ObjectId,
        owner: ObjectId,
        iova: u64,
        pages: u64,
    ) -> Result<InternalRef, DmaError> {
        let index = usize::try_from((iova - IOVA) / 0x10_0000).unwrap();
        match self.mappings.get(index) {
            Some(mapping)
                if mapping.0 == resource && mapping.3 == pages && self.owners[index] == owner =>
            {
                self.owners.remove(index);
                Ok(self.mappings.remove(index).5)
            }
            _ => Err(DmaError::NotFound),
        }
    }
}

struct Fixture {
    registry: ObjectRegistry<16>,
    tasks: Tasks,
    process: ProcessKey,
    domain: crate::task::TaskGroupKey,
    user: FakeUserMemory,
    backing: TestBacking,
    memory: MemoryObjectAuthority<4, 4>,
    devices: DeviceResourceAuthority<4>,
    cleanup: CleanupQueue<16>,
    dma: FakeDma,
}

impl Fixture {
    fn new() -> Self {
        let mut registry = ObjectRegistry::<16>::new();
        let mut tasks = Tasks::new();
        let (domain, root_owner) = tasks.create_root_group(&mut registry).unwrap();
        let (process, process_ref) = tasks.create_process(&mut registry, &root_owner).unwrap();
        assert!(registry.release_internal(root_owner).unwrap().is_none());
        tasks
            .process_handles_mut(process)
            .unwrap()
            .install(process_ref, DW_RIGHT_INSPECT)
            .unwrap();
        Self {
            registry,
            tasks,
            process,
            domain,
            user: FakeUserMemory::new(),
            backing: TestBacking::new(),
            memory: MemoryObjectAuthority::new(),
            devices: DeviceResourceAuthority::new(),
            cleanup: CleanupQueue::new(),
            dma: FakeDma::default(),
        }
    }

    fn resource(
        &mut self,
        kind: deepwyrm_abi::DwDeviceResourceKind,
        pci_address: u32,
        rights: DwRights,
    ) -> DwHandle {
        let pci = kind == DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION;
        let table = self.tasks.process_handles_mut(self.process).unwrap();
        self.devices
            .create(
                &mut self.registry,
                table,
                DeviceResourceDescriptor {
                    resource_id: u64::from(pci_address) + 1,
                    lease_generation: 1,
                    kind,
                    pio_base: if pci { 0 } else { 0x2f8 },
                    pio_length: if pci { 0 } else { 8 },
                    interrupt_source: if pci { 0 } else { 3 },
                    pci_address: if pci { pci_address } else { 0 },
                    pci_ids: if pci { 0x1042_1af4 } else { 0 },
                    resource_domain: self.domain,
                },
                rights,
            )
            .unwrap()
            .1
    }

    /// A function on bus 0, device 1, function 2.
    fn function(&mut self) -> DwHandle {
        self.resource(
            DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION,
            (1 << 3) | 2,
            DwRights(DW_RIGHT_MODIFY.0 | DW_RIGHT_READ.0),
        )
    }

    fn object(&mut self, pages: u64, rights: DwRights) -> DwHandle {
        let out = DwUserAddress(BASE + 0x100);
        assert_eq!(
            memory_object_create(
                &mut self.user,
                &mut self.backing,
                &mut self.registry,
                &mut self.memory,
                &mut self.tasks,
                self.process,
                pages * 4096,
                0,
                rights,
                out,
                &mut self.cleanup,
            ),
            DW_STATUS_SUCCESS
        );
        DwHandle(u64_at(&self.user, out.0))
    }

    fn map(
        &mut self,
        resource: DwHandle,
        object: DwHandle,
        offset: u64,
        byte_len: u64,
        access: u32,
    ) -> DwStatus {
        dma_map(
            &mut self.user,
            &mut self.registry,
            &self.memory,
            &mut self.tasks,
            &self.devices,
            &mut self.dma,
            &self.backing.roles,
            self.process,
            resource,
            object,
            offset,
            byte_len,
            access,
            DwUserAddress(OUT),
            &mut self.cleanup,
        )
    }

    fn unmap(&mut self, resource: DwHandle, iova: u64, byte_len: u64) -> DwStatus {
        dma_unmap(
            &mut self.registry,
            &mut self.tasks,
            &self.devices,
            &mut self.dma,
            self.process,
            resource,
            iova,
            byte_len,
            &mut self.cleanup,
        )
    }

    fn mmio_object(&mut self, resource: DwHandle) -> DwStatus {
        device_mmio_object_create(
            &mut self.user,
            &mut self.registry,
            &mut self.memory,
            &mut self.tasks,
            &self.devices,
            &mut self.dma,
            self.process,
            resource,
            0,
            DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0),
            DwUserAddress(OUT),
            &mut self.cleanup,
        )
    }

    fn pci_command(&mut self, resource: DwHandle, bus_master: u32) -> DwStatus {
        let mut config = NoConfig;
        device_pci_command(
            &mut self.registry,
            &mut self.tasks,
            &self.devices,
            &mut config,
            &mut self.dma,
            self.process,
            resource,
            1,
            bus_master,
            |_| true,
            &mut self.cleanup,
        )
    }

    /// Another live process's identity.
    fn other_process(&mut self) -> ObjectId {
        let creation = self
            .registry
            .create(deepwyrm_abi::DW_OBJECT_TYPE_PROCESS)
            .unwrap();
        self.registry.creation_into_internal(creation).unwrap().id()
    }

    fn close(&mut self, handle: DwHandle) -> Option<FinalRelease> {
        self.tasks
            .process_handles_mut(self.process)
            .unwrap()
            .close(&mut self.registry, handle)
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // As the other adapter tests do: the process's live handle table is
        // never torn down in a host test, so forget it rather than drain it.
        core::mem::forget(core::mem::replace(&mut self.tasks, Tasks::new()));
    }
}

fn read_write_map() -> DwRights {
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0)
}

#[test]
fn dma_map_hands_the_object_range_and_function_to_the_domain_and_reports_the_iova() {
    let mut fixture = Fixture::new();
    let resource = fixture.function();
    let object = fixture.object(4, read_write_map());
    let access = DW_DMA_ACCESS_DEVICE_READ | DW_DMA_ACCESS_DEVICE_WRITE;

    assert_eq!(
        fixture.map(resource, object, 4096, 2 * 4096, access),
        DW_STATUS_SUCCESS
    );
    assert_eq!(u64_at(&fixture.user, OUT), IOVA);
    let (_, devfn, physical, pages, device, _) = fixture.dma.mappings[0];
    assert_eq!((devfn, pages), ((1 << 3) | 2, 2));
    assert_eq!(
        device,
        DeviceAccess {
            read: true,
            write: true
        }
    );
    assert!(physical.is_multiple_of(4096));
    // The same object from offset 0 starts one page earlier.
    assert_eq!(
        fixture.map(resource, object, 0, 4096, DW_DMA_ACCESS_DEVICE_READ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(u64_at(&fixture.user, OUT), IOVA + 0x10_0000);
    assert_eq!(fixture.dma.mappings[1].2 + 4096, physical);
    assert_eq!(
        fixture.dma.mappings[1].4,
        DeviceAccess {
            read: true,
            write: false
        }
    );
}

#[test]
fn a_mapping_keeps_its_object_alive_until_unmap_hands_the_reference_to_cleanup() {
    let mut fixture = Fixture::new();
    let resource = fixture.function();
    let object = fixture.object(1, read_write_map());
    assert_eq!(
        fixture.map(resource, object, 0, 4096, DW_DMA_ACCESS_DEVICE_READ),
        DW_STATUS_SUCCESS
    );
    // The handle is no longer the last reference.
    assert!(fixture.close(object).is_none());

    assert_eq!(fixture.unmap(resource, IOVA, 2 * 4096), DW_STATUS_NOT_FOUND);
    assert_eq!(
        fixture.unmap(resource, IOVA + 1, 4096),
        DW_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(fixture.unmap(resource, IOVA, 0), DW_STATUS_INVALID_ARGUMENT);
    assert_eq!(fixture.cleanup.len, 0);
    assert_eq!(fixture.unmap(resource, IOVA, 4096), DW_STATUS_SUCCESS);
    assert_eq!(
        fixture.cleanup.len, 1,
        "the mapping held the last reference"
    );
}

#[test]
fn device_writes_need_the_write_right_and_access_must_be_a_known_nonzero_mask() {
    let mut fixture = Fixture::new();
    let resource = fixture.function();
    let read_only = fixture.object(1, DwRights(DW_RIGHT_READ.0 | DW_RIGHT_MAP.0));

    assert_eq!(
        fixture.map(resource, read_only, 0, 4096, DW_DMA_ACCESS_DEVICE_WRITE),
        DW_STATUS_ACCESS_DENIED
    );
    for access in [0, 4, DW_DMA_ACCESS_DEVICE_READ | 8] {
        assert_eq!(
            fixture.map(resource, read_only, 0, 4096, access),
            DW_STATUS_INVALID_ARGUMENT
        );
    }
    assert_eq!(
        fixture.map(resource, read_only, 0, 4096, DW_DMA_ACCESS_DEVICE_READ),
        DW_STATUS_SUCCESS
    );
}

#[test]
fn ranges_must_be_page_aligned_nonempty_and_inside_the_object() {
    let mut fixture = Fixture::new();
    let resource = fixture.function();
    let object = fixture.object(2, read_write_map());
    for (offset, byte_len) in [
        (0, 0),
        (1, 4096),
        (0, 100),
        (4096, 2 * 4096),
        (!0xfff, 4096),
    ] {
        assert_eq!(
            fixture.map(
                resource,
                object,
                offset,
                byte_len,
                DW_DMA_ACCESS_DEVICE_READ
            ),
            DW_STATUS_INVALID_ARGUMENT,
            "offset {offset:#x} length {byte_len:#x}"
        );
    }
    assert!(fixture.dma.mappings.is_empty());
    // No lookup pin leaked: the handle is still the object's only reference.
    assert!(fixture.close(object).is_some());
}

#[test]
fn only_a_bus_zero_pci_function_with_modify_can_map() {
    let mut fixture = Fixture::new();
    let object = fixture.object(1, read_write_map());
    let read = DW_DMA_ACCESS_DEVICE_READ;

    let pio = fixture.resource(
        DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
        0,
        DwRights(DW_RIGHT_MODIFY.0),
    );
    assert_eq!(
        fixture.map(pio, object, 0, 4096, read),
        DW_STATUS_INVALID_ARGUMENT
    );
    let other_bus = fixture.resource(
        DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION,
        1 << 8,
        DwRights(DW_RIGHT_MODIFY.0),
    );
    assert_eq!(
        fixture.map(other_bus, object, 0, 4096, read),
        DW_STATUS_NOT_SUPPORTED
    );
    let read_only = fixture.resource(
        DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION,
        2 << 3,
        DwRights(DW_RIGHT_READ.0),
    );
    assert_eq!(
        fixture.map(read_only, object, 0, 4096, read),
        DW_STATUS_ACCESS_DENIED
    );
    assert_eq!(
        fixture.unmap(read_only, IOVA, 4096),
        DW_STATUS_ACCESS_DENIED
    );
    assert!(fixture.dma.mappings.is_empty());
}

#[test]
fn domain_failures_map_to_statuses_and_return_the_reference() {
    let mut fixture = Fixture::new();
    let resource = fixture.function();
    let object = fixture.object(1, read_write_map());
    for (error, status) in [
        (DmaError::NotSupported, DW_STATUS_NOT_SUPPORTED),
        (DmaError::NoResources, DW_STATUS_NO_RESOURCES),
        (DmaError::NoAddressSpace, DW_STATUS_NO_MEMORY),
        (DmaError::FunctionBusy, DW_STATUS_BAD_STATE),
    ] {
        fixture.dma.fail_with = Some(error);
        assert_eq!(
            fixture.map(resource, object, 0, 4096, DW_DMA_ACCESS_DEVICE_READ),
            status
        );
        assert_eq!(u64_at(&fixture.user, OUT), 0, "out_iova is untouched");
    }
    assert!(
        fixture.close(object).is_some(),
        "every failed map released its pin"
    );
}

#[test]
fn device_mmio_objects_cannot_be_dma_targets() {
    let mut fixture = Fixture::new();
    let resource = fixture.function();
    // A DeviceMmio object over a synthetic BAR, parented on the resource.
    let parent = fixture
        .tasks
        .process_handles_mut(fixture.process)
        .unwrap()
        .lookup(
            &mut fixture.registry,
            resource,
            crate::handle::AcceptedObjectTypes::Any,
            DW_RIGHT_MODIFY,
        )
        .unwrap()
        .into_internal();
    let creation = fixture
        .registry
        .create(deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT)
        .unwrap();
    let binding = fixture
        .memory
        .bind_device_mmio(
            creation,
            crate::memory::frame_roles::synthetic_device_mmio_backing(0xe6_0000_0000, 1),
            parent,
        )
        .unwrap();
    let bound = fixture.registry.finish_payload_binding(binding).unwrap();
    let reference = fixture.registry.bound_into_handle(bound).unwrap();
    let object = fixture
        .tasks
        .process_handles_mut(fixture.process)
        .unwrap()
        .install(reference, read_write_map())
        .unwrap();
    assert_eq!(
        fixture.map(resource, object, 0, 4096, DW_DMA_ACCESS_DEVICE_READ),
        DW_STATUS_NOT_SUPPORTED
    );
    assert!(fixture.dma.mappings.is_empty());
}

/// Storage K4 follow-up R2: every map and unmap first asks the domains to
/// revoke a domain another process owns, as the calling process, and the
/// mapping is made for that process. References a revocation hands back go
/// to cleanup, so the last one finalizes its object.
#[test]
fn map_and_unmap_revoke_a_foreign_domain_first_and_act_as_the_caller() {
    let mut fixture = Fixture::new();
    let resource = fixture.function();
    let object = fixture.object(1, read_write_map());
    let caller = fixture.process.object_id();

    // A predecessor's mapping whose object has no other reference left.
    let orphan = fixture.object(1, read_write_map());
    let orphan_pin = {
        let table = fixture.tasks.process_handles_mut(fixture.process).unwrap();
        let resolved = table
            .lookup(
                &mut fixture.registry,
                orphan,
                crate::handle::AcceptedObjectTypes::One(deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT),
                DW_RIGHT_READ,
            )
            .unwrap();
        resolved.into_internal()
    };
    assert!(fixture.close(orphan).is_none());
    fixture.dma.revoked.push(orphan_pin);

    assert_eq!(
        fixture.map(resource, object, 0, 4096, DW_DMA_ACCESS_DEVICE_READ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(fixture.dma.revoke_checks.len(), 1);
    assert_eq!(fixture.dma.revoke_checks[0].1, caller);
    assert_eq!(fixture.dma.owners, [caller]);
    // The revoked reference was the orphan's last: it is queued for cleanup.
    assert_eq!(fixture.cleanup.len, 1);

    assert_eq!(fixture.unmap(resource, IOVA, 4096), DW_STATUS_SUCCESS);
    assert_eq!(fixture.dma.revoke_checks.len(), 2);
    assert_eq!(fixture.dma.revoke_checks[1], fixture.dma.revoke_checks[0]);
}

/// A config space no test reaches: every case here stops before the command
/// register is touched.
struct NoConfig;

impl crate::device::pci::ConfigSpace for NoConfig {
    fn read32(&mut self, _: crate::device::pci::PciAddress, _: u8) -> u32 {
        panic!("the command register was reached")
    }
    fn write32(&mut self, _: crate::device::pci::PciAddress, _: u8, _: u32) {
        panic!("the command register was reached")
    }
}

/// Storage review K2: while another process holds a live BAR object of the
/// function, nothing gives the function DMA reach for the caller, and its
/// domain is not touched either: `dma_map` and turning bus mastering on are
/// `BAD_STATE`, and so is a BAR object of its own.
#[test]
fn a_predecessors_live_bar_object_blocks_dma_and_bus_mastering() {
    let mut fixture = Fixture::new();
    // Bus 0, device 3, function 1: a boot resource ID no other test uses,
    // since the probe table is global.
    let address = (3 << 3) | 1;
    let resource = fixture.resource(
        DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION,
        address,
        DwRights(DW_RIGHT_MODIFY.0 | DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0),
    );
    let predecessor = fixture.other_process();
    crate::device::pci::PCI_FUNCTIONS.record_lent_for_test(
        u64::from(address) + 1,
        0xe7_0000_0000,
        predecessor,
    );
    let object = fixture.object(1, read_write_map());

    assert_eq!(
        fixture.map(resource, object, 0, 4096, DW_DMA_ACCESS_DEVICE_READ),
        DW_STATUS_BAD_STATE
    );
    assert_eq!(fixture.pci_command(resource, 1), DW_STATUS_BAD_STATE);
    assert_eq!(fixture.mmio_object(resource), DW_STATUS_BAD_STATE);
    assert!(fixture.dma.revoke_checks.is_empty(), "nothing was revoked");
    assert!(fixture.dma.mappings.is_empty());
}

/// Storage review K3: a holder of MAP alone cannot take a domain over from
/// another process; one whose handle may drive DMA can.
#[test]
fn only_a_handle_that_may_drive_dma_revokes_a_foreign_domain() {
    let mut fixture = Fixture::new();
    // Bus 0, device 4: a probe-table ID no other test uses. It has no BAR
    // backing, so a creation that gets past revocation is `NOT_FOUND`.
    let map_only = fixture.resource(DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION, 4 << 3, DW_RIGHT_MAP);
    fixture.dma.foreign_domain = true;
    assert_eq!(fixture.mmio_object(map_only), DW_STATUS_BAD_STATE);
    assert!(fixture.dma.foreign_domain, "the domain was left alone");

    let driver = fixture.resource(
        DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION,
        5 << 3,
        DwRights(DW_RIGHT_MAP.0 | DW_RIGHT_MODIFY.0),
    );
    assert_eq!(fixture.mmio_object(driver), DW_STATUS_NOT_FOUND);
    assert!(!fixture.dma.foreign_domain, "the domain was revoked");
}

/// Review M6-1: `dma_map`'s fill-in commits only for a caller whose resource
/// `dma_map` would accept, and then needs MAP on the object as well, so a
/// READ-only holder with a bogus resource commits nothing.
#[test]
fn dma_fill_in_commits_only_for_an_accepted_resource_and_a_mappable_object() {
    let mut fixture = Fixture::new();
    let function = fixture.function();
    let pio = fixture.resource(
        DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
        0,
        DwRights(DW_RIGHT_MODIFY.0 | DW_RIGHT_READ.0),
    );
    let unmodifiable = fixture.resource(
        DW_DEVICE_RESOURCE_KIND_PCI_FUNCTION,
        (2 << 3) | 1,
        DW_RIGHT_READ,
    );
    let rights = |fixture: &mut Fixture, resource, access| {
        dma_map_commit_rights(
            &mut fixture.registry,
            &mut fixture.tasks,
            &fixture.devices,
            fixture.process,
            resource,
            access,
        )
    };
    // Refusals `dma_map` itself would make: nothing is committed for them.
    for (resource, access) in [
        (function, 0),
        (function, 1 << 7),
        (DwHandle(0xdead), DW_DMA_ACCESS_DEVICE_READ),
        (pio, DW_DMA_ACCESS_DEVICE_READ),
        (unmodifiable, DW_DMA_ACCESS_DEVICE_READ),
    ] {
        assert_eq!(
            rights(&mut fixture, resource, access),
            None,
            "{resource:?} {access:#x}"
        );
    }
    let read = rights(&mut fixture, function, DW_DMA_ACCESS_DEVICE_READ).unwrap();
    assert_eq!(read, DwRights(DW_RIGHT_READ.0 | DW_RIGHT_MAP.0));
    let write = rights(
        &mut fixture,
        function,
        DW_DMA_ACCESS_DEVICE_READ | DW_DMA_ACCESS_DEVICE_WRITE,
    )
    .unwrap();
    assert_eq!(
        write,
        DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0)
    );
    // A READ-only handle cannot have its object committed by a DMA map.
    let object = fixture.object(1, DW_RIGHT_READ);
    assert_eq!(
        memory_object_commit_target(
            &mut fixture.registry,
            &mut fixture.tasks,
            &fixture.memory,
            fixture.process,
            object,
            0,
            4096,
            read,
        ),
        Err(deepwyrm_abi::DW_STATUS_ACCESS_DENIED)
    );
}
