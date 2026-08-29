extern crate std;

use deepwyrm_abi::{
    DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT, DW_OBJECT_INFO_DEVICE_RESOURCE_V1,
    DW_OBJECT_TYPE_DEVICE_RESOURCE, DW_OBJECT_TYPE_EVENT, DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT,
    DW_RIGHT_MODIFY, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WRITE, DW_STATUS_ACCESS_DENIED,
    DW_STATUS_BAD_HANDLE, DW_STATUS_INVALID_ARGUMENT, DW_STATUS_WRONG_OBJECT_TYPE, DwHandle,
    DwObjectType, DwRights, dw_object_compatible_rights,
};

use crate::arch::x86_64::io_port::{BytePortIo, ScalarPortIo};
use crate::handle::{HandleMoveRequest, HandleTable, HandleTableError};
use crate::object::{FinalRelease, InternalRef, ObjectRegistry};
use crate::service::ObjectInfoResult;
use crate::task::{TaskAuthority, TaskGroupKey};

use super::*;

type Registry = ObjectRegistry<16>;
type Table = HandleTable<16>;
type Tasks = TaskAuthority<2, 1, 1, 16>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PortOperation {
    Read { width: u32, port: u16 },
    Write { width: u32, port: u16, value: u32 },
}

#[derive(Default)]
struct MockPortIo {
    operations: std::vec::Vec<PortOperation>,
}

impl BytePortIo for MockPortIo {
    fn read_u8(&mut self, port: u16) -> u8 {
        self.operations.push(PortOperation::Read { width: 1, port });
        0xa5
    }

    fn write_u8(&mut self, port: u16, value: u8) {
        self.operations.push(PortOperation::Write {
            width: 1,
            port,
            value: u32::from(value),
        });
    }
}

impl ScalarPortIo for MockPortIo {
    fn read_u16(&mut self, port: u16) -> u16 {
        self.operations.push(PortOperation::Read { width: 2, port });
        0xbeef
    }

    fn read_u32(&mut self, port: u16) -> u32 {
        self.operations.push(PortOperation::Read { width: 4, port });
        0xdead_beef
    }

    fn write_u16(&mut self, port: u16, value: u16) {
        self.operations.push(PortOperation::Write {
            width: 2,
            port,
            value: u32::from(value),
        });
    }

    fn write_u32(&mut self, port: u16, value: u32) {
        self.operations.push(PortOperation::Write {
            width: 4,
            port,
            value,
        });
    }
}

fn rights(bits: &[DwRights]) -> DwRights {
    DwRights(bits.iter().fold(0, |mask, right| mask | right.0))
}

fn owner_domain(registry: &mut Registry) -> (Tasks, TaskGroupKey, InternalRef) {
    let mut tasks = Tasks::new();
    let (domain, owner) = tasks.create_root_group(registry).unwrap();
    (tasks, domain, owner)
}

fn descriptor(resource_id: u64, domain: TaskGroupKey) -> DeviceResourceDescriptor {
    DeviceResourceDescriptor {
        resource_id,
        lease_generation: resource_id + 100,
        kind: DW_DEVICE_RESOURCE_KIND_X86_PIO_WITH_PLATFORM_INTERRUPT,
        pio_base: 0x2f8,
        pio_length: 8,
        interrupt_source: 3,
        resource_domain: domain,
    }
}

fn install_resource<const RESOURCES: usize>(
    registry: &mut Registry,
    resources: &DeviceResourceAuthority<RESOURCES>,
    table: &mut Table,
    descriptor: DeviceResourceDescriptor,
    held: DwRights,
) -> (DeviceResourceKey, DwHandle) {
    resources.create(registry, table, descriptor, held).unwrap()
}

fn install_generic(
    registry: &mut Registry,
    table: &mut Table,
    object_type: DwObjectType,
    held: DwRights,
) -> DwHandle {
    let creation = registry.create(object_type).unwrap();
    let reference = registry.creation_into_handle(creation).unwrap();
    table.install(reference, held).unwrap()
}

fn finalize_resource<const RESOURCES: usize>(
    registry: &mut Registry,
    resources: &DeviceResourceAuthority<RESOURCES>,
    final_release: FinalRelease,
) {
    let finalization = resources.take_finalization(final_release).unwrap();
    complete_device_resource_finalization(registry, finalization);
}

fn close_and_finalize<const RESOURCES: usize>(
    registry: &mut Registry,
    resources: &DeviceResourceAuthority<RESOURCES>,
    table: &mut Table,
    handle: DwHandle,
) {
    let final_release = table.close(registry, handle).unwrap().unwrap();
    finalize_resource(registry, resources, final_release);
}

#[test]
fn scalar_reads_and_writes_use_exact_width_and_boundary_port_once() {
    let mut registry = Registry::new();
    let (_tasks, domain, _owner) = owner_domain(&mut registry);
    let resources = DeviceResourceAuthority::<1>::new();
    let mut table = Table::new();
    let held = rights(&[
        DW_RIGHT_READ,
        DW_RIGHT_WRITE,
        DW_RIGHT_INSPECT,
        DW_RIGHT_DUPLICATE,
        DW_RIGHT_TRANSFER,
    ]);
    let (_, handle) = install_resource(
        &mut registry,
        &resources,
        &mut table,
        descriptor(1, domain),
        held,
    );
    let mut io = MockPortIo::default();

    for (offset, width, expected) in [
        (0, 1, 0xa5),
        (7, 1, 0xa5),
        (0, 2, 0xbeef),
        (6, 2, 0xbeef),
        (0, 4, 0xdead_beef),
        (4, 4, 0xdead_beef),
    ] {
        assert_eq!(
            pio_read(
                &table,
                &mut registry,
                &resources,
                &mut io,
                handle,
                offset,
                width,
            ),
            Ok(expected)
        );
    }
    for (offset, width, value) in [
        (0, 1, 0x5a),
        (7, 1, 0xa5),
        (0, 2, 0x1234),
        (6, 2, 0xbeef),
        (0, 4, 0x1234_5678),
        (4, 4, 0xdead_beef),
    ] {
        assert_eq!(
            pio_write(
                &table,
                &mut registry,
                &resources,
                &mut io,
                handle,
                offset,
                width,
                value,
            ),
            Ok(())
        );
    }

    assert_eq!(
        io.operations,
        std::vec![
            PortOperation::Read {
                width: 1,
                port: 0x2f8
            },
            PortOperation::Read {
                width: 1,
                port: 0x2ff
            },
            PortOperation::Read {
                width: 2,
                port: 0x2f8
            },
            PortOperation::Read {
                width: 2,
                port: 0x2fe
            },
            PortOperation::Read {
                width: 4,
                port: 0x2f8
            },
            PortOperation::Read {
                width: 4,
                port: 0x2fc
            },
            PortOperation::Write {
                width: 1,
                port: 0x2f8,
                value: 0x5a
            },
            PortOperation::Write {
                width: 1,
                port: 0x2ff,
                value: 0xa5
            },
            PortOperation::Write {
                width: 2,
                port: 0x2f8,
                value: 0x1234
            },
            PortOperation::Write {
                width: 2,
                port: 0x2fe,
                value: 0xbeef
            },
            PortOperation::Write {
                width: 4,
                port: 0x2f8,
                value: 0x1234_5678
            },
            PortOperation::Write {
                width: 4,
                port: 0x2fc,
                value: 0xdead_beef
            },
        ]
    );
    close_and_finalize(&mut registry, &resources, &mut table, handle);
}

#[test]
fn malformed_accesses_and_write_truncation_fail_before_backend_io() {
    let mut registry = Registry::new();
    let (_tasks, domain, _owner) = owner_domain(&mut registry);
    let resources = DeviceResourceAuthority::<1>::new();
    let mut table = Table::new();
    let (_, handle) = install_resource(
        &mut registry,
        &resources,
        &mut table,
        descriptor(2, domain),
        dw_object_compatible_rights(DW_OBJECT_TYPE_DEVICE_RESOURCE),
    );
    let mut io = MockPortIo::default();

    for (offset, width) in [
        (0, 0),
        (0, 3),
        (0, 8),
        (0, u32::MAX),
        (8, 1),
        (7, 2),
        (5, 4),
        (u32::MAX, 4),
    ] {
        assert_eq!(
            pio_read(
                &table,
                &mut registry,
                &resources,
                &mut io,
                handle,
                offset,
                width,
            ),
            Err(DW_STATUS_INVALID_ARGUMENT)
        );
    }
    for (width, value) in [(1, 0x100), (2, 0x1_0000)] {
        assert_eq!(
            pio_write(
                &table,
                &mut registry,
                &resources,
                &mut io,
                handle,
                0,
                width,
                value,
            ),
            Err(DW_STATUS_INVALID_ARGUMENT)
        );
    }
    assert!(io.operations.is_empty());
    assert_eq!(resources.live_count(), 1);
    close_and_finalize(&mut registry, &resources, &mut table, handle);
}

#[test]
fn checked_port_conversion_rejects_namespace_crossing_before_io() {
    let mut registry = Registry::new();
    let (_tasks, domain, _owner) = owner_domain(&mut registry);
    let valid = descriptor(3, domain);

    assert!(
        super::resource::checked_pio_access(
            DeviceResourceDescriptor {
                pio_base: u16::MAX,
                pio_length: 1,
                ..valid
            },
            0,
            1,
        )
        .is_ok()
    );
    for descriptor in [
        DeviceResourceDescriptor {
            pio_base: u16::MAX,
            pio_length: 2,
            ..valid
        },
        DeviceResourceDescriptor {
            pio_base: u16::MAX - 1,
            pio_length: 4,
            ..valid
        },
    ] {
        assert_eq!(
            super::resource::checked_pio_access(descriptor, 0, u32::from(descriptor.pio_length)),
            Err(DeviceResourceError::InvalidAccess)
        );
    }
}

#[test]
fn invalid_creation_rolls_back_generic_and_typed_capacity() {
    let mut registry = Registry::new();
    let (_tasks, domain, _owner) = owner_domain(&mut registry);
    let resources = DeviceResourceAuthority::<1>::new();
    let mut table = Table::new();

    let valid = descriptor(10, domain);
    let invalid = [
        DeviceResourceDescriptor {
            resource_id: 0,
            ..valid
        },
        DeviceResourceDescriptor {
            lease_generation: 0,
            ..valid
        },
        DeviceResourceDescriptor {
            kind: deepwyrm_abi::DwDeviceResourceKind(0),
            ..valid
        },
        DeviceResourceDescriptor {
            kind: deepwyrm_abi::DwDeviceResourceKind(u32::MAX),
            ..valid
        },
        DeviceResourceDescriptor {
            pio_length: 0,
            ..valid
        },
        DeviceResourceDescriptor {
            pio_base: u16::MAX,
            pio_length: 2,
            ..valid
        },
        DeviceResourceDescriptor {
            interrupt_source: 0,
            ..valid
        },
    ];
    for descriptor in invalid {
        assert_eq!(
            resources.create(&mut registry, &mut table, descriptor, DW_RIGHT_INSPECT,),
            Err(DeviceResourceCreateError::Resource(
                DeviceResourceError::InvalidDescriptor
            ))
        );
        assert_eq!(resources.live_count(), 0);
    }

    let (_, handle) = resources
        .create(&mut registry, &mut table, valid, DW_RIGHT_INSPECT)
        .unwrap();
    assert_eq!(resources.live_count(), 1);
    close_and_finalize(&mut registry, &resources, &mut table, handle);
}

#[test]
fn first_handle_publication_failure_rolls_back_every_reservation() {
    let mut registry = Registry::new();
    let (_tasks, domain, _owner) = owner_domain(&mut registry);
    let resources = DeviceResourceAuthority::<1>::new();
    let mut table = Table::new();

    assert_eq!(
        resources.create(
            &mut registry,
            &mut table,
            descriptor(11, domain),
            DwRights(0),
        ),
        Err(DeviceResourceCreateError::Publication(
            crate::handle::HandleReservationError::Conflict
        ))
    );
    assert_eq!(resources.live_count(), 0);
    assert!(table.is_empty());

    let (_, replacement) = resources
        .create(
            &mut registry,
            &mut table,
            descriptor(11, domain),
            DW_RIGHT_INSPECT,
        )
        .unwrap();
    close_and_finalize(&mut registry, &resources, &mut table, replacement);
}

#[test]
fn protected_com1_and_irq4_are_rejected_by_the_typed_factory() {
    let mut registry = Registry::new();
    let (_tasks, domain, _owner) = owner_domain(&mut registry);
    let resources = DeviceResourceAuthority::<1>::new();
    let mut table = Table::new();
    let valid = descriptor(12, domain);

    for protected in [
        DeviceResourceDescriptor {
            pio_base: 0x3f8,
            pio_length: 8,
            ..valid
        },
        DeviceResourceDescriptor {
            pio_base: 0x3f7,
            pio_length: 2,
            ..valid
        },
        DeviceResourceDescriptor {
            pio_base: 0x3ff,
            pio_length: 2,
            ..valid
        },
        DeviceResourceDescriptor {
            pio_base: 0x3f0,
            pio_length: 32,
            ..valid
        },
        DeviceResourceDescriptor {
            interrupt_source: 4,
            ..valid
        },
    ] {
        assert_eq!(
            resources.create(&mut registry, &mut table, protected, DW_RIGHT_INSPECT,),
            Err(DeviceResourceCreateError::Resource(
                DeviceResourceError::InvalidDescriptor
            ))
        );
        assert_eq!(resources.live_count(), 0);
        assert!(table.is_empty());
    }
}

#[test]
fn rights_wrong_type_and_stale_generation_fail_before_io() {
    let mut registry = Registry::new();
    let (_tasks, domain, _owner) = owner_domain(&mut registry);
    let resources = DeviceResourceAuthority::<4>::new();
    let mut table = Table::new();
    let full = dw_object_compatible_rights(DW_OBJECT_TYPE_DEVICE_RESOURCE);
    let (_, source) = install_resource(
        &mut registry,
        &resources,
        &mut table,
        descriptor(20, domain),
        full,
    );
    let read_only = table
        .duplicate(&mut registry, source, DW_RIGHT_READ)
        .unwrap();
    let write_only = table
        .duplicate(&mut registry, source, DW_RIGHT_WRITE)
        .unwrap();
    let driver = table
        .duplicate(
            &mut registry,
            source,
            rights(&[DW_RIGHT_READ, DW_RIGHT_WRITE, DW_RIGHT_INSPECT]),
        )
        .unwrap();
    let wrong = install_generic(
        &mut registry,
        &mut table,
        DW_OBJECT_TYPE_EVENT,
        dw_object_compatible_rights(DW_OBJECT_TYPE_EVENT),
    );
    let mut io = MockPortIo::default();

    assert_eq!(
        pio_write(
            &table,
            &mut registry,
            &resources,
            &mut io,
            read_only,
            0,
            1,
            1,
        ),
        Err(DW_STATUS_ACCESS_DENIED)
    );
    assert_eq!(
        pio_read(&table, &mut registry, &resources, &mut io, write_only, 0, 1,),
        Err(DW_STATUS_ACCESS_DENIED)
    );
    assert_eq!(
        pio_read(&table, &mut registry, &resources, &mut io, wrong, 0, 1,),
        Err(DW_STATUS_WRONG_OBJECT_TYPE)
    );
    assert_eq!(
        table.duplicate(&mut registry, driver, DW_RIGHT_READ),
        Err(HandleTableError::AccessDenied),
        "driver-shaped authority cannot derive another handle"
    );
    assert!(io.operations.is_empty());
    assert_eq!(
        pio_read(&table, &mut registry, &resources, &mut io, driver, 0, 1,),
        Ok(0xa5)
    );
    assert_eq!(
        pio_write(
            &table,
            &mut registry,
            &resources,
            &mut io,
            driver,
            0,
            1,
            0x5a,
        ),
        Ok(())
    );

    for handle in [read_only, write_only, driver] {
        assert!(table.close(&mut registry, handle).unwrap().is_none());
    }
    let final_release = table.close(&mut registry, source).unwrap().unwrap();
    finalize_resource(&mut registry, &resources, final_release);
    let before = io.operations.len();
    assert_eq!(
        pio_read(&table, &mut registry, &resources, &mut io, source, 0, 1,),
        Err(DW_STATUS_BAD_HANDLE)
    );
    assert_eq!(io.operations.len(), before);
    let wrong_final = table.close(&mut registry, wrong).unwrap().unwrap();
    registry.complete_finalization(wrong_final).unwrap();
}

#[test]
fn duplicate_reduction_and_channel_move_never_amplify_rights() {
    let mut registry = Registry::new();
    let (_tasks, domain, _owner) = owner_domain(&mut registry);
    let resources = DeviceResourceAuthority::<2>::new();
    let mut sender = Table::new();
    let mut receiver = Table::new();
    let full = dw_object_compatible_rights(DW_OBJECT_TYPE_DEVICE_RESOURCE);
    let (_, source) = install_resource(
        &mut registry,
        &resources,
        &mut sender,
        descriptor(30, domain),
        full,
    );
    let reduced = rights(&[DW_RIGHT_READ, DW_RIGHT_WRITE, DW_RIGHT_INSPECT]);
    let duplicate = sender.duplicate(&mut registry, source, reduced).unwrap();
    assert_eq!(sender.inspect_basic(duplicate).unwrap().rights, reduced);
    assert_eq!(
        sender.duplicate(
            &mut registry,
            duplicate,
            rights(&[DW_RIGHT_READ, DW_RIGHT_WRITE, DW_RIGHT_MODIFY]),
        ),
        Err(HandleTableError::AccessDenied)
    );

    let prepared = sender
        .prepare_move_batch(&[HandleMoveRequest {
            handle: source,
            requested_rights: reduced,
        }])
        .unwrap();
    let (rollback, transfers) = prepared.extract();
    rollback.finish();
    let destination = receiver.reserve_transfer_batch(1).unwrap();
    let published = destination.publish(transfers)[0].unwrap();
    assert_eq!(published.rights, reduced);
    assert_eq!(published.object_type, DW_OBJECT_TYPE_DEVICE_RESOURCE);
    assert_eq!(
        receiver.inspect_basic(published.handle).unwrap().rights,
        reduced
    );
    let mut io = MockPortIo::default();
    assert_eq!(
        pio_read(
            &receiver,
            &mut registry,
            &resources,
            &mut io,
            published.handle,
            0,
            2,
        ),
        Ok(0xbeef)
    );

    assert!(sender.close(&mut registry, duplicate).unwrap().is_none());
    let final_release = receiver
        .close(&mut registry, published.handle)
        .unwrap()
        .unwrap();
    finalize_resource(&mut registry, &resources, final_release);
    assert_eq!(resources.live_count(), 0);
}

#[test]
fn object_info_reports_exact_immutable_identity_and_range() {
    let mut registry = Registry::new();
    let (tasks, domain, _owner) = owner_domain(&mut registry);
    let resources = DeviceResourceAuthority::<1>::new();
    let mut table = Table::new();
    let expected = descriptor(40, domain);
    let (_, handle) = install_resource(
        &mut registry,
        &resources,
        &mut table,
        expected,
        rights(&[DW_RIGHT_READ, DW_RIGHT_WRITE, DW_RIGHT_INSPECT]),
    );

    assert_eq!(
        crate::service::object_get_info_v1_with_tasks_and_devices(
            &table,
            &mut registry,
            &crate::memory::object::MemoryObjectAuthority::<1, 1>::new(),
            &tasks,
            &resources,
            handle,
            DW_OBJECT_INFO_DEVICE_RESOURCE_V1,
        ),
        Ok(ObjectInfoResult::DeviceResource(
            deepwyrm_abi::DwDeviceResourceInfoV1 {
                size: deepwyrm_abi::DW_DEVICE_RESOURCE_INFO_V1_SIZE,
                version: deepwyrm_abi::DW_DEVICE_RESOURCE_INFO_V1_VERSION,
                kind: expected.kind,
                flags: 0,
                resource_id: expected.resource_id,
                lease_generation: expected.lease_generation,
                pio_base: expected.pio_base,
                pio_length: expected.pio_length,
                interrupt_source: expected.interrupt_source,
                reserved: 0,
            }
        ))
    );
    close_and_finalize(&mut registry, &resources, &mut table, handle);
}

#[test]
fn final_close_removes_typed_payload_exactly_before_generic_completion() {
    let mut registry = Registry::new();
    let (_tasks, domain, _owner) = owner_domain(&mut registry);
    let resources = DeviceResourceAuthority::<1>::new();
    let mut table = Table::new();
    let (_, handle) = install_resource(
        &mut registry,
        &resources,
        &mut table,
        descriptor(50, domain),
        DW_RIGHT_INSPECT,
    );
    assert_eq!(resources.live_count(), 1);

    let final_release = table.close(&mut registry, handle).unwrap().unwrap();
    let duplicate_final_release = final_release.duplicate_for_negative_test();
    let finalization = resources.take_finalization(final_release).unwrap();
    assert_eq!(resources.live_count(), 0);
    let (error, duplicate_final_release) =
        match resources.take_finalization(duplicate_final_release) {
            Ok(_) => panic!("duplicate DeviceResource finalization must fail closed"),
            Err(error) => error,
        };
    assert_eq!(error, DeviceResourceError::FinalizationMismatch);
    let _ = duplicate_final_release;
    complete_device_resource_finalization(&mut registry, finalization);

    let replacement = descriptor(50, domain);
    let (_, handle) = resources
        .create(&mut registry, &mut table, replacement, DW_RIGHT_INSPECT)
        .unwrap();
    assert_eq!(resources.live_count(), 1);
    close_and_finalize(&mut registry, &resources, &mut table, handle);
}
