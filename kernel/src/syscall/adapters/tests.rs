extern crate std;

use super::*;
use crate::memory::user_range::UserPageChunk;
use crate::memory::usercopy::{PinnedUserBatchPages, PinnedUserPages, UserPageBatchAccess};
use crate::object::ObjectRegistry;
use crate::task::TaskAuthority;
use deepwyrm_abi::{DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_MODIFY};

const BASE: u64 = 0x4000;
const BYTES: usize = 4096;

struct FakeUserMemory {
    bytes: [u8; BYTES],
    deny_write: bool,
}

struct FakePinned<'a> {
    memory: &'a mut FakeUserMemory,
}

struct FakePinnedBatch<'a> {
    memory: &'a mut FakeUserMemory,
    ranges: [Option<UserRange>; 3],
}

impl FakeUserMemory {
    fn new() -> Self {
        Self {
            bytes: [0; BYTES],
            deny_write: false,
        }
    }

    fn offset(address: u64, len: usize) -> usize {
        let offset = usize::try_from(address - BASE).unwrap();
        assert!(offset + len <= BYTES);
        offset
    }
}

impl UserPageAccess for FakeUserMemory {
    type Error = ();
    type Pinned<'a>
        = FakePinned<'a>
    where
        Self: 'a;

    fn pin(&mut self, _range: UserRange) -> Result<Self::Pinned<'_>, Self::Error> {
        Ok(FakePinned { memory: self })
    }
}

impl UserPageBatchAccess for FakeUserMemory {
    type PinnedBatch<'a>
        = FakePinnedBatch<'a>
    where
        Self: 'a;

    fn pin_batch(
        &mut self,
        ranges: [Option<UserRange>; 3],
    ) -> Result<Self::PinnedBatch<'_>, Self::Error> {
        for left in 0..ranges.len() {
            let Some(left_range) = ranges[left] else {
                continue;
            };
            if left_range.is_empty() {
                continue;
            }
            for right_range in ranges[left + 1..].iter().flatten().copied() {
                if right_range.is_empty() {
                    continue;
                }
                if left_range.start() < right_range.end_exclusive()
                    && right_range.start() < left_range.end_exclusive()
                {
                    return Err(());
                }
            }
        }
        Ok(FakePinnedBatch {
            memory: self,
            ranges,
        })
    }
}

impl PinnedUserPages for FakePinned<'_> {
    type Error = ();

    fn preflight(&mut self, chunk: UserPageChunk) -> Result<(), Self::Error> {
        if self.memory.deny_write && chunk.access().includes(UserAccess::WRITE) {
            return Err(());
        }
        let _ = FakeUserMemory::offset(chunk.address(), usize::try_from(chunk.byte_len()).unwrap());
        Ok(())
    }

    fn read_exact(&mut self, range: UserRange, destination: &mut [u8]) {
        let offset = FakeUserMemory::offset(range.start(), destination.len());
        destination.copy_from_slice(&self.memory.bytes[offset..offset + destination.len()]);
    }

    fn write_exact(&mut self, range: UserRange, source: &[u8]) {
        let offset = FakeUserMemory::offset(range.start(), source.len());
        self.memory.bytes[offset..offset + source.len()].copy_from_slice(source);
    }
}

impl PinnedUserBatchPages for FakePinnedBatch<'_> {
    type Error = ();

    fn preflight(&mut self, index: usize, chunk: UserPageChunk) -> Result<(), Self::Error> {
        let range = self.ranges.get(index).copied().flatten().ok_or(())?;
        if self.memory.deny_write && chunk.access().includes(UserAccess::WRITE) {
            return Err(());
        }
        let end = chunk.address().checked_add(chunk.byte_len()).ok_or(())?;
        if chunk.address() < range.start() || end > range.end_exclusive() {
            return Err(());
        }
        let _ = FakeUserMemory::offset(chunk.address(), usize::try_from(chunk.byte_len()).unwrap());
        Ok(())
    }

    fn write_exact(&mut self, index: usize, range: UserRange, source: &[u8]) {
        let allowed = self.ranges.get(index).copied().flatten().unwrap();
        assert_eq!(range.start(), allowed.start());
        assert!(range.end_exclusive() <= allowed.end_exclusive());
        let offset = FakeUserMemory::offset(range.start(), source.len());
        self.memory.bytes[offset..offset + source.len()].copy_from_slice(source);
    }
}

fn u64_at(memory: &FakeUserMemory, address: u64) -> u64 {
    let offset = FakeUserMemory::offset(address, 8);
    u64::from_le_bytes(memory.bytes[offset..offset + 8].try_into().unwrap())
}

fn u32_at(memory: &FakeUserMemory, address: u64) -> u32 {
    let offset = FakeUserMemory::offset(address, 4);
    u32::from_le_bytes(memory.bytes[offset..offset + 4].try_into().unwrap())
}

fn write_handle_transfer(
    memory: &mut FakeUserMemory,
    address: u64,
    record: deepwyrm_abi::DwHandleTransferV1,
) {
    let offset = FakeUserMemory::offset(address, deepwyrm_abi::DW_HANDLE_TRANSFER_V1_SIZE as usize);
    memory.bytes[offset..offset + 8].copy_from_slice(&record.handle.0.to_le_bytes());
    memory.bytes[offset + 8..offset + 16].copy_from_slice(&record.requested_rights.0.to_le_bytes());
    memory.bytes[offset + 16..offset + 20].copy_from_slice(&record.operation.0.to_le_bytes());
    memory.bytes[offset + 20..offset + 24].copy_from_slice(&record.reserved0.to_le_bytes());
    memory.bytes[offset + 24..offset + 32].copy_from_slice(&record.reserved[0].to_le_bytes());
    memory.bytes[offset + 32..offset + 40].copy_from_slice(&record.reserved[1].to_le_bytes());
}

#[test]
fn abi_get_info_reports_size_and_writes_only_after_pointer_validation() {
    let mut user = FakeUserMemory::new();
    assert_eq!(
        abi_get_info(
            &mut user,
            DwUserAddress(BASE + 0x100),
            8,
            DwUserAddress(BASE + 0x20),
        ),
        DW_STATUS_BUFFER_TOO_SMALL
    );
    assert_eq!(u64_at(&user, BASE + 0x20), u64::from(DW_ABI_INFO_V1_SIZE));
    assert_eq!(&user.bytes[0x100..0x140], &[0; 64]);

    user.deny_write = true;
    let before = user.bytes;
    assert_eq!(
        abi_get_info(
            &mut user,
            DwUserAddress(BASE + 0x100),
            64,
            DwUserAddress(BASE + 0x20),
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(user.bytes, before);
}

#[test]
fn clock_get_validates_domain_and_output_before_reading_clock() {
    let mut user = FakeUserMemory::new();
    let mut called = false;
    assert_eq!(
        clock_get_with(
            &mut user,
            deepwyrm_abi::DW_CLOCK_BOOTTIME,
            DwUserAddress(BASE + 0x40),
            || {
                called = true;
                Ok(1)
            },
        ),
        DW_STATUS_NOT_SUPPORTED
    );
    assert!(!called);

    user.deny_write = true;
    assert_eq!(
        clock_get_with(
            &mut user,
            deepwyrm_abi::DW_CLOCK_MONOTONIC_ACTIVE,
            DwUserAddress(BASE + 0x40),
            || {
                called = true;
                Ok(2)
            },
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert!(!called);
    user.deny_write = false;
    assert_eq!(
        clock_get_with(
            &mut user,
            deepwyrm_abi::DW_CLOCK_MONOTONIC_ACTIVE,
            DwUserAddress(BASE + 0x40),
            || Ok(0x1122_3344_5566_7788),
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(u64_at(&user, BASE + 0x40), 0x1122_3344_5566_7788);
}

type Tasks = TaskAuthority<2, 2, 2, 8>;

fn process_fixture() -> (ObjectRegistry<16>, Tasks, ProcessKey, DwHandle) {
    let mut registry = ObjectRegistry::<16>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_ref) = tasks.create_process(&mut registry, &root_owner).unwrap();
    assert!(registry.release_internal(root_owner).unwrap().is_none());
    let rights = DwRights(DW_RIGHT_DUPLICATE.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_MODIFY.0);
    let handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(process_ref, rights)
        .unwrap();
    (registry, tasks, process, handle)
}

#[test]
fn event_create_preflights_output_before_object_and_handle_publication() {
    use deepwyrm_abi::{DW_OBJECT_TYPE_EVENT, DW_RIGHT_SIGNAL, DW_RIGHT_WAIT};

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let events = EventAuthority::<2>::new();
    let mut user = FakeUserMemory::new();
    let mut cleanup = CleanupQueue::<16>::new();
    let requested = DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_SIGNAL.0);
    let generations = registry.test_slot_generations();
    let handle_count = tasks.process_handle_count(process).unwrap();

    user.deny_write = true;
    assert_eq!(
        event_create(
            &mut user,
            &mut registry,
            &events,
            &mut tasks,
            process,
            requested,
            DwUserAddress(BASE + 0x180),
            &mut cleanup,
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(registry.test_slot_generations(), generations);
    assert_eq!(tasks.process_handle_count(process).unwrap(), handle_count);

    user.deny_write = false;
    assert_eq!(
        event_create(
            &mut user,
            &mut registry,
            &events,
            &mut tasks,
            process,
            requested,
            DwUserAddress(BASE + 0x180),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let event = DwHandle(u64_at(&user, BASE + 0x180));
    assert_ne!(event.0, 0);
    assert_eq!(
        tasks.process_handle_count(process).unwrap(),
        handle_count + 1
    );

    let waits = WaitRegistry::<2>::new();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    assert_eq!(
        event_signal(
            &mut registry,
            &events,
            &waits,
            &tasks,
            &execution,
            process,
            event,
            deepwyrm_abi::DwSignals(0),
            deepwyrm_abi::DW_SIGNAL_SIGNALED,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let pin = resolve_current_handle(
        &tasks,
        &mut registry,
        process,
        event,
        DW_OBJECT_TYPE_EVENT,
        DW_RIGHT_SIGNAL,
    )
    .unwrap();
    let key = EventKey::from_object_id(pin.id());
    assert_eq!(
        events.current_signals(key).unwrap(),
        deepwyrm_abi::DW_SIGNAL_SIGNALED
    );
    release_lookup_pin(&mut registry, pin, &mut cleanup);

    assert_eq!(
        event_signal(
            &mut registry,
            &events,
            &waits,
            &tasks,
            &execution,
            process,
            event,
            deepwyrm_abi::DW_SIGNAL_SIGNALED,
            deepwyrm_abi::DwSignals(0),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let pin = resolve_current_handle(
        &tasks,
        &mut registry,
        process,
        event,
        DW_OBJECT_TYPE_EVENT,
        DW_RIGHT_SIGNAL,
    )
    .unwrap();
    let key = EventKey::from_object_id(pin.id());
    assert_eq!(
        events.current_signals(key).unwrap(),
        deepwyrm_abi::DwSignals(0)
    );
    release_lookup_pin(&mut registry, pin, &mut cleanup);

    assert_eq!(
        handle_close(&mut registry, &mut tasks, process, event, &mut cleanup),
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    for release in cleanup.into_releases().into_iter().flatten() {
        assert_eq!(release.object_type(), DW_OBJECT_TYPE_EVENT);
        let finalization = events.take_finalization(release).unwrap();
        crate::wait::complete_event_finalization(&mut registry, finalization);
    }
}

fn install_event_for_test<const EVENTS: usize>(
    registry: &mut ObjectRegistry<16>,
    tasks: &mut Tasks,
    process: ProcessKey,
    events: &EventAuthority<EVENTS>,
    rights: DwRights,
) -> DwHandle {
    let (_key, reference) = events.create_event(registry).unwrap();
    tasks
        .process_handles_mut(process)
        .unwrap()
        .install(reference, rights)
        .unwrap()
}

fn close_event_for_test<const EVENTS: usize>(
    registry: &mut ObjectRegistry<16>,
    tasks: &mut Tasks,
    process: ProcessKey,
    events: &EventAuthority<EVENTS>,
    handle: DwHandle,
) {
    let release = tasks
        .process_handles_mut(process)
        .unwrap()
        .close(registry, handle)
        .unwrap()
        .unwrap();
    let finalization = events.take_finalization(release).unwrap();
    crate::wait::complete_event_finalization(registry, finalization);
}

fn close_channel_for_test(
    registry: &mut ObjectRegistry<16>,
    tasks: &mut Tasks,
    process: ProcessKey,
    channels: &ChannelAuthority<2, 4>,
    waits: &WaitRegistry<8>,
    handle: DwHandle,
) {
    let release = tasks
        .process_handles_mut(process)
        .unwrap()
        .close(registry, handle)
        .unwrap()
        .unwrap();
    let finalization = channels.take_finalization(release, waits).unwrap();
    let completion = crate::ipc::complete_channel_finalization(registry, finalization);
    let (wakes, releases) = completion.into_parts();
    assert_eq!(wakes.len(), 0);
    assert!(releases.into_iter().flatten().next().is_none());
}

#[test]
fn channel_create_preflights_both_outputs_before_pair_publication() {
    use deepwyrm_abi::{DW_RIGHT_READ, DW_RIGHT_WRITE};

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let channels = ChannelAuthority::<2, 4>::new();
    let waits = WaitRegistry::<8>::new();
    let mut user = FakeUserMemory::new();
    let requested = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0);
    let generations = registry.test_slot_generations();
    let before = tasks.process_handle_count(process).unwrap();

    user.deny_write = true;
    assert_eq!(
        channel_create(
            &mut user,
            &mut registry,
            &channels,
            &mut tasks,
            process,
            requested,
            DwUserAddress(BASE + 0x180),
            DwUserAddress(BASE + 0x188),
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(registry.test_slot_generations(), generations);
    assert_eq!(tasks.process_handle_count(process).unwrap(), before);

    user.deny_write = false;
    assert_eq!(
        channel_create(
            &mut user,
            &mut registry,
            &channels,
            &mut tasks,
            process,
            requested,
            DwUserAddress(BASE + 0x180),
            DwUserAddress(BASE + 0x180),
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(registry.test_slot_generations(), generations);
    assert_eq!(tasks.process_handle_count(process).unwrap(), before);

    assert_eq!(
        channel_create(
            &mut user,
            &mut registry,
            &channels,
            &mut tasks,
            process,
            requested,
            DwUserAddress(BASE + 0x180),
            DwUserAddress(BASE + 0x188),
        ),
        DW_STATUS_SUCCESS
    );
    let endpoint0 = DwHandle(u64_at(&user, BASE + 0x180));
    let endpoint1 = DwHandle(u64_at(&user, BASE + 0x188));
    assert_ne!(endpoint0, endpoint1);
    assert_eq!(tasks.process_handle_count(process).unwrap(), before + 2);

    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        endpoint0,
    );
    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        endpoint1,
    );
    let mut cleanup = CleanupQueue::<16>::new();
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert!(
        cleanup
            .into_releases()
            .into_iter()
            .flatten()
            .next()
            .is_none()
    );
}

#[test]
fn channel_send_receive_and_buffer_too_small_are_transactional() {
    use deepwyrm_abi::{DW_RIGHT_READ, DW_RIGHT_WRITE};

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let channels = ChannelAuthority::<2, 4>::new();
    let waits = WaitRegistry::<8>::new();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut user = FakeUserMemory::new();
    let mut cleanup = CleanupQueue::<16>::new();
    let requested = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0);
    assert_eq!(
        channel_create(
            &mut user,
            &mut registry,
            &channels,
            &mut tasks,
            process,
            requested,
            DwUserAddress(BASE + 0x180),
            DwUserAddress(BASE + 0x188),
        ),
        DW_STATUS_SUCCESS
    );
    let endpoint0 = DwHandle(u64_at(&user, BASE + 0x180));
    let endpoint1 = DwHandle(u64_at(&user, BASE + 0x188));
    let input = FakeUserMemory::offset(BASE + 0x300, 6);
    user.bytes[input..input + 6].copy_from_slice(b"dragon");
    let mut staging = std::vec![0_u8; DW_CHANNEL_MAX_PAYLOAD as usize];

    assert_eq!(
        channel_send(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint0,
            DwUserAddress(BASE + 0x300),
            6,
            DwUserAddress(0),
            0,
            0,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );

    assert_eq!(
        channel_receive(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint1,
            DwUserAddress(0),
            4,
            DwUserAddress(0),
            0,
            DwUserAddress(BASE + 0x500),
            &mut cleanup,
        ),
        DW_STATUS_BUFFER_TOO_SMALL
    );
    assert_eq!(u32_at(&user, BASE + 0x500 + 8), 0);
    assert_eq!(u32_at(&user, BASE + 0x500 + 16), 6);

    assert_eq!(
        channel_receive(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint1,
            // Only the six bytes in the reserved head need to be pinned. The
            // caller-declared capacity extends beyond FakeUserMemory and would
            // fail if receive incorrectly preflighted the whole capacity.
            DwUserAddress(BASE + BYTES as u64 - 6),
            8,
            DwUserAddress(0),
            0,
            DwUserAddress(BASE + 0x500),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let output = FakeUserMemory::offset(BASE + BYTES as u64 - 6, 6);
    assert_eq!(&user.bytes[output..output + 6], b"dragon");
    assert_eq!(u32_at(&user, BASE + 0x500 + 8), 6);
    assert_eq!(u32_at(&user, BASE + 0x500 + 16), 6);

    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        endpoint0,
    );
    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        endpoint1,
    );
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
}

#[test]
fn channel_send_reports_peer_closed_after_peer_finalization() {
    use deepwyrm_abi::{DW_RIGHT_READ, DW_RIGHT_WRITE};

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let channels = ChannelAuthority::<2, 4>::new();
    let waits = WaitRegistry::<8>::new();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut user = FakeUserMemory::new();
    let mut cleanup = CleanupQueue::<16>::new();
    let requested = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0);
    assert_eq!(
        channel_create(
            &mut user,
            &mut registry,
            &channels,
            &mut tasks,
            process,
            requested,
            DwUserAddress(BASE + 0x180),
            DwUserAddress(BASE + 0x188),
        ),
        DW_STATUS_SUCCESS
    );
    let endpoint0 = DwHandle(u64_at(&user, BASE + 0x180));
    let endpoint1 = DwHandle(u64_at(&user, BASE + 0x188));
    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        endpoint1,
    );
    let mut staging = std::vec![0_u8; DW_CHANNEL_MAX_PAYLOAD as usize];
    let input = FakeUserMemory::offset(BASE + 0x300, 1);
    user.bytes[input] = 0x5a;
    assert_eq!(
        channel_send(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint0,
            DwUserAddress(BASE + 0x300),
            1,
            DwUserAddress(0),
            0,
            0,
            &mut cleanup,
        ),
        DW_STATUS_PEER_CLOSED
    );
    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        endpoint0,
    );
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
}

#[test]
fn event_signal_rejects_invalid_masks_and_missing_signal_right_before_mutation() {
    use deepwyrm_abi::{DW_OBJECT_TYPE_EVENT, DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED};

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let events = EventAuthority::<1>::new();
    let waits = WaitRegistry::<1>::new();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let (key, reference) = events.create_event(&mut registry).unwrap();
    let event = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(reference, DW_RIGHT_WAIT)
        .unwrap();
    let mut cleanup = CleanupQueue::<16>::new();

    assert_eq!(
        event_signal(
            &mut registry,
            &events,
            &waits,
            &tasks,
            &execution,
            process,
            DwHandle(u64::MAX),
            deepwyrm_abi::DwSignals(0),
            deepwyrm_abi::DwSignals(0),
            &mut cleanup,
        ),
        DW_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(
        events.current_signals(key).unwrap(),
        deepwyrm_abi::DwSignals(0)
    );

    assert_eq!(
        event_signal(
            &mut registry,
            &events,
            &waits,
            &tasks,
            &execution,
            process,
            event,
            deepwyrm_abi::DwSignals(0),
            DW_SIGNAL_SIGNALED,
            &mut cleanup,
        ),
        DW_STATUS_ACCESS_DENIED
    );
    assert_eq!(
        events.current_signals(key).unwrap(),
        deepwyrm_abi::DwSignals(0)
    );

    assert_eq!(
        handle_close(&mut registry, &mut tasks, process, event, &mut cleanup),
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    for release in cleanup.into_releases().into_iter().flatten() {
        assert_eq!(release.object_type(), DW_OBJECT_TYPE_EVENT);
        let finalization = events.take_finalization(release).unwrap();
        crate::wait::complete_event_finalization(&mut registry, finalization);
    }
}

#[test]
fn duplicate_does_not_mutate_handle_table_until_output_is_preflighted() {
    let (mut registry, mut tasks, process, source) = process_fixture();
    let mut user = FakeUserMemory::new();
    user.deny_write = true;
    let before = tasks.process_handle_count(process).unwrap();
    assert_eq!(
        handle_duplicate(
            &mut user,
            &mut registry,
            &mut tasks,
            process,
            source,
            DW_RIGHT_INSPECT,
            DwUserAddress(BASE + 0x80),
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(tasks.process_handle_count(process).unwrap(), before);
    user.deny_write = false;
    assert_eq!(
        handle_duplicate(
            &mut user,
            &mut registry,
            &mut tasks,
            process,
            source,
            DW_RIGHT_INSPECT,
            DwUserAddress(BASE + 0x80),
        ),
        DW_STATUS_SUCCESS
    );
    let duplicate = DwHandle(u64_at(&user, BASE + 0x80));
    assert_ne!(duplicate.0, 0);
    assert_eq!(tasks.process_handle_count(process).unwrap(), before + 1);

    let mut cleanup = CleanupQueue::<16>::new();
    assert_eq!(
        handle_close(&mut registry, &mut tasks, process, duplicate, &mut cleanup),
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        handle_close(&mut registry, &mut tasks, process, source, &mut cleanup),
        DW_STATUS_SUCCESS
    );
    assert_eq!(tasks.process_handle_count(process).unwrap(), 0);
}

struct TestBacking {
    roles: crate::memory::frame_roles::FrameRoleManager<1, 8>,
    allocations: usize,
}

impl TestBacking {
    fn new() -> Self {
        Self {
            roles: crate::memory::frame_roles::synthetic_frame_role_manager::<1, 8>(0x20_000, 8),
            allocations: 0,
        }
    }
}

impl MemoryObjectBackingAccess for TestBacking {
    #[allow(
        unsafe_code,
        reason = "the host fixture models the production post-zeroing typed role transition"
    )]
    fn allocate_zeroed_backing(
        &mut self,
        page_count: u64,
    ) -> Result<crate::memory::frame_roles::ObjectBackingGrant, DwStatus> {
        self.allocations += 1;
        let allocation = self
            .roles
            .allocate(page_count)
            .map_err(|_| deepwyrm_abi::DW_STATUS_NO_MEMORY)?;
        let zeroed = unsafe { self.roles.assume_zeroed(allocation) }.unwrap();
        self.roles
            .assign_object_backing(zeroed)
            .map_err(|_| deepwyrm_abi::DW_STATUS_NO_MEMORY)
    }

    fn rollback_object_backing(&mut self, backing: crate::memory::frame_roles::ObjectBackingGrant) {
        self.roles.cancel_object_backing(backing).unwrap();
    }
}

#[test]
fn memory_object_create_preflights_output_before_backing_allocation() {
    use deepwyrm_abi::{DW_RIGHT_MAP, DW_RIGHT_READ, DW_RIGHT_WRITE};

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let mut user = FakeUserMemory::new();
    let mut backing = TestBacking::new();
    let mut memory = MemoryObjectAuthority::<4, 4>::new();
    let rights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0);
    let mut cleanup = CleanupQueue::<16>::new();

    user.deny_write = true;
    assert_eq!(
        memory_object_create(
            &mut user,
            &mut backing,
            &mut registry,
            &mut memory,
            &mut tasks,
            process,
            4096,
            0,
            rights,
            DwUserAddress(BASE + 0x100),
            &mut cleanup,
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(backing.allocations, 0);
    assert_eq!(tasks.process_handle_count(process).unwrap(), 1);
    user.deny_write = false;
    assert_eq!(
        memory_object_create(
            &mut user,
            &mut backing,
            &mut registry,
            &mut memory,
            &mut tasks,
            process,
            4096,
            0,
            rights,
            DwUserAddress(BASE + 0x100),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let memory_handle = DwHandle(u64_at(&user, BASE + 0x100));
    assert_ne!(memory_handle.0, 0);
    assert_eq!(backing.allocations, 1);
    assert_eq!(tasks.process_handle_count(process).unwrap(), 2);

    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            memory_handle,
            &mut cleanup
        ),
        DW_STATUS_SUCCESS
    );
    for release in cleanup.into_releases().into_iter().flatten() {
        let finalization = memory.take_finalization(release).unwrap();
        crate::memory::object::complete_memory_finalization(
            &mut registry,
            &mut backing.roles,
            finalization,
        );
    }
    let mut final_cleanup = CleanupQueue::<16>::new();
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut final_cleanup,
        ),
        DW_STATUS_SUCCESS
    );
}
struct FakePublisher {
    address_space: crate::memory::address_region::AddressSpaceKey,
    region: crate::memory::address_region::RegionKey,
    replacements: usize,
}

impl crate::memory::address_region::publisher_seal::Sealed for FakePublisher {}

#[allow(
    unsafe_code,
    reason = "the host fixture atomically accepts only its exact authority-issued address-space/region pair"
)]
unsafe impl crate::memory::address_region::AddressSpacePublisher for FakePublisher {
    type Error = ();

    fn address_space_key(&self) -> crate::memory::address_region::AddressSpaceKey {
        self.address_space
    }

    fn publish_replace(
        &mut self,
        address_space: crate::memory::address_region::AddressSpaceKey,
        region: crate::memory::address_region::RegionKey,
        _before: &[crate::memory::address_region::Mapping],
        _after: &[crate::memory::address_region::Mapping],
    ) -> Result<(), Self::Error> {
        assert_eq!(address_space, self.address_space);
        assert_eq!(region, self.region);
        self.replacements += 1;
        Ok(())
    }
}
#[allow(
    unsafe_code,
    reason = "test-local AddressSpaceAuthority uniquely owns its synthetic E5 address-space identities"
)]
fn region_fixture() -> (
    ObjectRegistry<24>,
    Tasks,
    ProcessKey,
    DwHandle,
    crate::memory::address_region::AddressSpaceAuthority<2, 2>,
    crate::memory::address_region::AddressRegionObjectAuthority<2, 8>,
    crate::memory::address_region::AddressRegionObjectKey,
    DwHandle,
) {
    use deepwyrm_abi::{DW_RIGHT_MAP, DW_RIGHT_MODIFY};

    let mut registry = ObjectRegistry::<24>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_ref) = tasks.create_process(&mut registry, &root_owner).unwrap();
    assert!(registry.release_internal(root_owner).unwrap().is_none());
    let mut spaces = unsafe { crate::memory::address_region::AddressSpaceAuthority::<2, 2>::new() };
    let mut regions = crate::memory::address_region::AddressRegionObjectAuthority::<2, 8>::new();
    let (region_key, region_ref) = regions
        .create_root_region(
            &mut registry,
            &mut tasks,
            &mut spaces,
            process,
            &process_ref,
        )
        .unwrap();
    let process_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(
            process_ref,
            DwRights(DW_RIGHT_DUPLICATE.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_MODIFY.0),
        )
        .unwrap();
    let region_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(region_ref, DwRights(DW_RIGHT_MAP.0 | DW_RIGHT_MODIFY.0))
        .unwrap();
    (
        registry,
        tasks,
        process,
        process_handle,
        spaces,
        regions,
        region_key,
        region_handle,
    )
}

fn write_map_args(memory: &mut FakeUserMemory, address: u64, protections: u32) {
    let offset = FakeUserMemory::offset(address, super::super::abi_bytes::ADDRESS_REGION_MAP_BYTES);
    let bytes =
        &mut memory.bytes[offset..offset + super::super::abi_bytes::ADDRESS_REGION_MAP_BYTES];
    bytes.fill(0);
    bytes[0..4].copy_from_slice(&deepwyrm_abi::DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE.to_le_bytes());
    bytes[4..8].copy_from_slice(&1_u32.to_le_bytes());
    bytes[16..24].copy_from_slice(&4096_u64.to_le_bytes());
    bytes[32..36].copy_from_slice(&protections.to_le_bytes());
}
#[test]
fn address_region_map_preflights_copyout_and_preserves_mapping_leases() {
    use deepwyrm_abi::{
        DW_MEMORY_PROTECTION_READ, DW_MEMORY_PROTECTION_WRITE, DW_RIGHT_MAP, DW_RIGHT_READ,
        DW_RIGHT_WRITE,
    };

    let (
        mut registry,
        mut tasks,
        process,
        process_handle,
        _spaces,
        mut regions,
        region_key,
        region_handle,
    ) = region_fixture();
    let mut user = FakeUserMemory::new();
    let mut backing = TestBacking::new();
    let mut memory = MemoryObjectAuthority::<4, 8>::new();
    let mut cleanup = CleanupQueue::<24>::new();
    let memory_rights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_MAP.0);
    assert_eq!(
        memory_object_create(
            &mut user,
            &mut backing,
            &mut registry,
            &mut memory,
            &mut tasks,
            process,
            4096,
            0,
            memory_rights,
            DwUserAddress(BASE + 0x100),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let memory_handle = DwHandle(u64_at(&user, BASE + 0x100));
    write_map_args(
        &mut user,
        BASE + 0x200,
        DW_MEMORY_PROTECTION_READ.0 | DW_MEMORY_PROTECTION_WRITE.0,
    );
    let region_model = regions.region(region_key).unwrap();
    let mut publisher = FakePublisher {
        address_space: region_model.address_space_key(),
        region: region_model.region_key(),
        replacements: 0,
    };

    user.deny_write = true;
    assert_eq!(
        address_region_map(
            &mut user,
            &mut publisher,
            &mut registry,
            &mut memory,
            &mut tasks,
            &mut regions,
            process,
            region_handle,
            memory_handle,
            DwUserAddress(BASE + 0x200),
            u64::from(deepwyrm_abi::DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE),
            DwUserAddress(BASE + 0x300),
            &mut cleanup,
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(publisher.replacements, 0);
    assert!(
        regions
            .region(region_key)
            .unwrap()
            .mappings()
            .iter()
            .all(Option::is_none)
    );
    user.deny_write = false;
    assert_eq!(
        address_region_map(
            &mut user,
            &mut publisher,
            &mut registry,
            &mut memory,
            &mut tasks,
            &mut regions,
            process,
            region_handle,
            memory_handle,
            DwUserAddress(BASE + 0x200),
            u64::from(deepwyrm_abi::DW_ADDRESS_REGION_MAP_ARGS_V1_SIZE),
            DwUserAddress(BASE + 0x300),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let mapped = u64_at(&user, BASE + 0x300);
    assert_eq!(mapped, 4096);
    assert_eq!(publisher.replacements, 1);
    assert_eq!(
        regions
            .region(region_key)
            .unwrap()
            .mappings()
            .iter()
            .flatten()
            .count(),
        1
    );

    assert_eq!(
        address_region_protect(
            &mut publisher,
            &mut registry,
            &mut memory,
            &mut tasks,
            &mut regions,
            process,
            region_handle,
            DwUserAddress(mapped),
            4096,
            DW_MEMORY_PROTECTION_READ.0,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(publisher.replacements, 2);
    assert_eq!(
        address_region_unmap(
            &mut publisher,
            &mut registry,
            &mut memory,
            &mut tasks,
            &mut regions,
            process,
            region_handle,
            DwUserAddress(mapped),
            4096,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(publisher.replacements, 3);
    assert!(
        regions
            .region(region_key)
            .unwrap()
            .mappings()
            .iter()
            .all(Option::is_none)
    );

    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            memory_handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    for release in cleanup.into_releases().into_iter().flatten() {
        let finalization = memory.take_finalization(release).unwrap();
        crate::memory::object::complete_memory_finalization(
            &mut registry,
            &mut backing.roles,
            finalization,
        );
    }
    let mut final_cleanup = CleanupQueue::<24>::new();
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            region_handle,
            &mut final_cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut final_cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(tasks.process_handle_count(process).unwrap(), 0);
}

fn test_stack_bounds<const N: usize>() -> [crate::memory::kernel_stack::KernelStackBounds; N] {
    core::array::from_fn(|index| {
        let stride = 0x11_000_u64;
        let guard = 0xffff_9100_0000_0000 + u64::try_from(index).unwrap() * stride;
        crate::memory::kernel_stack::KernelStackBounds::new(guard, guard + 0x1000, guard + stride)
            .unwrap()
    })
}

fn test_start(seed: u64) -> ThreadStartState {
    ThreadStartState::from_validated_user_state(
        0x0000_0000_4000_0000 + seed * 0x1000,
        0x0000_0000_5000_0000 + seed * 0x1000,
        seed,
        seed + 1,
    )
}

fn finish_task_cleanup<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut Tasks,
    cleanup: CleanupQueue<OBJECTS>,
) {
    for release in cleanup.into_releases().into_iter().flatten() {
        let mut pending = Some(release);
        while let Some(release) = pending.take() {
            let finalization = tasks.take_finalization(release).unwrap();
            pending = crate::task::complete_task_finalization(registry, finalization);
        }
    }
}

#[test]
fn invalid_task_creation_rights_do_not_burn_object_generations() {
    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let mut user = FakeUserMemory::new();
    let before = registry.test_slot_generations();
    let mut cleanup = CleanupQueue::<16>::new();

    assert_eq!(
        thread_create(
            &mut user,
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            DwRights(0),
            DwUserAddress(BASE + 0x180),
            &mut cleanup,
        ),
        DW_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(registry.test_slot_generations(), before);
    assert_eq!(tasks.process_handle_count(process).unwrap(), 1);
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
}

#[test]
fn self_thread_termination_with_live_sibling_never_returns_to_reclaimed_context() {
    use deepwyrm_abi::{DW_OBJECT_TYPE_PROCESS, DW_RIGHT_MODIFY, DW_TERMINATION_AUTHORIZED};

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let execution = ExecutionDomain::<2>::new(test_stack_bounds::<2>()).unwrap();
    let mut cleanup = CleanupQueue::<16>::new();
    let process_pin = resolve_current_handle(
        &tasks,
        &mut registry,
        process,
        process_handle,
        DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_MODIFY,
    )
    .unwrap();
    let (current, current_ref) = tasks.create_thread(&mut registry, &process_pin).unwrap();
    let (sibling, sibling_ref) = tasks.create_thread(&mut registry, &process_pin).unwrap();
    release_lookup_pin(&mut registry, process_pin, &mut cleanup);
    let current_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(current_ref, DW_RIGHT_MODIFY)
        .unwrap();
    let sibling_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(sibling_ref, DW_RIGHT_MODIFY)
        .unwrap();

    execution
        .start_thread(&mut tasks, current, test_start(1))
        .unwrap();
    execution
        .start_thread(&mut tasks, sibling, test_start(2))
        .unwrap();
    assert_eq!(execution.schedule_next().unwrap().current, Some(current));

    assert_eq!(
        thread_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            process,
            current,
            current_handle,
            DW_TERMINATION_AUTHORIZED,
            0x51,
            &mut cleanup,
        ),
        (DW_STATUS_SUCCESS, SyscallControl::TerminateCurrent)
    );
    assert_eq!(execution.scheduler_state(current), None);
    assert_eq!(
        execution.scheduler_state(sibling),
        Some(SchedulerThreadState::Running)
    );
    assert_ne!(
        tasks.process_info(process).unwrap().state,
        deepwyrm_abi::DW_TASK_STATE_EXITED
    );

    assert_eq!(
        thread_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            process,
            sibling,
            sibling_handle,
            DW_TERMINATION_AUTHORIZED,
            0x52,
            &mut cleanup,
        ),
        (DW_STATUS_SUCCESS, SyscallControl::TerminateCurrent)
    );
    assert_eq!(execution.scheduler_state(sibling), None);
    assert_eq!(tasks.process_handle_count(process).unwrap(), 0);
    finish_task_cleanup(&mut registry, &mut tasks, cleanup);
}

struct ProcessBoundMappings {
    process: ProcessKey,
    executable: bool,
    writable_stack: bool,
}

impl crate::arch::x86_64::syscall::UserReturnMappingValidation for ProcessBoundMappings {
    fn executable_at(&mut self, _instruction_pointer: u64) -> bool {
        self.executable
    }

    fn writable_byte_below(&mut self, _stack_pointer: u64) -> bool {
        self.writable_stack
    }
}

impl crate::arch::x86_64::syscall::ProcessUserReturnMappingValidation for ProcessBoundMappings {
    fn process_key(&self) -> ProcessKey {
        self.process
    }
}

fn write_thread_start_args(
    memory: &mut FakeUserMemory,
    address: u64,
    thread: DwHandle,
    entry: u64,
    stack_pointer: u64,
) {
    let offset = FakeUserMemory::offset(address, THREAD_START_BYTES);
    let bytes = &mut memory.bytes[offset..offset + THREAD_START_BYTES];
    bytes.fill(0);
    bytes[0..4].copy_from_slice(&(THREAD_START_BYTES as u32).to_le_bytes());
    bytes[4..8].copy_from_slice(&1_u32.to_le_bytes());
    bytes[8..16].copy_from_slice(&thread.0.to_le_bytes());
    bytes[16..24].copy_from_slice(&entry.to_le_bytes());
    bytes[24..32].copy_from_slice(&stack_pointer.to_le_bytes());
}

#[test]
fn thread_start_validates_the_target_process_address_space() {
    use deepwyrm_abi::DW_RIGHT_EXECUTE;

    let mut registry = ObjectRegistry::<24>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (caller, caller_ref) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let (target, target_ref) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let target_owner = registry.retain_internal_from_handle(&target_ref).unwrap();
    let (thread, thread_ref) = tasks.create_thread(&mut registry, &target_owner).unwrap();
    assert!(registry.release_internal(target_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());
    assert!(registry.release_handle(target_ref).unwrap().is_none());

    let caller_handle = tasks
        .process_handles_mut(caller)
        .unwrap()
        .install(caller_ref, DW_RIGHT_MODIFY)
        .unwrap();
    let thread_handle = tasks
        .process_handles_mut(caller)
        .unwrap()
        .install(thread_ref, DW_RIGHT_EXECUTE)
        .unwrap();
    let mut user = FakeUserMemory::new();
    write_thread_start_args(
        &mut user,
        BASE + 0x280,
        thread_handle,
        0x4000_1000,
        0x5000_2000,
    );
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut cleanup = CleanupQueue::<24>::new();

    let mut wrong = ProcessBoundMappings {
        process: caller,
        executable: true,
        writable_stack: true,
    };
    assert_eq!(
        thread_start(
            &mut user,
            &mut wrong,
            &mut registry,
            &mut tasks,
            &execution,
            caller,
            DwUserAddress(BASE + 0x280),
            THREAD_START_BYTES as u64,
            &mut cleanup,
        ),
        DW_STATUS_BAD_STATE
    );
    assert_eq!(execution.scheduler_state(thread), None);
    assert_eq!(
        tasks.thread_info(thread).unwrap().state,
        deepwyrm_abi::DW_TASK_STATE_CREATED
    );

    let mut correct = ProcessBoundMappings {
        process: target,
        executable: true,
        writable_stack: true,
    };
    assert_eq!(
        thread_start(
            &mut user,
            &mut correct,
            &mut registry,
            &mut tasks,
            &execution,
            caller,
            DwUserAddress(BASE + 0x280),
            THREAD_START_BYTES as u64,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        execution.scheduler_state(thread),
        Some(SchedulerThreadState::Runnable)
    );
    assert_eq!(
        thread_start(
            &mut user,
            &mut correct,
            &mut registry,
            &mut tasks,
            &execution,
            caller,
            DwUserAddress(BASE + 0x280),
            THREAD_START_BYTES as u64,
            &mut cleanup,
        ),
        DW_STATUS_BAD_STATE
    );
    assert_eq!(
        execution.scheduler_state(thread),
        Some(SchedulerThreadState::Runnable)
    );
    assert_eq!(execution.schedule_next().unwrap().current, Some(thread));
    let pins = tasks.exit_thread(thread, 0).unwrap();
    let retired = execution.retire_exit_pins(pins);
    let (process_pin, thread_pins) = retired.into_parts();
    for pin in thread_pins.into_iter().flatten().chain(process_pin) {
        cleanup.push_optional(registry.release_internal(pin).unwrap());
    }
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            caller,
            thread_handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            caller,
            caller_handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    finish_task_cleanup(&mut registry, &mut tasks, cleanup);
    assert_eq!(tasks.process_handle_count(caller).unwrap(), 0);
    assert_eq!(tasks.thread_process(thread), Err(TaskError::InvalidTask));
}

#[test]
fn task_create_output_preflight_precedes_generation_and_handle_mutation() {
    let mut registry = ObjectRegistry::<16>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let root_handle_owner = registry.retain_internal(&root_owner).unwrap();
    let root_handle_ref = registry.internal_into_handle(root_handle_owner).unwrap();
    let (process, process_ref) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let root_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(root_handle_ref, DW_RIGHT_MODIFY)
        .unwrap();
    let process_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(process_ref, DW_RIGHT_MODIFY)
        .unwrap();
    let before_generations = registry.test_slot_generations();
    let before_handles = tasks.process_handle_count(process).unwrap();
    let mut user = FakeUserMemory::new();
    user.deny_write = true;
    let mut cleanup = CleanupQueue::<16>::new();

    assert_eq!(
        task_group_create(
            &mut user,
            &mut registry,
            &mut tasks,
            process,
            root_handle,
            DW_RIGHT_INSPECT,
            DwUserAddress(BASE + 0x100),
            &mut cleanup,
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(
        thread_create(
            &mut user,
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            DW_RIGHT_INSPECT,
            DwUserAddress(BASE + 0x180),
            &mut cleanup,
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(registry.test_slot_generations(), before_generations);
    assert_eq!(tasks.process_handle_count(process).unwrap(), before_handles);

    for handle in [root_handle, process_handle] {
        assert_eq!(
            handle_close(&mut registry, &mut tasks, process, handle, &mut cleanup),
            DW_STATUS_SUCCESS
        );
    }
    let effects = tasks
        .terminate_process_authorized(&mut registry, process, 0x40)
        .unwrap();
    assert_eq!(effects.drained.final_release_count(), 0);
    let (process_pin, thread_pins, resources) = effects.pins.into_parts();
    assert!(thread_pins.into_iter().flatten().next().is_none());
    assert!(resources.into_iter().flatten().next().is_none());
    cleanup.push_optional(registry.release_internal(process_pin.unwrap()).unwrap());
    finish_task_cleanup(&mut registry, &mut tasks, cleanup);
    let root_final = registry.release_internal(root_owner).unwrap().unwrap();
    let mut root_cleanup = CleanupQueue::<16>::new();
    root_cleanup.push(root_final);
    finish_task_cleanup(&mut registry, &mut tasks, root_cleanup);
}

#[test]
fn termination_rejects_reason_type_and_rights_before_target_mutation() {
    use deepwyrm_abi::{DW_OBJECT_TYPE_PROCESS, DW_TERMINATION_AUTHORIZED};

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut cleanup = CleanupQueue::<16>::new();
    let process_pin = resolve_current_handle(
        &tasks,
        &mut registry,
        process,
        process_handle,
        DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_MODIFY,
    )
    .unwrap();
    let (current, current_ref) = tasks.create_thread(&mut registry, &process_pin).unwrap();
    let (target, target_ref) = tasks.create_thread(&mut registry, &process_pin).unwrap();
    release_lookup_pin(&mut registry, process_pin, &mut cleanup);
    let current_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(current_ref, DW_RIGHT_MODIFY)
        .unwrap();
    let target_full = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(
            target_ref,
            DwRights(DW_RIGHT_DUPLICATE.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_MODIFY.0),
        )
        .unwrap();
    let target_inspect = tasks
        .process_handles_mut(process)
        .unwrap()
        .duplicate(&mut registry, target_full, DW_RIGHT_INSPECT)
        .unwrap();

    execution
        .start_thread(&mut tasks, current, test_start(0x41))
        .unwrap();
    assert_eq!(execution.schedule_next().unwrap().current, Some(current));

    assert_eq!(
        thread_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            process,
            current,
            target_full,
            deepwyrm_abi::DwTerminationReason(u32::MAX),
            1,
            &mut cleanup,
        ),
        (DW_STATUS_INVALID_ARGUMENT, SyscallControl::ReturnToCaller)
    );
    assert_eq!(
        tasks.thread_info(target).unwrap().state,
        deepwyrm_abi::DW_TASK_STATE_CREATED
    );
    assert_eq!(
        thread_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            process,
            current,
            process_handle,
            DW_TERMINATION_AUTHORIZED,
            2,
            &mut cleanup,
        ),
        (DW_STATUS_WRONG_OBJECT_TYPE, SyscallControl::ReturnToCaller)
    );
    assert_eq!(
        thread_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            process,
            current,
            target_inspect,
            DW_TERMINATION_AUTHORIZED,
            3,
            &mut cleanup,
        ),
        (DW_STATUS_ACCESS_DENIED, SyscallControl::ReturnToCaller)
    );
    assert_eq!(
        tasks.thread_info(target).unwrap().state,
        deepwyrm_abi::DW_TASK_STATE_CREATED
    );
    assert_eq!(
        thread_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            process,
            current,
            target_full,
            DW_TERMINATION_AUTHORIZED,
            0x44,
            &mut cleanup,
        ),
        (DW_STATUS_SUCCESS, SyscallControl::ReturnToCaller)
    );
    let target_info = tasks.thread_info(target).unwrap();
    assert_eq!(target_info.state, deepwyrm_abi::DW_TASK_STATE_EXITED);
    assert_eq!(target_info.reason, DW_TERMINATION_AUTHORIZED);
    assert_eq!(target_info.detail, 0x44);
    assert_eq!(
        execution.scheduler_state(current),
        Some(SchedulerThreadState::Running)
    );

    for handle in [target_full, target_inspect] {
        assert_eq!(
            handle_close(&mut registry, &mut tasks, process, handle, &mut cleanup),
            DW_STATUS_SUCCESS
        );
    }
    assert_eq!(
        thread_exit(
            &mut registry,
            &mut tasks,
            &execution,
            process,
            current,
            0x55,
            &mut cleanup,
        ),
        (DW_STATUS_SUCCESS, SyscallControl::TerminateCurrent)
    );
    assert_eq!(execution.scheduler_state(current), None);
    let _ = current_handle;
    finish_task_cleanup(&mut registry, &mut tasks, cleanup);
}

#[test]
fn channel_transfer_moves_event_and_publishes_reduced_receiver_rights() {
    use deepwyrm_abi::{
        DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_EVENT, DW_RIGHT_INSPECT, DW_RIGHT_READ,
        DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE,
    };

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let channels = ChannelAuthority::<2, 4>::new();
    let waits = WaitRegistry::<8>::new();
    let events = EventAuthority::<2>::new();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut user = FakeUserMemory::new();
    let mut cleanup = CleanupQueue::<16>::new();
    let channel_rights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_TRANSFER.0);
    assert_eq!(
        channel_create(
            &mut user,
            &mut registry,
            &channels,
            &mut tasks,
            process,
            channel_rights,
            DwUserAddress(BASE + 0x180),
            DwUserAddress(BASE + 0x188),
        ),
        DW_STATUS_SUCCESS
    );
    let endpoint0 = DwHandle(u64_at(&user, BASE + 0x180));
    let endpoint1 = DwHandle(u64_at(&user, BASE + 0x188));
    let source = install_event_for_test(
        &mut registry,
        &mut tasks,
        process,
        &events,
        DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0),
    );
    write_handle_transfer(
        &mut user,
        BASE + 0x300,
        deepwyrm_abi::DwHandleTransferV1 {
            handle: source,
            requested_rights: DW_RIGHT_WAIT,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        },
    );
    user.bytes[FakeUserMemory::offset(BASE + 0x380, 1)] = 0x6b;
    let mut staging = std::vec![0_u8; DW_CHANNEL_MAX_PAYLOAD as usize];

    assert_eq!(
        channel_send(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint0,
            DwUserAddress(BASE + 0x380),
            1,
            DwUserAddress(BASE + 0x300),
            1,
            0,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        tasks
            .process_handles(process)
            .unwrap()
            .inspect_basic(source),
        Err(HandleTableError::InvalidHandle)
    );

    assert_eq!(
        channel_receive(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint1,
            DwUserAddress(BASE + 0x400),
            1,
            DwUserAddress(BASE + 0x480),
            1,
            DwUserAddress(BASE + 0x500),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(user.bytes[FakeUserMemory::offset(BASE + 0x400, 1)], 0x6b);
    let received = DwHandle(u64_at(&user, BASE + 0x480));
    assert_ne!(received, source);
    assert_eq!(u64_at(&user, BASE + 0x488), DW_RIGHT_WAIT.0);
    assert_eq!(u32_at(&user, BASE + 0x490), DW_OBJECT_TYPE_EVENT.0);
    assert_eq!(u32_at(&user, BASE + 0x500 + 12), 1);
    assert_eq!(u32_at(&user, BASE + 0x500 + 20), 1);
    let resolved = tasks
        .process_handles(process)
        .unwrap()
        .lookup(
            &mut registry,
            received,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_EVENT),
            DW_RIGHT_WAIT,
        )
        .unwrap();
    assert_eq!(resolved.rights(), DW_RIGHT_WAIT);
    assert!(
        registry
            .release_internal(resolved.into_internal())
            .unwrap()
            .is_none()
    );

    close_event_for_test(&mut registry, &mut tasks, process, &events, received);
    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        endpoint0,
    );
    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        endpoint1,
    );
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
}

#[test]
fn channel_transfer_descriptor_validation_precedes_source_mutation() {
    use deepwyrm_abi::{
        DW_HANDLE_TRANSFER_MOVE, DW_RIGHT_INSPECT, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT,
        DW_RIGHT_WRITE, DwHandleTransferOperation,
    };

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let channels = ChannelAuthority::<2, 4>::new();
    let waits = WaitRegistry::<8>::new();
    let events = EventAuthority::<2>::new();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut user = FakeUserMemory::new();
    let mut cleanup = CleanupQueue::<16>::new();
    assert_eq!(
        channel_create(
            &mut user,
            &mut registry,
            &channels,
            &mut tasks,
            process,
            DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0),
            DwUserAddress(BASE + 0x180),
            DwUserAddress(BASE + 0x188),
        ),
        DW_STATUS_SUCCESS
    );
    let endpoint0 = DwHandle(u64_at(&user, BASE + 0x180));
    let endpoint1 = DwHandle(u64_at(&user, BASE + 0x188));
    let source_rights = DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0);
    let source = install_event_for_test(&mut registry, &mut tasks, process, &events, source_rights);
    let mut staging = std::vec![0_u8; DW_CHANNEL_MAX_PAYLOAD as usize];

    write_handle_transfer(
        &mut user,
        BASE + 0x300,
        deepwyrm_abi::DwHandleTransferV1 {
            handle: DwHandle(u64::MAX),
            requested_rights: DW_RIGHT_WAIT,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 1,
            reserved: [0; 2],
        },
    );
    assert_eq!(
        channel_send(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint0,
            DwUserAddress(0),
            0,
            DwUserAddress(BASE + 0x300),
            1,
            0,
            &mut cleanup,
        ),
        DW_STATUS_INVALID_ARGUMENT
    );

    write_handle_transfer(
        &mut user,
        BASE + 0x300,
        deepwyrm_abi::DwHandleTransferV1 {
            handle: source,
            requested_rights: DW_RIGHT_WAIT,
            operation: DwHandleTransferOperation(99),
            reserved0: 0,
            reserved: [0; 2],
        },
    );
    assert_eq!(
        channel_send(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint0,
            DwUserAddress(0),
            0,
            DwUserAddress(BASE + 0x300),
            1,
            0,
            &mut cleanup,
        ),
        DW_STATUS_INVALID_ARGUMENT
    );

    for address in [BASE + 0x300, BASE + 0x328] {
        write_handle_transfer(
            &mut user,
            address,
            deepwyrm_abi::DwHandleTransferV1 {
                handle: source,
                requested_rights: DW_RIGHT_WAIT,
                operation: DW_HANDLE_TRANSFER_MOVE,
                reserved0: 0,
                reserved: [0; 2],
            },
        );
    }
    assert_eq!(
        channel_send(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint0,
            DwUserAddress(0),
            0,
            DwUserAddress(BASE + 0x300),
            2,
            0,
            &mut cleanup,
        ),
        DW_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(
        tasks
            .process_handles(process)
            .unwrap()
            .inspect_basic(source)
            .unwrap()
            .rights,
        source_rights
    );

    close_event_for_test(&mut registry, &mut tasks, process, &events, source);
    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        endpoint0,
    );
    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        endpoint1,
    );
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut cleanup
        ),
        DW_STATUS_SUCCESS
    );
}

#[test]
fn channel_queue_full_preserves_transfer_source_authority() {
    use deepwyrm_abi::{
        DW_HANDLE_TRANSFER_MOVE, DW_RIGHT_INSPECT, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT,
        DW_RIGHT_WRITE,
    };

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let channels = ChannelAuthority::<2, 4>::new();
    let waits = WaitRegistry::<8>::new();
    let events = EventAuthority::<2>::new();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut user = FakeUserMemory::new();
    let mut cleanup = CleanupQueue::<16>::new();
    assert_eq!(
        channel_create(
            &mut user,
            &mut registry,
            &channels,
            &mut tasks,
            process,
            DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0),
            DwUserAddress(BASE + 0x180),
            DwUserAddress(BASE + 0x188),
        ),
        DW_STATUS_SUCCESS
    );
    let endpoint0 = DwHandle(u64_at(&user, BASE + 0x180));
    let endpoint1 = DwHandle(u64_at(&user, BASE + 0x188));
    let source_rights = DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0);
    let source = install_event_for_test(&mut registry, &mut tasks, process, &events, source_rights);
    let mut staging = std::vec![0_u8; DW_CHANNEL_MAX_PAYLOAD as usize];
    for _ in 0..4 {
        assert_eq!(
            channel_send(
                &mut user,
                &mut staging,
                &mut registry,
                &channels,
                &waits,
                &mut tasks,
                &execution,
                process,
                endpoint0,
                DwUserAddress(0),
                0,
                DwUserAddress(0),
                0,
                0,
                &mut cleanup,
            ),
            DW_STATUS_SUCCESS
        );
    }
    write_handle_transfer(
        &mut user,
        BASE + 0x300,
        deepwyrm_abi::DwHandleTransferV1 {
            handle: source,
            requested_rights: DW_RIGHT_WAIT,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        },
    );
    assert_eq!(
        channel_send(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint0,
            DwUserAddress(0),
            0,
            DwUserAddress(BASE + 0x300),
            1,
            0,
            &mut cleanup,
        ),
        DW_STATUS_WOULD_BLOCK
    );
    assert_eq!(
        tasks
            .process_handles(process)
            .unwrap()
            .inspect_basic(source)
            .unwrap()
            .rights,
        source_rights
    );

    close_event_for_test(&mut registry, &mut tasks, process, &events, source);
    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        endpoint0,
    );
    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        endpoint1,
    );
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut cleanup
        ),
        DW_STATUS_SUCCESS
    );
}

#[test]
fn channel_peer_self_reference_is_rejected_but_sending_endpoint_move_succeeds() {
    use deepwyrm_abi::{
        DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DW_RIGHT_READ, DW_RIGHT_TRANSFER,
        DW_RIGHT_WRITE,
    };

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let channels = ChannelAuthority::<2, 4>::new();
    let waits = WaitRegistry::<8>::new();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut user = FakeUserMemory::new();
    let mut cleanup = CleanupQueue::<16>::new();
    let channel_rights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_TRANSFER.0);
    assert_eq!(
        channel_create(
            &mut user,
            &mut registry,
            &channels,
            &mut tasks,
            process,
            channel_rights,
            DwUserAddress(BASE + 0x180),
            DwUserAddress(BASE + 0x188),
        ),
        DW_STATUS_SUCCESS
    );
    let endpoint0 = DwHandle(u64_at(&user, BASE + 0x180));
    let endpoint1 = DwHandle(u64_at(&user, BASE + 0x188));
    let mut staging = std::vec![0_u8; DW_CHANNEL_MAX_PAYLOAD as usize];

    write_handle_transfer(
        &mut user,
        BASE + 0x300,
        deepwyrm_abi::DwHandleTransferV1 {
            handle: endpoint1,
            requested_rights: DW_RIGHT_READ,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        },
    );
    assert_eq!(
        channel_send(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint0,
            DwUserAddress(0),
            0,
            DwUserAddress(BASE + 0x300),
            1,
            0,
            &mut cleanup,
        ),
        DW_STATUS_INVALID_ARGUMENT
    );
    let peer_pin = tasks
        .process_handles(process)
        .unwrap()
        .lookup(
            &mut registry,
            endpoint1,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_CHANNEL),
            DW_RIGHT_READ,
        )
        .unwrap();
    assert!(
        registry
            .release_internal(peer_pin.into_internal())
            .unwrap()
            .is_none()
    );

    write_handle_transfer(
        &mut user,
        BASE + 0x300,
        deepwyrm_abi::DwHandleTransferV1 {
            handle: endpoint0,
            requested_rights: DW_RIGHT_WRITE,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        },
    );
    assert_eq!(
        channel_send(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint0,
            DwUserAddress(0),
            0,
            DwUserAddress(BASE + 0x300),
            1,
            0,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        tasks
            .process_handles(process)
            .unwrap()
            .inspect_basic(endpoint0),
        Err(HandleTableError::InvalidHandle)
    );
    assert_eq!(
        channel_receive(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint1,
            DwUserAddress(0),
            0,
            DwUserAddress(BASE + 0x480),
            1,
            DwUserAddress(BASE + 0x500),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let moved_endpoint0 = DwHandle(u64_at(&user, BASE + 0x480));
    assert_ne!(moved_endpoint0, endpoint0);
    assert_eq!(u64_at(&user, BASE + 0x488), DW_RIGHT_WRITE.0);
    assert_eq!(u32_at(&user, BASE + 0x490), DW_OBJECT_TYPE_CHANNEL.0);

    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        moved_endpoint0,
    );
    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        endpoint1,
    );
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut cleanup
        ),
        DW_STATUS_SUCCESS
    );
}

#[test]
fn channel_receive_handle_capacity_failure_preserves_queued_datagram() {
    use deepwyrm_abi::{
        DW_HANDLE_TRANSFER_MOVE, DW_RIGHT_INSPECT, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT,
        DW_RIGHT_WRITE,
    };

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let channels = ChannelAuthority::<2, 4>::new();
    let waits = WaitRegistry::<8>::new();
    let events = EventAuthority::<8>::new();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut user = FakeUserMemory::new();
    let mut cleanup = CleanupQueue::<16>::new();
    assert_eq!(
        channel_create(
            &mut user,
            &mut registry,
            &channels,
            &mut tasks,
            process,
            DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0),
            DwUserAddress(BASE + 0x180),
            DwUserAddress(BASE + 0x188),
        ),
        DW_STATUS_SUCCESS
    );
    let endpoint0 = DwHandle(u64_at(&user, BASE + 0x180));
    let endpoint1 = DwHandle(u64_at(&user, BASE + 0x188));
    let source = install_event_for_test(
        &mut registry,
        &mut tasks,
        process,
        &events,
        DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0),
    );
    write_handle_transfer(
        &mut user,
        BASE + 0x300,
        deepwyrm_abi::DwHandleTransferV1 {
            handle: source,
            requested_rights: DW_RIGHT_WAIT,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        },
    );
    let mut staging = std::vec![0_u8; DW_CHANNEL_MAX_PAYLOAD as usize];
    assert_eq!(
        channel_send(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint0,
            DwUserAddress(0),
            0,
            DwUserAddress(BASE + 0x300),
            1,
            0,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );

    let mut fillers = [DwHandle(0); 5];
    for filler in &mut fillers {
        *filler =
            install_event_for_test(&mut registry, &mut tasks, process, &events, DW_RIGHT_WAIT);
    }
    assert_eq!(tasks.process_handle_count(process).unwrap(), 8);
    let result_offset =
        FakeUserMemory::offset(BASE + 0x700, DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize);
    user.bytes[result_offset..result_offset + DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize]
        .fill(0xa5);
    assert_eq!(
        channel_receive(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint1,
            DwUserAddress(0),
            0,
            DwUserAddress(BASE + 0x600),
            1,
            DwUserAddress(BASE + 0x700),
            &mut cleanup,
        ),
        DW_STATUS_NO_RESOURCES
    );
    assert!(
        user.bytes[result_offset..result_offset + DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize]
            .iter()
            .all(|byte| *byte == 0xa5)
    );
    assert_eq!(tasks.process_handle_count(process).unwrap(), 8);

    close_event_for_test(&mut registry, &mut tasks, process, &events, fillers[0]);
    assert_eq!(tasks.process_handle_count(process).unwrap(), 7);
    assert_eq!(
        channel_receive(
            &mut user,
            &mut staging,
            &mut registry,
            &channels,
            &waits,
            &mut tasks,
            &execution,
            process,
            endpoint1,
            DwUserAddress(0),
            0,
            DwUserAddress(BASE + 0x600),
            1,
            DwUserAddress(BASE + 0x700),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let received = DwHandle(u64_at(&user, BASE + 0x600));
    assert_eq!(u32_at(&user, BASE + 0x700 + 12), 1);
    assert_eq!(u32_at(&user, BASE + 0x700 + 20), 1);
    assert_eq!(tasks.process_handle_count(process).unwrap(), 8);

    close_event_for_test(&mut registry, &mut tasks, process, &events, received);
    for filler in fillers.into_iter().skip(1) {
        close_event_for_test(&mut registry, &mut tasks, process, &events, filler);
    }
    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        endpoint0,
    );
    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        endpoint1,
    );
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut cleanup
        ),
        DW_STATUS_SUCCESS
    );
}
