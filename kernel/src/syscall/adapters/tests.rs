extern crate std;

use super::*;
use crate::memory::address_region::{
    AddressRegionObjectAuthority, AddressSpaceAuthority, complete_address_region_finalization,
};
use crate::memory::user_range::UserPageChunk;
use crate::memory::usercopy::{PinnedUserBatchPages, PinnedUserPages, UserPageBatchAccess};
use crate::object::ObjectRegistry;
use crate::task::{BlockedOperation, BlockedOperationWinner, TaskAuthority};
use deepwyrm_abi::{DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_MODIFY};

const BASE: u64 = 0x4000;
const BYTES: usize = 4096;

fn terminal_outcome(
    outcome: (
        DwStatus,
        SyscallControl,
        Option<DeferredCurrentExecutionResources>,
    ),
    status: DwStatus,
    control: SyscallControl,
) -> Option<DeferredCurrentExecutionResources> {
    let (actual_status, actual_control, deferred) = outcome;
    assert_eq!(actual_status, status);
    assert_eq!(actual_control, control);
    assert_eq!(
        deferred.is_some(),
        control == SyscallControl::TerminateCurrent,
        "terminal control and deferred current ownership diverged"
    );
    deferred
}

struct FakeUserMemory {
    bytes: [u8; BYTES],
    deny_read: bool,
    deny_write: bool,
    deny_write_at: Option<u64>,
    owned_outputs: usize,
}

struct FakeOwnedOutput {
    range: UserRange,
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
            deny_read: false,
            deny_write: false,
            deny_write_at: None,
            owned_outputs: 0,
        }
    }

    fn offset(address: u64, len: usize) -> usize {
        let offset = usize::try_from(address - BASE).unwrap();
        assert!(offset + len <= BYTES);
        offset
    }

    fn write_is_denied(&self, address: u64, byte_len: u64) -> bool {
        self.deny_write
            || self.deny_write_at.is_some_and(|denied| {
                let end = address
                    .checked_add(byte_len)
                    .expect("fake user write range cannot overflow");
                address <= denied && denied < end
            })
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

impl OwnedUserOutputAccess for FakeUserMemory {
    type OwnedOutput = FakeOwnedOutput;

    fn preflight_owned_output(
        &mut self,
        range: UserRange,
    ) -> Result<Self::OwnedOutput, Self::Error> {
        if !range.access().includes(UserAccess::WRITE)
            || self.write_is_denied(range.start(), range.byte_len())
        {
            return Err(());
        }
        let len = usize::try_from(range.byte_len()).map_err(|_| ())?;
        let _ = Self::offset(range.start(), len);
        self.owned_outputs += 1;
        Ok(FakeOwnedOutput { range })
    }

    fn commit_owned_output(&mut self, output: Self::OwnedOutput, source: &[u8]) {
        assert_eq!(
            usize::try_from(output.range.byte_len()).unwrap(),
            source.len()
        );
        let offset = Self::offset(output.range.start(), source.len());
        self.bytes[offset..offset + source.len()].copy_from_slice(source);
        self.owned_outputs = self
            .owned_outputs
            .checked_sub(1)
            .expect("owned fake output commit underflow");
    }

    fn discard_owned_output(&mut self, _output: Self::OwnedOutput) {
        self.owned_outputs = self
            .owned_outputs
            .checked_sub(1)
            .expect("owned fake output discard underflow");
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
        if self.memory.deny_read && chunk.access().includes(UserAccess::READ) {
            return Err(());
        }
        if chunk.access().includes(UserAccess::WRITE)
            && self
                .memory
                .write_is_denied(chunk.address(), chunk.byte_len())
        {
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
        if chunk.access().includes(UserAccess::WRITE)
            && self
                .memory
                .write_is_denied(chunk.address(), chunk.byte_len())
        {
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

#[test]
fn atomic_wake_zero_count_preserves_address_key_output_and_dispatch_order() {
    use std::cell::RefCell;

    let mut user = FakeUserMemory::new();
    let trace = RefCell::new(std::vec::Vec::new());
    let out_woken = BASE + 0x80;
    user.bytes[FakeUserMemory::offset(out_woken, 4)..FakeUserMemory::offset(out_woken, 4) + 4]
        .fill(0xa5);

    assert_eq!(
        atomic_wake_with(
            &mut user,
            DwUserAddress(BASE + 0x40),
            0,
            DwUserAddress(out_woken),
            |_, address| {
                trace.borrow_mut().push("pin");
                assert_eq!(address, DwUserAddress(BASE + 0x40));
                Ok(0x11_u32)
            },
            |address, pin| {
                trace.borrow_mut().push("key");
                assert_eq!(address, DwUserAddress(BASE + 0x40));
                assert_eq!(*pin, 0x11);
                Ok(0x22_u32)
            },
            |_, pin| {
                trace.borrow_mut().push("release");
                assert_eq!(pin, 0x11);
            },
            |key, count| {
                trace.borrow_mut().push("wake");
                assert_eq!(key, 0x22);
                assert_eq!(count, 0);
                Ok(0)
            },
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(&*trace.borrow(), &["pin", "key", "wake", "release"]);
    assert_eq!(u32_at(&user, out_woken), 0);
    assert_eq!(user.owned_outputs, 0);
}

#[test]
fn atomic_wake_validation_failures_release_pins_without_wake_or_copyout() {
    use std::cell::RefCell;

    let out_woken = BASE + 0x80;

    let mut user = FakeUserMemory::new();
    user.bytes[FakeUserMemory::offset(out_woken, 4)..FakeUserMemory::offset(out_woken, 4) + 4]
        .fill(0xa5);
    let trace = RefCell::new(std::vec::Vec::new());
    assert_eq!(
        atomic_wake_with(
            &mut user,
            DwUserAddress(BASE + 0x40),
            1,
            DwUserAddress(out_woken),
            |_, _| {
                trace.borrow_mut().push("pin");
                Err::<u32, _>(DW_STATUS_BAD_ADDRESS)
            },
            |_, _| {
                trace.borrow_mut().push("key");
                Ok(0_u32)
            },
            |_, _| trace.borrow_mut().push("release"),
            |_, _| {
                trace.borrow_mut().push("wake");
                Ok(1)
            },
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(&*trace.borrow(), &["pin"]);
    assert_eq!(
        &user.bytes[FakeUserMemory::offset(out_woken, 4)..][..4],
        &[0xa5; 4]
    );

    let trace = RefCell::new(std::vec::Vec::new());
    assert_eq!(
        atomic_wake_with(
            &mut user,
            DwUserAddress(BASE + 0x40),
            1,
            DwUserAddress(out_woken),
            |_, _| {
                trace.borrow_mut().push("pin");
                Ok(0x11_u32)
            },
            |_, _| {
                trace.borrow_mut().push("key");
                Err::<u32, _>(DW_STATUS_BAD_ADDRESS)
            },
            |_, pin| {
                trace.borrow_mut().push("release");
                assert_eq!(pin, 0x11);
            },
            |_, _| {
                trace.borrow_mut().push("wake");
                Ok(1)
            },
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(&*trace.borrow(), &["pin", "key", "release"]);
    assert_eq!(
        &user.bytes[FakeUserMemory::offset(out_woken, 4)..][..4],
        &[0xa5; 4]
    );

    for denied_output in [DwUserAddress(out_woken + 1), DwUserAddress(out_woken)] {
        user.deny_write_at = (denied_output == DwUserAddress(out_woken)).then_some(out_woken);
        let trace = RefCell::new(std::vec::Vec::new());
        assert_eq!(
            atomic_wake_with(
                &mut user,
                DwUserAddress(BASE + 0x40),
                1,
                denied_output,
                |_, _| {
                    trace.borrow_mut().push("pin");
                    Ok(0x11_u32)
                },
                |_, _| {
                    trace.borrow_mut().push("key");
                    Ok(0x22_u32)
                },
                |_, pin| {
                    trace.borrow_mut().push("release");
                    assert_eq!(pin, 0x11);
                },
                |_, _| {
                    trace.borrow_mut().push("wake");
                    Ok(1)
                },
            ),
            DW_STATUS_BAD_ADDRESS
        );
        assert_eq!(&*trace.borrow(), &["pin", "key", "release"]);
        assert_eq!(
            &user.bytes[FakeUserMemory::offset(out_woken, 4)..][..4],
            &[0xa5; 4]
        );
        assert_eq!(user.owned_outputs, 0);
    }
}

#[test]
fn atomic_wake_failure_discards_output_and_success_commits_exact_count() {
    use std::cell::RefCell;

    let mut user = FakeUserMemory::new();
    let out_woken = BASE + 0x80;
    user.bytes[FakeUserMemory::offset(out_woken, 4)..FakeUserMemory::offset(out_woken, 4) + 4]
        .fill(0xa5);
    let trace = RefCell::new(std::vec::Vec::new());
    assert_eq!(
        atomic_wake_with(
            &mut user,
            DwUserAddress(BASE + 0x40),
            3,
            DwUserAddress(out_woken),
            |_, _| {
                trace.borrow_mut().push("pin");
                Ok(0x11_u32)
            },
            |_, _| {
                trace.borrow_mut().push("key");
                Ok(0x22_u32)
            },
            |_, _| trace.borrow_mut().push("release"),
            |key, count| {
                trace.borrow_mut().push("wake");
                assert_eq!((key, count), (0x22, 3));
                Err(DW_STATUS_BAD_STATE)
            },
        ),
        DW_STATUS_BAD_STATE
    );
    assert_eq!(&*trace.borrow(), &["pin", "key", "wake", "release"]);
    assert_eq!(
        &user.bytes[FakeUserMemory::offset(out_woken, 4)..][..4],
        &[0xa5; 4]
    );
    assert_eq!(user.owned_outputs, 0);

    assert_eq!(
        atomic_wake_with(
            &mut user,
            DwUserAddress(BASE + 0x40),
            3,
            DwUserAddress(out_woken),
            |_, _| Ok(0x11_u32),
            |_, _| Ok(0x22_u32),
            |_, pin| assert_eq!(pin, 0x11),
            |key, count| {
                assert_eq!((key, count), (0x22, 3));
                Ok(2)
            },
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(u32_at(&user, out_woken), 2);
    assert_eq!(user.owned_outputs, 0);
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

fn close_channel_for_test<const PAIRS: usize, const DEPTH: usize, const WAITERS: usize>(
    registry: &mut ObjectRegistry<16>,
    tasks: &mut Tasks,
    process: ProcessKey,
    channels: &ChannelAuthority<PAIRS, DEPTH>,
    waits: &WaitRegistry<WAITERS>,
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

fn create_channel_pair_for_test<const PAIRS: usize, const DEPTH: usize>(
    user: &mut FakeUserMemory,
    registry: &mut ObjectRegistry<16>,
    channels: &ChannelAuthority<PAIRS, DEPTH>,
    tasks: &mut Tasks,
    process: ProcessKey,
    rights: DwRights,
    first_output: u64,
) -> [DwHandle; 2] {
    assert_eq!(
        channel_create(
            user,
            registry,
            channels,
            tasks,
            process,
            rights,
            DwUserAddress(first_output),
            DwUserAddress(first_output + 8),
        ),
        DW_STATUS_SUCCESS
    );
    [
        DwHandle(u64_at(user, first_output)),
        DwHandle(u64_at(user, first_output + 8)),
    ]
}

fn complete_channel_cleanup_for_test<
    const PAIRS: usize,
    const DEPTH: usize,
    const WAITERS: usize,
>(
    registry: &mut ObjectRegistry<16>,
    channels: &ChannelAuthority<PAIRS, DEPTH>,
    waits: &WaitRegistry<WAITERS>,
    cleanup: CleanupQueue<16>,
) {
    let mut pending: std::vec::Vec<_> = cleanup.into_releases().into_iter().flatten().collect();
    while let Some(release) = pending.pop() {
        assert_eq!(release.object_type(), deepwyrm_abi::DW_OBJECT_TYPE_CHANNEL);
        let finalization = channels.take_finalization(release, waits).unwrap();
        let completion = crate::ipc::complete_channel_finalization(registry, finalization);
        let (wakes, releases) = completion.into_parts();
        assert_eq!(wakes.len(), 0);
        pending.extend(releases.into_iter().flatten());
    }
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
fn timer_syscalls_preserve_validation_rights_and_level_state() {
    use deepwyrm_abi::{
        DW_DEADLINE_INFINITE, DW_OBJECT_TYPE_TIMER, DW_RIGHT_MODIFY, DW_RIGHT_WAIT,
        DW_SIGNAL_SIGNALED, DwRights,
    };

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let timers = TimerAuthority::<2>::new();
    let waits = WaitRegistry::<2>::new();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut deadlines = AdapterTimerDeadline::<2>::new(10);
    let mut user = FakeUserMemory::new();
    let mut cleanup = CleanupQueue::<16>::new();
    let out = DwUserAddress(BASE + 0x1c0);
    let generations = registry.test_slot_generations();

    user.deny_write = true;
    assert_eq!(
        timer_create(
            &mut user,
            &mut registry,
            &timers,
            &mut tasks,
            process,
            DwRights(0),
            out,
            &mut cleanup,
        ),
        DW_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(registry.test_slot_generations(), generations);

    let full_rights = DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0);
    assert_eq!(
        timer_create(
            &mut user,
            &mut registry,
            &timers,
            &mut tasks,
            process,
            full_rights,
            out,
            &mut cleanup,
        ),
        DW_STATUS_BAD_ADDRESS
    );
    assert_eq!(registry.test_slot_generations(), generations);

    user.deny_write = false;
    assert_eq!(
        timer_create(
            &mut user,
            &mut registry,
            &timers,
            &mut tasks,
            process,
            full_rights,
            out,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let timer = DwHandle(u64_at(&user, out.0));
    let timer_pin = tasks
        .process_handles(process)
        .unwrap()
        .lookup(
            &mut registry,
            timer,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_TIMER),
            DW_RIGHT_WAIT,
        )
        .unwrap();
    let timer_key = TimerKey::from_object_id(timer_pin.object_id());
    release_lookup_pin(&mut registry, timer_pin.into_internal(), &mut cleanup);
    assert_eq!(
        timers.current_signals(timer_key).unwrap(),
        deepwyrm_abi::DwSignals(0)
    );

    assert_eq!(
        timer_set(
            &mut registry,
            &timers,
            &mut deadlines,
            &waits,
            &tasks,
            &execution,
            process,
            DwHandle(u64::MAX),
            DW_DEADLINE_INFINITE,
            &mut cleanup,
        ),
        DW_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(
        timer_set(
            &mut registry,
            &timers,
            &mut deadlines,
            &waits,
            &tasks,
            &execution,
            process,
            process_handle,
            deepwyrm_abi::DwDeadline(100),
            &mut cleanup,
        ),
        DW_STATUS_WRONG_OBJECT_TYPE
    );
    assert_eq!(
        timer_set(
            &mut registry,
            &timers,
            &mut deadlines,
            &waits,
            &tasks,
            &execution,
            process,
            timer,
            deepwyrm_abi::DwDeadline(100),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        timers.current_signals(timer_key).unwrap(),
        deepwyrm_abi::DwSignals(0)
    );
    assert_eq!(deadlines.queue.earliest(), Some(100));

    assert_eq!(
        timer_set(
            &mut registry,
            &timers,
            &mut deadlines,
            &waits,
            &tasks,
            &execution,
            process,
            timer,
            deepwyrm_abi::DwDeadline(10),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        timers.current_signals(timer_key).unwrap(),
        DW_SIGNAL_SIGNALED
    );
    assert_eq!(deadlines.queue.earliest(), None);
    assert_eq!(
        timer_cancel(
            &mut registry,
            &timers,
            &mut deadlines,
            &tasks,
            process,
            timer,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        timers.current_signals(timer_key).unwrap(),
        deepwyrm_abi::DwSignals(0)
    );

    let second_out = DwUserAddress(BASE + 0x1d0);
    assert_eq!(
        timer_create(
            &mut user,
            &mut registry,
            &timers,
            &mut tasks,
            process,
            DW_RIGHT_WAIT,
            second_out,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let wait_only = DwHandle(u64_at(&user, second_out.0));
    assert_eq!(
        timer_set(
            &mut registry,
            &timers,
            &mut deadlines,
            &waits,
            &tasks,
            &execution,
            process,
            wait_only,
            deepwyrm_abi::DwDeadline(200),
            &mut cleanup,
        ),
        DW_STATUS_ACCESS_DENIED
    );

    for handle in [timer, wait_only] {
        let release = tasks
            .process_handles_mut(process)
            .unwrap()
            .close(&mut registry, handle)
            .unwrap()
            .expect("unarmed Timer handle is final");
        let finalization = timers.take_finalization(release, &mut deadlines).unwrap();
        crate::time::complete_timer_finalization(&mut registry, finalization);
    }
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

struct NativeTimerHarness<'a> {
    user: &'a mut FakeUserMemory,
    registry: &'a mut ObjectRegistry<16>,
    timers: &'a TimerAuthority<2>,
    deadlines: &'a mut AdapterTimerDeadline<2>,
    waits: &'a WaitRegistry<2>,
    tasks: &'a mut Tasks,
    execution: &'a ExecutionDomain<1>,
    process: ProcessKey,
    cleanup: &'a mut CleanupQueue<16>,
}

impl crate::syscall::native::NativeSyscallHandler for NativeTimerHarness<'_> {
    fn handle(
        &mut self,
        request: crate::syscall::native::NativeSyscallRequest,
    ) -> crate::syscall::native::NativeSyscallResult {
        let status = match request {
            crate::syscall::native::NativeSyscallRequest::TimerCreate {
                requested_rights,
                out_timer,
            } => timer_create(
                self.user,
                self.registry,
                self.timers,
                self.tasks,
                self.process,
                requested_rights,
                out_timer,
                self.cleanup,
            ),
            crate::syscall::native::NativeSyscallRequest::TimerSet { timer, deadline } => {
                timer_set(
                    self.registry,
                    self.timers,
                    self.deadlines,
                    self.waits,
                    self.tasks,
                    self.execution,
                    self.process,
                    timer,
                    deadline,
                    self.cleanup,
                )
            }
            crate::syscall::native::NativeSyscallRequest::TimerCancel { timer } => timer_cancel(
                self.registry,
                self.timers,
                self.deadlines,
                self.tasks,
                self.process,
                timer,
                self.cleanup,
            ),
            _ => panic!("native F8 harness received a non-Timer request"),
        };
        crate::syscall::native::NativeSyscallResult::returning(status)
    }
}

#[test]
fn native_timer_ids_route_through_real_timer_transactions() {
    use deepwyrm_abi::{DW_RIGHT_MODIFY, DW_RIGHT_WAIT, DwKnownSyscall, DwRights};

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let timers = TimerAuthority::<2>::new();
    let waits = WaitRegistry::<2>::new();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut deadlines = AdapterTimerDeadline::<2>::new(10);
    let mut user = FakeUserMemory::new();
    let mut cleanup = CleanupQueue::<16>::new();
    let out = BASE + 0x1e0;

    {
        let mut harness = NativeTimerHarness {
            user: &mut user,
            registry: &mut registry,
            timers: &timers,
            deadlines: &mut deadlines,
            waits: &waits,
            tasks: &mut tasks,
            execution: &execution,
            process,
            cleanup: &mut cleanup,
        };
        let create = crate::syscall::native::dispatch_native(
            &mut harness,
            DwKnownSyscall::TimerCreate.id(),
            crate::syscall::RawSyscallArguments::new([
                DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0).0,
                out,
                0,
                0,
                0,
                0,
            ]),
        );
        assert_eq!(create.status, DW_STATUS_SUCCESS);
        assert_eq!(create.control, SyscallControl::ReturnToCaller);
    }
    let timer = DwHandle(u64_at(&user, out));

    {
        let mut harness = NativeTimerHarness {
            user: &mut user,
            registry: &mut registry,
            timers: &timers,
            deadlines: &mut deadlines,
            waits: &waits,
            tasks: &mut tasks,
            execution: &execution,
            process,
            cleanup: &mut cleanup,
        };
        for (syscall, arguments) in [
            (DwKnownSyscall::TimerSet, [timer.0, 100, 0, 0, 0, 0]),
            (DwKnownSyscall::TimerSet, [timer.0, 10, 0, 0, 0, 0]),
            (DwKnownSyscall::TimerCancel, [timer.0, 0, 0, 0, 0, 0]),
        ] {
            let result = crate::syscall::native::dispatch_native(
                &mut harness,
                syscall.id(),
                crate::syscall::RawSyscallArguments::new(arguments),
            );
            assert_eq!(result.status, DW_STATUS_SUCCESS, "{syscall:?}");
            assert_eq!(result.control, SyscallControl::ReturnToCaller);
        }
    }

    let release = tasks
        .process_handles_mut(process)
        .unwrap()
        .close(&mut registry, timer)
        .unwrap()
        .expect("native Timer handle is final");
    let finalization = timers.take_finalization(release, &mut deadlines).unwrap();
    crate::time::complete_timer_finalization(&mut registry, finalization);
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
fn process_exit_defers_current_execution_bundle_until_reaper_completion() {
    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let waits = WaitRegistry::<2>::new();
    let mut terminal_waits = NoTerminalWaitCleanup;
    let mut cleanup = CleanupQueue::<16>::new();
    let process_pin = resolve_current_handle(
        &tasks,
        &mut registry,
        process,
        process_handle,
        deepwyrm_abi::DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_MODIFY,
    )
    .unwrap();
    let (current, current_ref) = tasks.create_thread(&mut registry, &process_pin).unwrap();
    release_lookup_pin(&mut registry, process_pin, &mut cleanup);
    execution
        .start_thread(&mut tasks, current, test_start(0x10))
        .unwrap();
    assert_eq!(execution.schedule_next().unwrap().current, Some(current));
    let (stack, context) = tasks.thread_execution_resources(current).unwrap().unwrap();

    let deferred = terminal_outcome(
        process_exit(
            &mut registry,
            &mut tasks,
            &execution,
            &waits,
            &mut terminal_waits,
            process,
            current,
            0,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS,
        SyscallControl::TerminateCurrent,
    )
    .unwrap();
    assert!(execution.stack_bounds(stack).is_ok());
    assert!(execution.load_context(context).is_ok());
    complete_deferred_current_reclaim(&mut registry, &execution, &waits, deferred, &mut cleanup);
    assert!(execution.stack_bounds(stack).is_err());
    assert!(execution.load_context(context).is_err());
    cleanup.push_optional(registry.release_handle(current_ref).unwrap());
    finish_task_cleanup(&mut registry, &mut tasks, cleanup);
}

#[test]
fn unhandled_user_exception_defers_current_stack_and_records_structured_exit() {
    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let waits = WaitRegistry::<2>::new();
    let mut terminal_waits = NoTerminalWaitCleanup;
    let mut cleanup = CleanupQueue::<16>::new();
    let process_pin = resolve_current_handle(
        &tasks,
        &mut registry,
        process,
        process_handle,
        deepwyrm_abi::DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_MODIFY,
    )
    .unwrap();
    let (current, current_ref) = tasks.create_thread(&mut registry, &process_pin).unwrap();
    release_lookup_pin(&mut registry, process_pin, &mut cleanup);
    execution
        .start_thread(&mut tasks, current, test_start(0x20))
        .unwrap();
    assert_eq!(execution.schedule_next().unwrap().current, Some(current));
    let (stack, context) = tasks.thread_execution_resources(current).unwrap().unwrap();

    let deferred = terminal_outcome(
        process_unhandled_exception(
            &mut registry,
            &mut tasks,
            &execution,
            &waits,
            &mut terminal_waits,
            process,
            current,
            crate::task::TaskExceptionRecord::new(
                deepwyrm_abi::DW_EXCEPTION_PAGE_FAULT,
                0x44,
                0x5555,
            ),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS,
        SyscallControl::TerminateCurrent,
    )
    .unwrap();
    let info = tasks.process_info(process).unwrap();
    assert_eq!(
        info.reason,
        deepwyrm_abi::DW_TERMINATION_UNHANDLED_EXCEPTION
    );
    assert_eq!(info.exception_type, deepwyrm_abi::DW_EXCEPTION_PAGE_FAULT);
    assert_eq!(info.detail, 0x44);
    assert_eq!(info.fault_address, 0x5555);
    assert!(execution.stack_bounds(stack).is_ok());
    assert!(execution.load_context(context).is_ok());

    complete_deferred_current_reclaim(&mut registry, &execution, &waits, deferred, &mut cleanup);
    assert!(execution.stack_bounds(stack).is_err());
    assert!(execution.load_context(context).is_err());
    cleanup.push_optional(registry.release_handle(current_ref).unwrap());
    finish_task_cleanup(&mut registry, &mut tasks, cleanup);
}

#[test]
fn current_process_termination_defers_execution_bundle_until_reaper_completion() {
    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let waits = WaitRegistry::<2>::new();
    let mut terminal_waits = NoTerminalWaitCleanup;
    let mut cleanup = CleanupQueue::<16>::new();
    let process_pin = resolve_current_handle(
        &tasks,
        &mut registry,
        process,
        process_handle,
        deepwyrm_abi::DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_MODIFY,
    )
    .unwrap();
    let (current, current_ref) = tasks.create_thread(&mut registry, &process_pin).unwrap();
    release_lookup_pin(&mut registry, process_pin, &mut cleanup);
    execution
        .start_thread(&mut tasks, current, test_start(0x11))
        .unwrap();
    assert_eq!(execution.schedule_next().unwrap().current, Some(current));
    let (stack, context) = tasks.thread_execution_resources(current).unwrap().unwrap();

    let deferred = terminal_outcome(
        process_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            &waits,
            &mut terminal_waits,
            process,
            current,
            process_handle,
            deepwyrm_abi::DW_TERMINATION_AUTHORIZED,
            0x20,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS,
        SyscallControl::TerminateCurrent,
    )
    .unwrap();
    assert!(execution.stack_bounds(stack).is_ok());
    assert!(execution.load_context(context).is_ok());
    complete_deferred_current_reclaim(&mut registry, &execution, &waits, deferred, &mut cleanup);
    assert!(execution.stack_bounds(stack).is_err());
    assert!(execution.load_context(context).is_err());
    cleanup.push_optional(registry.release_handle(current_ref).unwrap());
    finish_task_cleanup(&mut registry, &mut tasks, cleanup);
}

#[test]
fn non_current_process_termination_reclaims_only_the_target_batch() {
    let mut registry = ObjectRegistry::<24>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (current_process, current_process_ref) =
        tasks.create_process(&mut registry, &root_owner).unwrap();
    let (_target_process, target_process_ref) =
        tasks.create_process(&mut registry, &root_owner).unwrap();
    let current_owner = registry
        .retain_internal_from_handle(&current_process_ref)
        .unwrap();
    let target_owner = registry
        .retain_internal_from_handle(&target_process_ref)
        .unwrap();
    let (current_thread, current_thread_ref) =
        tasks.create_thread(&mut registry, &current_owner).unwrap();
    let (target_thread, target_thread_ref) =
        tasks.create_thread(&mut registry, &target_owner).unwrap();
    assert!(registry.release_internal(current_owner).unwrap().is_none());
    assert!(registry.release_internal(target_owner).unwrap().is_none());
    let target_handle = tasks
        .process_handles_mut(current_process)
        .unwrap()
        .install(target_process_ref, DW_RIGHT_MODIFY)
        .unwrap();
    let execution = ExecutionDomain::<2>::new(test_stack_bounds::<2>()).unwrap();
    let waits = WaitRegistry::<2>::new();
    let mut terminal_waits = NoTerminalWaitCleanup;
    let mut cleanup = CleanupQueue::<24>::new();
    execution
        .start_thread(&mut tasks, current_thread, test_start(0x13))
        .unwrap();
    execution
        .start_thread(&mut tasks, target_thread, test_start(0x14))
        .unwrap();
    assert_eq!(
        execution.schedule_next().unwrap().current,
        Some(current_thread)
    );
    let (current_stack, current_context) = tasks
        .thread_execution_resources(current_thread)
        .unwrap()
        .unwrap();
    let (target_stack, target_context) = tasks
        .thread_execution_resources(target_thread)
        .unwrap()
        .unwrap();

    assert!(
        terminal_outcome(
            process_terminate(
                &mut registry,
                &mut tasks,
                &execution,
                &waits,
                &mut terminal_waits,
                current_process,
                current_thread,
                target_handle,
                deepwyrm_abi::DW_TERMINATION_AUTHORIZED,
                0x21,
                &mut cleanup,
            ),
            DW_STATUS_SUCCESS,
            SyscallControl::ReturnToCaller,
        )
        .is_none()
    );
    assert!(execution.stack_bounds(current_stack).is_ok());
    assert!(execution.load_context(current_context).is_ok());
    assert!(execution.stack_bounds(target_stack).is_err());
    assert!(execution.load_context(target_context).is_err());

    let deferred = terminal_outcome(
        process_exit(
            &mut registry,
            &mut tasks,
            &execution,
            &waits,
            &mut terminal_waits,
            current_process,
            current_thread,
            0,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS,
        SyscallControl::TerminateCurrent,
    )
    .unwrap();
    complete_deferred_current_reclaim(&mut registry, &execution, &waits, deferred, &mut cleanup);
    cleanup.push_optional(registry.release_handle(current_thread_ref).unwrap());
    cleanup.push_optional(registry.release_handle(target_thread_ref).unwrap());
    cleanup.push_optional(registry.release_handle(current_process_ref).unwrap());
    cleanup.push_optional(registry.release_internal(root_owner).unwrap());
    finish_task_cleanup(&mut registry, &mut tasks, cleanup);
}

#[test]
fn caller_containing_group_termination_defers_execution_bundle_until_reaper_completion() {
    let mut registry = ObjectRegistry::<16>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let root_handle_owner = registry.retain_internal(&root_owner).unwrap();
    let root_handle_ref = registry.internal_into_handle(root_handle_owner).unwrap();
    let (process, process_ref) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry.retain_internal_from_handle(&process_ref).unwrap();
    let (current, current_ref) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    let group_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(root_handle_ref, DW_RIGHT_MODIFY)
        .unwrap();
    let _process_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(process_ref, DW_RIGHT_MODIFY)
        .unwrap();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let waits = WaitRegistry::<2>::new();
    let mut terminal_waits = NoTerminalWaitCleanup;
    let mut cleanup = CleanupQueue::<16>::new();
    execution
        .start_thread(&mut tasks, current, test_start(0x12))
        .unwrap();
    assert_eq!(execution.schedule_next().unwrap().current, Some(current));
    let (stack, context) = tasks.thread_execution_resources(current).unwrap().unwrap();

    let deferred = terminal_outcome(
        task_group_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            &waits,
            &mut terminal_waits,
            process,
            current,
            group_handle,
            deepwyrm_abi::DW_TERMINATION_AUTHORIZED,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS,
        SyscallControl::TerminateCurrent,
    )
    .unwrap();
    assert!(execution.stack_bounds(stack).is_ok());
    assert!(execution.load_context(context).is_ok());
    complete_deferred_current_reclaim(&mut registry, &execution, &waits, deferred, &mut cleanup);
    assert!(execution.stack_bounds(stack).is_err());
    assert!(execution.load_context(context).is_err());
    cleanup.push_optional(registry.release_handle(current_ref).unwrap());
    cleanup.push_optional(registry.release_internal(root_owner).unwrap());
    finish_task_cleanup(&mut registry, &mut tasks, cleanup);
}

#[test]
fn mixed_group_termination_defers_only_the_caller_process_batch() {
    let mut registry = ObjectRegistry::<24>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let root_handle_owner = registry.retain_internal(&root_owner).unwrap();
    let root_handle_ref = registry.internal_into_handle(root_handle_owner).unwrap();
    let (current_process, current_process_ref) =
        tasks.create_process(&mut registry, &root_owner).unwrap();
    let (_remote_process, remote_process_ref) =
        tasks.create_process(&mut registry, &root_owner).unwrap();
    let current_owner = registry
        .retain_internal_from_handle(&current_process_ref)
        .unwrap();
    let remote_owner = registry
        .retain_internal_from_handle(&remote_process_ref)
        .unwrap();
    let (current_thread, current_thread_ref) =
        tasks.create_thread(&mut registry, &current_owner).unwrap();
    let (remote_thread, remote_thread_ref) =
        tasks.create_thread(&mut registry, &remote_owner).unwrap();
    assert!(registry.release_internal(current_owner).unwrap().is_none());
    assert!(registry.release_internal(remote_owner).unwrap().is_none());
    let group_handle = tasks
        .process_handles_mut(current_process)
        .unwrap()
        .install(root_handle_ref, DW_RIGHT_MODIFY)
        .unwrap();
    let execution = ExecutionDomain::<2>::new(test_stack_bounds::<2>()).unwrap();
    let waits = WaitRegistry::<2>::new();
    let mut terminal_waits = NoTerminalWaitCleanup;
    let mut cleanup = CleanupQueue::<24>::new();
    execution
        .start_thread(&mut tasks, current_thread, test_start(0x15))
        .unwrap();
    execution
        .start_thread(&mut tasks, remote_thread, test_start(0x16))
        .unwrap();
    assert_eq!(
        execution.schedule_next().unwrap().current,
        Some(current_thread)
    );
    let (current_stack, current_context) = tasks
        .thread_execution_resources(current_thread)
        .unwrap()
        .unwrap();
    let (remote_stack, remote_context) = tasks
        .thread_execution_resources(remote_thread)
        .unwrap()
        .unwrap();

    let deferred = terminal_outcome(
        task_group_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            &waits,
            &mut terminal_waits,
            current_process,
            current_thread,
            group_handle,
            deepwyrm_abi::DW_TERMINATION_AUTHORIZED,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS,
        SyscallControl::TerminateCurrent,
    )
    .unwrap();
    assert!(execution.stack_bounds(current_stack).is_ok());
    assert!(execution.load_context(current_context).is_ok());
    assert!(execution.stack_bounds(remote_stack).is_err());
    assert!(execution.load_context(remote_context).is_err());
    complete_deferred_current_reclaim(&mut registry, &execution, &waits, deferred, &mut cleanup);
    assert!(execution.stack_bounds(current_stack).is_err());
    assert!(execution.load_context(current_context).is_err());
    cleanup.push_optional(registry.release_handle(current_thread_ref).unwrap());
    cleanup.push_optional(registry.release_handle(remote_thread_ref).unwrap());
    cleanup.push_optional(registry.release_handle(current_process_ref).unwrap());
    cleanup.push_optional(registry.release_handle(remote_process_ref).unwrap());
    cleanup.push_optional(registry.release_internal(root_owner).unwrap());
    finish_task_cleanup(&mut registry, &mut tasks, cleanup);
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
    use deepwyrm_abi::{
        DW_OBJECT_TYPE_PROCESS, DW_OBJECT_TYPE_THREAD, DW_RIGHT_MODIFY, DW_RIGHT_WAIT,
        DW_SIGNAL_EXITED, DW_TERMINATION_AUTHORIZED,
    };

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let execution = ExecutionDomain::<2>::new(test_stack_bounds::<2>()).unwrap();
    let waits = WaitRegistry::<8>::new();
    let mut terminal_waits = NoTerminalWaitCleanup;
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
        .install(current_ref, DwRights(DW_RIGHT_MODIFY.0 | DW_RIGHT_WAIT.0))
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

    // Let the sibling block on the current Thread's EXITED level signal, then
    // return execution to current so its terminal transition must wake sibling.
    assert_eq!(
        execution.yield_current(current).unwrap().current,
        Some(sibling)
    );
    let target = tasks
        .process_handles(process)
        .unwrap()
        .lookup(
            &mut registry,
            current_handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_THREAD),
            DW_RIGHT_WAIT,
        )
        .unwrap();
    let (blocked, decision) = execution.block_current(sibling).unwrap();
    assert_eq!(decision.current, Some(current));
    let wake = blocked.into_wake_key();
    let blocked_owner =
        BlockedOperation::publish(execution.blocked_operations(), process, sibling, wake, ())
            .unwrap();
    let _registration = waits
        .register(target.into_internal(), DW_SIGNAL_EXITED, 0, sibling, wake)
        .unwrap();

    let (current_stack, current_context) =
        tasks.thread_execution_resources(current).unwrap().unwrap();
    let (sibling_stack, sibling_context) =
        tasks.thread_execution_resources(sibling).unwrap().unwrap();
    let deferred = terminal_outcome(
        thread_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            &waits,
            &mut terminal_waits,
            process,
            current,
            current_handle,
            DW_TERMINATION_AUTHORIZED,
            0x51,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS,
        SyscallControl::TerminateCurrent,
    );
    assert_eq!(execution.scheduler_state(current), None);
    assert!(execution.stack_bounds(current_stack).is_ok());
    assert!(execution.load_context(current_context).is_ok());
    assert_eq!(
        execution.scheduler_state(sibling),
        Some(SchedulerThreadState::Blocked)
    );
    complete_deferred_current_reclaim(
        &mut registry,
        &execution,
        &waits,
        deferred.unwrap(),
        &mut cleanup,
    );
    assert!(execution.stack_bounds(current_stack).is_err());
    assert!(execution.load_context(current_context).is_err());
    assert_eq!(
        execution.scheduler_state(sibling),
        Some(SchedulerThreadState::Runnable)
    );
    let winner = execution
        .blocked_operations()
        .winner(wake)
        .unwrap()
        .expect("EXITED transition claimed sibling wait");
    assert_eq!(
        winner,
        BlockedOperationWinner::Signal {
            item_index: 0,
            observed: DW_SIGNAL_EXITED,
        }
    );
    blocked_owner
        .complete_with(execution.blocked_operations(), winner, |()| ())
        .unwrap();
    assert_eq!(waits.len(), 0);
    assert_eq!(execution.schedule_next().unwrap().current, Some(sibling));
    assert_ne!(
        tasks.process_info(process).unwrap().state,
        deepwyrm_abi::DW_TASK_STATE_EXITED
    );

    let deferred = terminal_outcome(
        thread_terminate(
            &mut registry,
            &mut tasks,
            &execution,
            &waits,
            &mut terminal_waits,
            process,
            sibling,
            sibling_handle,
            DW_TERMINATION_AUTHORIZED,
            0x52,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS,
        SyscallControl::TerminateCurrent,
    );
    assert_eq!(execution.scheduler_state(sibling), None);
    assert!(execution.stack_bounds(sibling_stack).is_ok());
    assert!(execution.load_context(sibling_context).is_ok());
    complete_deferred_current_reclaim(
        &mut registry,
        &execution,
        &waits,
        deferred.unwrap(),
        &mut cleanup,
    );
    assert!(execution.stack_bounds(sibling_stack).is_err());
    assert!(execution.load_context(sibling_context).is_err());
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
    let (retired, deferred) = execution.retire_exit_pins_defer_current(pins, thread);
    let (process_pin, thread_pins) = retired.into_parts();
    for pin in thread_pins.into_iter().flatten().chain(process_pin) {
        cleanup.push_optional(registry.release_internal(pin).unwrap());
    }
    let deferred_pins = execution.reclaim_deferred_current(deferred);
    let (process_pin, thread_pins) = deferred_pins.into_parts();
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
    let waits = WaitRegistry::<8>::new();
    let mut terminal_waits = NoTerminalWaitCleanup;
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

    assert!(
        terminal_outcome(
            thread_terminate(
                &mut registry,
                &mut tasks,
                &execution,
                &waits,
                &mut terminal_waits,
                process,
                current,
                target_full,
                deepwyrm_abi::DwTerminationReason(u32::MAX),
                1,
                &mut cleanup,
            ),
            DW_STATUS_INVALID_ARGUMENT,
            SyscallControl::ReturnToCaller,
        )
        .is_none()
    );
    assert_eq!(
        tasks.thread_info(target).unwrap().state,
        deepwyrm_abi::DW_TASK_STATE_CREATED
    );
    assert!(
        terminal_outcome(
            thread_terminate(
                &mut registry,
                &mut tasks,
                &execution,
                &waits,
                &mut terminal_waits,
                process,
                current,
                process_handle,
                DW_TERMINATION_AUTHORIZED,
                2,
                &mut cleanup,
            ),
            DW_STATUS_WRONG_OBJECT_TYPE,
            SyscallControl::ReturnToCaller,
        )
        .is_none()
    );
    assert!(
        terminal_outcome(
            thread_terminate(
                &mut registry,
                &mut tasks,
                &execution,
                &waits,
                &mut terminal_waits,
                process,
                current,
                target_inspect,
                DW_TERMINATION_AUTHORIZED,
                3,
                &mut cleanup,
            ),
            DW_STATUS_ACCESS_DENIED,
            SyscallControl::ReturnToCaller,
        )
        .is_none()
    );
    assert_eq!(
        tasks.thread_info(target).unwrap().state,
        deepwyrm_abi::DW_TASK_STATE_CREATED
    );
    assert!(
        terminal_outcome(
            thread_terminate(
                &mut registry,
                &mut tasks,
                &execution,
                &waits,
                &mut terminal_waits,
                process,
                current,
                target_full,
                DW_TERMINATION_AUTHORIZED,
                0x44,
                &mut cleanup,
            ),
            DW_STATUS_SUCCESS,
            SyscallControl::ReturnToCaller,
        )
        .is_none()
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
    let (current_stack, current_context) =
        tasks.thread_execution_resources(current).unwrap().unwrap();
    let deferred = terminal_outcome(
        thread_exit(
            &mut registry,
            &mut tasks,
            &execution,
            &waits,
            process,
            current,
            0x55,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS,
        SyscallControl::TerminateCurrent,
    );
    assert_eq!(execution.scheduler_state(current), None);
    assert!(execution.stack_bounds(current_stack).is_ok());
    assert!(execution.load_context(current_context).is_ok());
    complete_deferred_current_reclaim(
        &mut registry,
        &execution,
        &waits,
        deferred.unwrap(),
        &mut cleanup,
    );
    assert!(execution.stack_bounds(current_stack).is_err());
    assert!(execution.load_context(current_context).is_err());
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
fn channel_cross_pair_cycle_is_rejected_and_all_authority_is_recyclable() {
    use deepwyrm_abi::{
        DW_HANDLE_TRANSFER_MOVE, DW_RIGHT_INSPECT, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WRITE,
    };

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let channels = ChannelAuthority::<2, 4>::new();
    let waits = WaitRegistry::<8>::new();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut user = FakeUserMemory::new();
    let mut cleanup = CleanupQueue::<16>::new();
    let rights =
        DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0);
    let [a0, a1] = create_channel_pair_for_test(
        &mut user,
        &mut registry,
        &channels,
        &mut tasks,
        process,
        rights,
        BASE + 0x180,
    );
    let [b0, b1] = create_channel_pair_for_test(
        &mut user,
        &mut registry,
        &channels,
        &mut tasks,
        process,
        rights,
        BASE + 0x1a0,
    );
    let mut staging = std::vec![0_u8; DW_CHANNEL_MAX_PAYLOAD as usize];

    write_handle_transfer(
        &mut user,
        BASE + 0x300,
        deepwyrm_abi::DwHandleTransferV1 {
            handle: b0,
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
            a1,
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
        tasks.process_handles(process).unwrap().inspect_basic(b0),
        Err(HandleTableError::InvalidHandle)
    );

    write_handle_transfer(
        &mut user,
        BASE + 0x300,
        deepwyrm_abi::DwHandleTransferV1 {
            handle: a0,
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
            b1,
            DwUserAddress(0),
            0,
            DwUserAddress(BASE + 0x300),
            1,
            0,
            &mut cleanup,
        ),
        DW_STATUS_INVALID_ARGUMENT
    );
    assert_eq!(
        tasks
            .process_handles(process)
            .unwrap()
            .inspect_basic(a0)
            .unwrap()
            .rights,
        rights
    );

    assert_eq!(
        handle_close(&mut registry, &mut tasks, process, a0, &mut cleanup),
        DW_STATUS_SUCCESS
    );
    complete_channel_cleanup_for_test(&mut registry, &channels, &waits, cleanup);
    for handle in [a1, b1] {
        let mut close_cleanup = CleanupQueue::<16>::new();
        assert_eq!(
            handle_close(
                &mut registry,
                &mut tasks,
                process,
                handle,
                &mut close_cleanup,
            ),
            DW_STATUS_SUCCESS
        );
        complete_channel_cleanup_for_test(&mut registry, &channels, &waits, close_cleanup);
    }
    assert_eq!(tasks.process_handle_count(process).unwrap(), 1);

    let recycled_a = create_channel_pair_for_test(
        &mut user,
        &mut registry,
        &channels,
        &mut tasks,
        process,
        rights,
        BASE + 0x1c0,
    );
    let recycled_b = create_channel_pair_for_test(
        &mut user,
        &mut registry,
        &channels,
        &mut tasks,
        process,
        rights,
        BASE + 0x1e0,
    );
    for handle in recycled_a.into_iter().chain(recycled_b) {
        close_channel_for_test(
            &mut registry,
            &mut tasks,
            process,
            &channels,
            &waits,
            handle,
        );
    }
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut CleanupQueue::new(),
        ),
        DW_STATUS_SUCCESS
    );
}

#[test]
fn channel_long_cycle_in_multi_handle_batch_rolls_back_every_source() {
    use deepwyrm_abi::{
        DW_HANDLE_TRANSFER_MOVE, DW_RIGHT_INSPECT, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT,
        DW_RIGHT_WRITE,
    };

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let channels = ChannelAuthority::<3, 4>::new();
    let waits = WaitRegistry::<8>::new();
    let events = EventAuthority::<1>::new();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut user = FakeUserMemory::new();
    let mut cleanup = CleanupQueue::<16>::new();
    let channel_rights =
        DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0);
    let [a0, a1] = create_channel_pair_for_test(
        &mut user,
        &mut registry,
        &channels,
        &mut tasks,
        process,
        channel_rights,
        BASE + 0x180,
    );
    let [b0, b1] = create_channel_pair_for_test(
        &mut user,
        &mut registry,
        &channels,
        &mut tasks,
        process,
        channel_rights,
        BASE + 0x1a0,
    );
    let [c0, c1] = create_channel_pair_for_test(
        &mut user,
        &mut registry,
        &channels,
        &mut tasks,
        process,
        channel_rights,
        BASE + 0x1c0,
    );
    let event_rights = DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0);
    let event = install_event_for_test(&mut registry, &mut tasks, process, &events, event_rights);
    let mut staging = std::vec![0_u8; DW_CHANNEL_MAX_PAYLOAD as usize];

    for (sender, transferred) in [(a1, b0), (b1, c0)] {
        write_handle_transfer(
            &mut user,
            BASE + 0x300,
            deepwyrm_abi::DwHandleTransferV1 {
                handle: transferred,
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
                sender,
                DwUserAddress(0),
                0,
                DwUserAddress(BASE + 0x300),
                1,
                0,
                &mut cleanup,
            ),
            DW_STATUS_SUCCESS
        );
    }

    for (index, (handle, requested_rights)) in [(event, DW_RIGHT_WAIT), (a0, DW_RIGHT_READ)]
        .into_iter()
        .enumerate()
    {
        write_handle_transfer(
            &mut user,
            BASE + 0x300 + (index as u64 * 40),
            deepwyrm_abi::DwHandleTransferV1 {
                handle,
                requested_rights,
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
            c1,
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
            .inspect_basic(event)
            .unwrap()
            .rights,
        event_rights
    );
    assert_eq!(
        tasks
            .process_handles(process)
            .unwrap()
            .inspect_basic(a0)
            .unwrap()
            .rights,
        channel_rights
    );

    close_event_for_test(&mut registry, &mut tasks, process, &events, event);
    for handle in [a0, a1, b1, c1] {
        let mut close_cleanup = CleanupQueue::<16>::new();
        assert_eq!(
            handle_close(
                &mut registry,
                &mut tasks,
                process,
                handle,
                &mut close_cleanup,
            ),
            DW_STATUS_SUCCESS
        );
        complete_channel_cleanup_for_test(&mut registry, &channels, &waits, close_cleanup);
    }
    assert_eq!(tasks.process_handle_count(process).unwrap(), 1);
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            process_handle,
            &mut CleanupQueue::new(),
        ),
        DW_STATUS_SUCCESS
    );
}

#[test]
fn channel_receive_denied_outputs_preserve_head_transfer_and_receiver_table() {
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
    let receiver_pin = tasks
        .process_handles(process)
        .unwrap()
        .lookup(
            &mut registry,
            endpoint1,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_CHANNEL),
            DW_RIGHT_READ,
        )
        .unwrap();
    let receiver_key = ChannelEndpointKey::from_object_id(receiver_pin.object_id());

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
            requested_rights: DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0),
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        },
    );
    let head_input = FakeUserMemory::offset(BASE + 0x380, 4);
    user.bytes[head_input..head_input + 4].copy_from_slice(b"head");
    let tail_input = FakeUserMemory::offset(BASE + 0x390, 4);
    user.bytes[tail_input..tail_input + 4].copy_from_slice(b"tail");
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
            4,
            DwUserAddress(BASE + 0x300),
            1,
            0,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
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
            DwUserAddress(BASE + 0x390),
            4,
            DwUserAddress(0),
            0,
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
    let receiver_handle_count = tasks.process_handle_count(process).unwrap();

    let out_bytes = BASE + 0x500;
    let out_handles = BASE + 0x580;
    let out_result = BASE + 0x680;
    let byte_output = FakeUserMemory::offset(out_bytes, 4);
    let handle_output =
        FakeUserMemory::offset(out_handles, DW_RECEIVED_HANDLE_INFO_V1_SIZE as usize);
    let result_output =
        FakeUserMemory::offset(out_result, DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize);
    for denied in [out_result, out_bytes, out_handles] {
        user.bytes[byte_output..byte_output + 4].fill(0xa5);
        user.bytes[handle_output..handle_output + DW_RECEIVED_HANDLE_INFO_V1_SIZE as usize]
            .fill(0xa5);
        user.bytes[result_output..result_output + DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize]
            .fill(0xa5);
        user.deny_write_at = Some(denied);
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
                DwUserAddress(out_bytes),
                4,
                DwUserAddress(out_handles),
                1,
                DwUserAddress(out_result),
                &mut cleanup,
            ),
            DW_STATUS_BAD_ADDRESS
        );
        user.deny_write_at = None;

        assert!(
            user.bytes[byte_output..byte_output + 4]
                .iter()
                .all(|byte| *byte == 0xa5)
        );
        assert!(
            user.bytes[handle_output..handle_output + DW_RECEIVED_HANDLE_INFO_V1_SIZE as usize]
                .iter()
                .all(|byte| *byte == 0xa5)
        );
        assert!(
            user.bytes[result_output..result_output + DW_CHANNEL_RECEIVE_RESULT_V1_SIZE as usize]
                .iter()
                .all(|byte| *byte == 0xa5)
        );
        assert_eq!(
            tasks.process_handle_count(process).unwrap(),
            receiver_handle_count
        );
        let head = channels.peek_receive(receiver_key).unwrap();
        assert_eq!(head.required_bytes, 4);
        assert_eq!(head.required_handles, 1);
    }

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
            DwUserAddress(out_bytes),
            4,
            DwUserAddress(out_handles),
            1,
            DwUserAddress(out_result),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(&user.bytes[byte_output..byte_output + 4], b"head");
    let received = DwHandle(u64_at(&user, out_handles));
    assert_eq!(
        tasks
            .process_handles(process)
            .unwrap()
            .inspect_basic(received)
            .unwrap()
            .rights,
        DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0)
    );
    assert_eq!(u32_at(&user, out_handles + 16), DW_OBJECT_TYPE_EVENT.0);
    assert_eq!(
        tasks.process_handle_count(process).unwrap(),
        receiver_handle_count + 1
    );
    assert_eq!(u32_at(&user, out_result + 8), 4);
    assert_eq!(u32_at(&user, out_result + 12), 1);

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
            DwUserAddress(out_bytes),
            4,
            DwUserAddress(0),
            0,
            DwUserAddress(out_result),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(&user.bytes[byte_output..byte_output + 4], b"tail");
    assert_eq!(u32_at(&user, out_result + 12), 0);

    close_event_for_test(&mut registry, &mut tasks, process, &events, received);
    assert!(
        registry
            .release_internal(receiver_pin.into_internal())
            .unwrap()
            .is_none()
    );
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

#[test]
fn deferred_signal_before_block_commit_is_completed_without_a_stale_wake_panic() {
    use deepwyrm_abi::{DW_OBJECT_TYPE_EVENT, DW_RIGHT_MODIFY, DW_RIGHT_SIGNAL, DW_RIGHT_WAIT};

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    let mut cleanup = CleanupQueue::<16>::new();
    let process_pin = resolve_current_handle(
        &tasks,
        &mut registry,
        process,
        process_handle,
        deepwyrm_abi::DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_MODIFY,
    )
    .unwrap();
    let (thread, thread_ref) = tasks.create_thread(&mut registry, &process_pin).unwrap();
    release_lookup_pin(&mut registry, process_pin, &mut cleanup);
    execution
        .start_thread(&mut tasks, thread, test_start(0x71))
        .unwrap();
    assert_eq!(execution.schedule_next().unwrap().current, Some(thread));

    let events = EventAuthority::<1>::new();
    let waits = WaitRegistry::<2>::new();
    let (event_key, event_ref) = events.create_event(&mut registry).unwrap();
    let event_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(event_ref, DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_SIGNAL.0))
        .unwrap();

    let block = execution.prepare_block_current(thread).unwrap();
    let wake = block.wake_key();
    let operation = crate::task::BlockedOperation::publish(
        execution.blocked_operations(),
        process,
        thread,
        wake,
        (),
    )
    .unwrap();
    let target = tasks
        .process_handles(process)
        .unwrap()
        .lookup(
            &mut registry,
            event_handle,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_EVENT),
            DW_RIGHT_WAIT,
        )
        .unwrap();
    assert!(matches!(
        events
            .register_wait(
                &waits,
                target,
                deepwyrm_abi::DW_SIGNAL_SIGNALED,
                0,
                thread,
                wake
            )
            .unwrap(),
        crate::wait::EventWaitOutcome::Registered(_)
    ));
    let wakes = events
        .signal(
            event_key,
            deepwyrm_abi::DwSignals(0),
            deepwyrm_abi::DW_SIGNAL_SIGNALED,
            &waits,
        )
        .unwrap();
    complete_wait_wakes(&mut registry, &execution, wakes, &mut cleanup);
    assert_eq!(waits.len(), 0);
    let winner = crate::task::BlockedOperationWinner::Signal {
        item_index: 0,
        observed: deepwyrm_abi::DW_SIGNAL_SIGNALED,
    };
    assert_eq!(
        execution.blocked_operations().winner(wake),
        Ok(Some(winner))
    );
    assert_eq!(
        execution
            .blocked_operations()
            .try_claim_winner(wake, crate::task::BlockedOperationWinner::Timeout),
        Ok(false)
    );
    assert_eq!(
        execution.scheduler_state(thread),
        Some(SchedulerThreadState::Running)
    );
    assert_eq!(
        operation.complete_with(execution.blocked_operations(), winner, |_| ()),
        Ok(())
    );
    execution.cancel_block(block).unwrap();

    let event_final = tasks
        .process_handles_mut(process)
        .unwrap()
        .close(&mut registry, event_handle)
        .unwrap()
        .unwrap();
    crate::wait::complete_event_finalization(
        &mut registry,
        events.take_finalization(event_final).unwrap(),
    );
    assert!(
        tasks
            .process_handles_mut(process)
            .unwrap()
            .close(&mut registry, process_handle)
            .unwrap()
            .is_none()
    );
    assert!(registry.release_handle(thread_ref).unwrap().is_none());
}

#[test]
#[should_panic(
    expected = "wait registration carried a foreign or unissued wake key: ForeignBlockToken"
)]
fn deferred_signal_routed_to_a_foreign_execution_domain_fails_stopped() {
    let mut registry = ObjectRegistry::<16>::new();
    let events = EventAuthority::<1>::new();
    let waits = WaitRegistry::<1>::new();
    let (event_key, event_ref) = events.create_event(&mut registry).unwrap();
    let wait_pin = registry.retain_internal_from_handle(&event_ref).unwrap();
    let thread_creation = registry
        .create(deepwyrm_abi::DW_OBJECT_TYPE_THREAD)
        .unwrap();
    let thread = ThreadKey::from_object_id(thread_creation.id());
    registry.cancel_creation(thread_creation).unwrap();

    let foreign_scheduler = crate::task::CooperativeScheduler::<1>::new();
    let reservation = foreign_scheduler.reserve(thread).unwrap();
    foreign_scheduler.commit(reservation).unwrap();
    foreign_scheduler.schedule_next().unwrap();
    let block = foreign_scheduler.prepare_block_current(thread).unwrap();
    let _registration = waits
        .register(
            wait_pin,
            deepwyrm_abi::DW_SIGNAL_SIGNALED,
            0,
            thread,
            block.wake_key(),
        )
        .unwrap();
    let wakes = events
        .signal(
            event_key,
            deepwyrm_abi::DwSignals(0),
            deepwyrm_abi::DW_SIGNAL_SIGNALED,
            &waits,
        )
        .unwrap();

    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    complete_wait_wakes(
        &mut registry,
        &execution,
        wakes,
        &mut CleanupQueue::<16>::new(),
    );
}

fn wait_running_fixture() -> (
    ObjectRegistry<16>,
    Tasks,
    ExecutionDomain<1>,
    ProcessKey,
    ThreadKey,
    DwHandle,
) {
    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let parent = tasks
        .process_handles(process)
        .unwrap()
        .lookup(
            &mut registry,
            process_handle,
            AcceptedObjectTypes::One(deepwyrm_abi::DW_OBJECT_TYPE_PROCESS),
            DW_RIGHT_MODIFY,
        )
        .unwrap();
    let (thread, thread_ref) = tasks
        .create_thread(&mut registry, &parent.into_internal())
        .unwrap();
    assert!(registry.release_handle(thread_ref).unwrap().is_none());
    let execution = ExecutionDomain::<1>::new(test_stack_bounds::<1>()).unwrap();
    execution
        .start_thread(&mut tasks, thread, test_start(0xd1))
        .unwrap();
    assert_eq!(execution.schedule_next().unwrap().current, Some(thread));
    (registry, tasks, execution, process, thread, process_handle)
}

fn write_wait_item(
    user: &mut FakeUserMemory,
    address: u64,
    index: usize,
    handle: DwHandle,
    signals: deepwyrm_abi::DwSignals,
) {
    let start =
        FakeUserMemory::offset(address, (index + 1) * WAIT_ITEM_BYTES) + index * WAIT_ITEM_BYTES;
    user.bytes[start..start + 8].copy_from_slice(&handle.0.to_le_bytes());
    user.bytes[start + 8..start + 16].copy_from_slice(&signals.0.to_le_bytes());
}

#[test]
#[allow(
    unsafe_code,
    reason = "the test gives the F7 suspend coordinator process-owned aligned stack carriers and inspects the fresh destination plan"
)]
fn wait_suspend_plan_switches_to_fresh_runnable_sibling() {
    extern crate std;
    #[repr(align(4096))]
    struct Region([u8; 0x12_000]);

    fn owned_bounds(region: &mut Region) -> crate::memory::kernel_stack::KernelStackBounds {
        let guard = region.0.as_mut_ptr() as u64;
        crate::memory::kernel_stack::KernelStackBounds::new(guard, guard + 0x1000, guard + 0x11_000)
            .unwrap()
    }

    let mut first_region = std::boxed::Box::new(Region([0; 0x12_000]));
    let mut second_region = std::boxed::Box::new(Region([0; 0x12_000]));
    let first_bounds = owned_bounds(&mut first_region);
    let second_bounds = owned_bounds(&mut second_region);

    let mut registry = ObjectRegistry::<16>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (_process, process_ref) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry.retain_internal_from_handle(&process_ref).unwrap();
    let (first, _first_ref) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    let (second, _second_ref) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());

    let execution = ExecutionDomain::<2>::new([first_bounds, second_bounds]).unwrap();
    execution
        .start_thread(&mut tasks, first, test_start(0xe1))
        .unwrap();
    execution
        .start_thread(&mut tasks, second, test_start(0xe2))
        .unwrap();
    assert_eq!(execution.schedule_next().unwrap().current, Some(first));
    let (_second_stack, second_context) =
        tasks.thread_execution_resources(second).unwrap().unwrap();
    assert_eq!(execution.kernel_continuation_rsp(second_context), Ok(0));

    let (blocked, decision) = execution.block_current(first).unwrap();
    let state = WaitSuspendState {
        wake: blocked.into_wake_key(),
        decision,
    };
    let trusted_entry = 0xffff_8000_0012_3000;
    let plan = match unsafe { prepare_wait_suspend_plan(&tasks, &execution, state, trusted_entry) }
        .unwrap()
    {
        crate::syscall::native::NativeSuspendPlan::Switch(plan) => plan,
        crate::syscall::native::NativeSuspendPlan::IdleCurrent => {
            panic!("fresh runnable sibling must be selected instead of idle")
        }
    };
    assert_eq!(plan.next_stack(), second_bounds);
    assert_eq!(plan.next_rsp() & 0xf, 8);
    assert_eq!(execution.kernel_continuation_rsp(second_context), Ok(0));
}

struct AdapterDeadline<const N: usize> {
    queue: crate::time::DeadlineQueue<N>,
}

impl<const N: usize> AdapterDeadline<N> {
    fn new() -> Self {
        Self {
            queue: crate::time::DeadlineQueue::new(),
        }
    }
}

struct AdapterTimerDeadline<const N: usize> {
    now_ns: u64,
    queue: crate::time::DeadlineQueue<N, crate::time::TimerExpiryToken>,
}

impl<const N: usize> AdapterTimerDeadline<N> {
    fn new(now_ns: u64) -> Self {
        Self {
            now_ns,
            queue: crate::time::DeadlineQueue::new(),
        }
    }

    fn expire_at(&mut self, now_ns: u64) -> [Option<crate::time::TimerExpiryToken>; N] {
        self.now_ns = now_ns;
        let mut expired = core::array::from_fn(|_| None);
        self.queue.expire(now_ns, &mut expired);
        expired
    }
}

impl<const N: usize> crate::time::TimerDeadlineAuthority for AdapterTimerDeadline<N> {
    fn replace_timer_deadline(
        &mut self,
        old: Option<&crate::time::DeadlineRegistration>,
        deadline_ns: u64,
        token: crate::time::TimerExpiryToken,
    ) -> Result<Option<crate::time::DeadlineRegistration>, crate::time::TimerDeadlineError> {
        if deadline_ns <= self.now_ns {
            if let Some(old) = old {
                self.queue
                    .cancel_if_live_ref(old)
                    .map_err(|_| crate::time::TimerDeadlineError::Fault)?;
            }
            return Ok(None);
        }
        if let Some(old) = old
            && let Some(registration) = self
                .queue
                .replace_if_live(old, deadline_ns, token)
                .map_err(|error| match error {
                    crate::time::DeadlineQueueError::Capacity => {
                        crate::time::TimerDeadlineError::Capacity
                    }
                    _ => crate::time::TimerDeadlineError::Fault,
                })?
        {
            return Ok(Some(registration));
        }
        self.queue
            .register(deadline_ns, token)
            .map(Some)
            .map_err(|error| match error {
                crate::time::DeadlineQueueError::Capacity => {
                    crate::time::TimerDeadlineError::Capacity
                }
                _ => crate::time::TimerDeadlineError::Fault,
            })
    }

    fn cancel_timer_deadline(
        &mut self,
        registration: &crate::time::DeadlineRegistration,
    ) -> Result<(), crate::time::TimerDeadlineError> {
        self.queue
            .cancel_if_live_ref(registration)
            .map(|_| ())
            .map_err(|_| crate::time::TimerDeadlineError::Fault)
    }
}

impl<const N: usize> crate::wait::engine::WaitDeadlineAuthority for AdapterDeadline<N> {
    fn register_wait_deadline(
        &mut self,
        deadline_ns: u64,
        wake: crate::task::BlockWakeKey,
    ) -> Result<crate::time::DeadlineRegistration, crate::wait::engine::WaitDeadlineError> {
        self.queue
            .register(deadline_ns, wake)
            .map_err(|error| match error {
                crate::time::DeadlineQueueError::Capacity => {
                    crate::wait::engine::WaitDeadlineError::Capacity
                }
                _ => crate::wait::engine::WaitDeadlineError::Fault,
            })
    }

    fn cancel_wait_deadline(
        &mut self,
        registration: crate::time::DeadlineRegistration,
    ) -> Result<(), crate::wait::engine::WaitDeadlineError> {
        self.queue
            .cancel_if_live(registration)
            .map(|_| ())
            .map_err(|_| crate::wait::engine::WaitDeadlineError::Fault)
    }
}

#[test]
#[allow(
    unsafe_code,
    reason = "the fixture retains the blocked Thread's physical idle continuation and fixed synthetic entry"
)]
fn signal_timeout_race_has_exactly_one_winner_in_both_orders() {
    use deepwyrm_abi::{DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED};

    fn run(timeout_first: bool) {
        let (mut registry, mut tasks, execution, process, thread, process_handle) =
            wait_running_fixture();
        let events = EventAuthority::<1>::new();
        let timers = TimerAuthority::<1>::new();
        let channels = ChannelAuthority::<1, 2>::new();
        let waits = WaitRegistry::<8>::new();
        let mut user = FakeUserMemory::new();
        let (event_key, reference) = events.create_event(&mut registry).unwrap();
        let event = tasks
            .process_handles_mut(process)
            .unwrap()
            .install(reference, DW_RIGHT_WAIT)
            .unwrap();
        let mut operations = WaitOperationRegistry::<FakeOwnedOutput, 1>::new();
        let mut deadlines = AdapterDeadline::<2>::new();
        let out = BASE + 0x980;
        let state = match wait_one_syscall(
            &mut user,
            &mut registry,
            &tasks,
            &events,
            &timers,
            &channels,
            &waits,
            &execution,
            &mut operations,
            Some(&mut deadlines),
            process,
            thread,
            event,
            DW_SIGNAL_SIGNALED,
            deepwyrm_abi::DwDeadline(50),
            DwUserAddress(out),
        ) {
            WaitSyscallAction::Suspended(state) => state,
            other => panic!("finite race wait did not suspend: {other:?}"),
        };
        assert_eq!(user.owned_outputs, 1);
        assert_eq!(waits.len(), 1);

        let mut expired = [None; 2];
        let mut cleanup = CleanupQueue::<16>::new();
        if timeout_first {
            assert_eq!(deadlines.queue.expire(50, &mut expired), 1);
            assert_eq!(expired[0], Some(state.wake_key()));
            assert!(
                crate::wait::engine::claim_timeout_and_wake(&execution, state.wake_key()).unwrap()
            );
            let wakes = events
                .signal(
                    event_key,
                    deepwyrm_abi::DwSignals(0),
                    DW_SIGNAL_SIGNALED,
                    &waits,
                )
                .unwrap();
            complete_wait_wakes(&mut registry, &execution, wakes, &mut cleanup);
        } else {
            let wakes = events
                .signal(
                    event_key,
                    deepwyrm_abi::DwSignals(0),
                    DW_SIGNAL_SIGNALED,
                    &waits,
                )
                .unwrap();
            complete_wait_wakes(&mut registry, &execution, wakes, &mut cleanup);
            assert_eq!(deadlines.queue.expire(50, &mut expired), 1);
            assert_eq!(expired[0], Some(state.wake_key()));
            assert!(
                !crate::wait::engine::claim_timeout_and_wake(&execution, state.wake_key()).unwrap()
            );
        }

        assert_eq!(waits.len(), 0);
        assert_eq!(
            execution.scheduler_state(thread),
            Some(SchedulerThreadState::Runnable)
        );
        assert!(matches!(
            unsafe { poll_wait_idle_suspend(&tasks, &execution, state, 0xffff_8000_0012_3000) }
                .unwrap(),
            crate::syscall::native::NativeIdleSuspendPoll::ResumeCurrent
        ));
        let status = resume_wait_thread_syscall(
            &mut user,
            &mut registry,
            &waits,
            &execution,
            &mut operations,
            Some(&mut deadlines),
            thread,
            &mut cleanup,
        )
        .unwrap();
        assert_eq!(user.owned_outputs, 0);
        assert!(!operations.contains_thread(thread));
        if timeout_first {
            assert_eq!(status, DW_STATUS_TIMED_OUT);
            assert_eq!(u32_at(&user, out), 0);
        } else {
            assert_eq!(status, DW_STATUS_SUCCESS);
            assert_eq!(u32_at(&user, out + 8), 0);
            assert_eq!(u64_at(&user, out + 16), DW_SIGNAL_SIGNALED.0);
        }

        close_event_for_test(&mut registry, &mut tasks, process, &events, event);
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

    run(false);
    run(true);
}

#[test]
#[allow(
    unsafe_code,
    reason = "the fixture retains the blocked Thread's physical idle continuation and fixed synthetic entry"
)]
fn deferred_signal_after_timeout_resume_releases_stale_registration_pins() {
    use deepwyrm_abi::{DW_RIGHT_SIGNAL, DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED};

    let (mut registry, mut tasks, execution, process, thread, process_handle) =
        wait_running_fixture();
    let events = EventAuthority::<1>::new();
    let timers = TimerAuthority::<1>::new();
    let channels = ChannelAuthority::<1, 2>::new();
    let waits = WaitRegistry::<8>::new();
    let mut user = FakeUserMemory::new();
    let (event_key, reference) = events.create_event(&mut registry).unwrap();
    let event = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(reference, DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_SIGNAL.0))
        .unwrap();
    let mut operations = WaitOperationRegistry::<FakeOwnedOutput, 1>::new();
    let mut deadlines = AdapterDeadline::<2>::new();
    let out = BASE + 0x980;
    let state = match wait_one_syscall(
        &mut user,
        &mut registry,
        &tasks,
        &events,
        &timers,
        &channels,
        &waits,
        &execution,
        &mut operations,
        Some(&mut deadlines),
        process,
        thread,
        event,
        DW_SIGNAL_SIGNALED,
        deepwyrm_abi::DwDeadline(50),
        DwUserAddress(out),
    ) {
        WaitSyscallAction::Suspended(state) => state,
        other => panic!("finite stale-ledger wait did not suspend: {other:?}"),
    };

    let delayed_wakes = events
        .signal(
            event_key,
            deepwyrm_abi::DwSignals(0),
            DW_SIGNAL_SIGNALED,
            &waits,
        )
        .unwrap();
    assert_eq!(waits.len(), 0);

    let mut expired = [None; 2];
    assert_eq!(deadlines.queue.expire(50, &mut expired), 1);
    assert_eq!(expired[0], Some(state.wake_key()));
    assert!(crate::wait::engine::claim_timeout_and_wake(&execution, state.wake_key()).unwrap());
    assert!(matches!(
        unsafe { poll_wait_idle_suspend(&tasks, &execution, state, 0xffff_8000_0012_3000) }
            .unwrap(),
        crate::syscall::native::NativeIdleSuspendPoll::ResumeCurrent
    ));

    let mut cleanup = CleanupQueue::<16>::new();
    assert_eq!(
        resume_wait_thread_syscall(
            &mut user,
            &mut registry,
            &waits,
            &execution,
            &mut operations,
            Some(&mut deadlines),
            thread,
            &mut cleanup,
        )
        .unwrap(),
        DW_STATUS_TIMED_OUT
    );
    assert_eq!(
        execution.blocked_operations().winner(state.wake_key()),
        Err(crate::task::BlockedOperationError::StaleReservation)
    );

    complete_wait_wakes(&mut registry, &execution, delayed_wakes, &mut cleanup);
    close_event_for_test(&mut registry, &mut tasks, process, &events, event);
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
#[allow(
    unsafe_code,
    reason = "the fixture retains the blocked Thread's physical idle continuation and fixed synthetic entry"
)]
fn public_finite_wait_idles_then_timeout_resumes_in_place_and_discards_output() {
    use deepwyrm_abi::{DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED};

    let (mut registry, mut tasks, execution, process, thread, process_handle) =
        wait_running_fixture();
    let events = EventAuthority::<1>::new();
    let timers = TimerAuthority::<1>::new();
    let channels = ChannelAuthority::<1, 2>::new();
    let waits = WaitRegistry::<8>::new();
    let mut user = FakeUserMemory::new();
    let (_event_key, reference) = events.create_event(&mut registry).unwrap();
    let event = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(reference, DW_RIGHT_WAIT)
        .unwrap();
    let mut operations = WaitOperationRegistry::<FakeOwnedOutput, 1>::new();
    let mut deadlines = AdapterDeadline::<2>::new();
    let out = BASE + 0x980;

    let suspended = match wait_one_syscall(
        &mut user,
        &mut registry,
        &tasks,
        &events,
        &timers,
        &channels,
        &waits,
        &execution,
        &mut operations,
        Some(&mut deadlines),
        process,
        thread,
        event,
        DW_SIGNAL_SIGNALED,
        DwDeadline(50),
        DwUserAddress(out),
    ) {
        WaitSyscallAction::Suspended(state) => state,
        other => panic!("finite public wait did not suspend: {other:?}"),
    };
    assert_eq!(user.owned_outputs, 1);
    assert_eq!(
        execution.scheduler_state(thread),
        Some(SchedulerThreadState::Blocked)
    );
    assert!(matches!(
        unsafe { prepare_wait_suspend_plan(&tasks, &execution, suspended, 0xffff_8000_0012_3000) },
        Ok(crate::syscall::native::NativeSuspendPlan::IdleCurrent)
    ));

    let mut expired = [None; 2];
    assert_eq!(deadlines.queue.expire(50, &mut expired), 1);
    assert_eq!(expired[0], Some(suspended.wake_key()));
    assert!(crate::wait::engine::claim_timeout_and_wake(&execution, suspended.wake_key()).unwrap());
    assert!(matches!(
        unsafe { poll_wait_idle_suspend(&tasks, &execution, suspended, 0xffff_8000_0012_3000) }
            .unwrap(),
        crate::syscall::native::NativeIdleSuspendPoll::ResumeCurrent
    ));
    assert_eq!(
        execution.scheduler_state(thread),
        Some(SchedulerThreadState::Running)
    );

    let mut cleanup = CleanupQueue::<16>::new();
    assert_eq!(
        resume_wait_syscall(
            &mut user,
            &mut registry,
            &waits,
            &execution,
            &mut operations,
            Some(&mut deadlines),
            suspended.wake_key(),
            &mut cleanup,
        )
        .unwrap(),
        DW_STATUS_TIMED_OUT
    );
    assert_eq!(user.owned_outputs, 0);
    assert_eq!(
        &user.bytes[0x980..0x980 + DW_WAIT_RESULT_V1_SIZE as usize],
        &[0; DW_WAIT_RESULT_V1_SIZE as usize]
    );
    assert!(!operations.contains_thread(thread));
    close_event_for_test(&mut registry, &mut tasks, process, &events, event);
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

struct NativeWaitHarness<'a> {
    user: &'a mut FakeUserMemory,
    registry: &'a mut ObjectRegistry<16>,
    tasks: &'a Tasks,
    events: &'a EventAuthority<1>,
    timers: &'a TimerAuthority<1>,
    channels: &'a ChannelAuthority<1, 2>,
    waits: &'a WaitRegistry<8>,
    execution: &'a ExecutionDomain<1>,
    operations: &'a mut WaitOperationRegistry<FakeOwnedOutput, 1>,
    process: ProcessKey,
    thread: ThreadKey,
    control: NativeWaitControl,
}

impl crate::syscall::native::NativeSyscallHandler for NativeWaitHarness<'_> {
    fn handle(
        &mut self,
        request: crate::syscall::native::NativeSyscallRequest,
    ) -> crate::syscall::native::NativeSyscallResult {
        let action = match request {
            crate::syscall::native::NativeSyscallRequest::WaitOne {
                handle,
                signals,
                deadline,
                out_result,
            } => wait_one_syscall(
                self.user,
                self.registry,
                self.tasks,
                self.events,
                self.timers,
                self.channels,
                self.waits,
                self.execution,
                self.operations,
                None,
                self.process,
                self.thread,
                handle,
                signals,
                deadline,
                out_result,
            ),
            crate::syscall::native::NativeSyscallRequest::WaitMany {
                items,
                item_count,
                mode,
                deadline,
                out_result,
            } => wait_many_syscall(
                self.user,
                self.registry,
                self.tasks,
                self.events,
                self.timers,
                self.channels,
                self.waits,
                self.execution,
                self.operations,
                None,
                self.process,
                self.thread,
                items,
                item_count,
                mode,
                deadline,
                out_result,
            ),
            _ => panic!("native F7 harness received a non-wait request"),
        };
        self.control.accept(action)
    }
}

#[test]
#[allow(
    unsafe_code,
    reason = "the fixture retains the blocked Thread's physical idle continuation and fixed synthetic entry"
)]
fn native_wait_ids_route_through_real_wait_transactions_and_resume_control() {
    use deepwyrm_abi::{
        DW_DEADLINE_INFINITE, DW_DEADLINE_NOW, DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED, DW_WAIT_MODE_ANY,
        DwKnownSyscall,
    };

    let (mut registry, mut tasks, execution, process, thread, process_handle) =
        wait_running_fixture();
    let events = EventAuthority::<1>::new();
    let timers = TimerAuthority::<1>::new();
    let channels = ChannelAuthority::<1, 2>::new();
    let waits = WaitRegistry::<8>::new();
    let mut user = FakeUserMemory::new();
    let (event_key, reference) = events.create_event(&mut registry).unwrap();
    let event = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(reference, DW_RIGHT_WAIT)
        .unwrap();
    let mut operations = WaitOperationRegistry::<FakeOwnedOutput, 1>::new();
    let out_one = BASE + 0x900;

    let mut control = {
        let mut harness = NativeWaitHarness {
            user: &mut user,
            registry: &mut registry,
            tasks: &tasks,
            events: &events,
            timers: &timers,
            channels: &channels,
            waits: &waits,
            execution: &execution,
            operations: &mut operations,
            process,
            thread,
            control: NativeWaitControl::new(),
        };
        let begin = crate::syscall::native::dispatch_native(
            &mut harness,
            DwKnownSyscall::WaitOne.id(),
            crate::syscall::RawSyscallArguments::new([
                event.0,
                DW_SIGNAL_SIGNALED.0,
                DW_DEADLINE_INFINITE.0,
                out_one,
                0,
                0,
            ]),
        );
        assert_eq!(begin.status, DW_STATUS_SUCCESS);
        assert_eq!(begin.control, SyscallControl::SuspendCurrent);
        core::mem::replace(&mut harness.control, NativeWaitControl::new())
    };
    assert!(matches!(
        unsafe { control.prepare_suspend(&tasks, &execution, 0xffff_8000_0012_3000) }.unwrap(),
        crate::syscall::native::NativeSuspendPlan::IdleCurrent
    ));

    let wakes = events
        .signal(
            event_key,
            deepwyrm_abi::DwSignals(0),
            DW_SIGNAL_SIGNALED,
            &waits,
        )
        .unwrap();
    let mut cleanup = CleanupQueue::<16>::new();
    complete_wait_wakes(&mut registry, &execution, wakes, &mut cleanup);
    assert!(matches!(
        unsafe { control.poll_idle(&tasks, &execution, 0xffff_8000_0012_3000) }.unwrap(),
        crate::syscall::native::NativeIdleSuspendPoll::ResumeCurrent
    ));
    assert!(control.is_clear());
    assert_eq!(
        resume_wait_thread_syscall(
            &mut user,
            &mut registry,
            &waits,
            &execution,
            &mut operations,
            None,
            thread,
            &mut cleanup,
        )
        .unwrap(),
        DW_STATUS_SUCCESS
    );
    assert_eq!(u32_at(&user, out_one + 8), 0);
    assert_eq!(u64_at(&user, out_one + 16), DW_SIGNAL_SIGNALED.0);

    let items = BASE + 0xa00;
    let out_many = BASE + 0xb00;
    write_wait_item(&mut user, items, 0, event, DW_SIGNAL_SIGNALED);
    let immediate = {
        let mut harness = NativeWaitHarness {
            user: &mut user,
            registry: &mut registry,
            tasks: &tasks,
            events: &events,
            timers: &timers,
            channels: &channels,
            waits: &waits,
            execution: &execution,
            operations: &mut operations,
            process,
            thread,
            control,
        };
        let immediate = crate::syscall::native::dispatch_native(
            &mut harness,
            DwKnownSyscall::WaitMany.id(),
            crate::syscall::RawSyscallArguments::new([
                items,
                1,
                u64::from(DW_WAIT_MODE_ANY),
                DW_DEADLINE_NOW.0,
                out_many,
                0,
            ]),
        );
        assert!(harness.control.is_clear());
        immediate
    };
    assert_eq!(immediate.status, DW_STATUS_SUCCESS);
    assert_eq!(immediate.control, SyscallControl::ReturnToCaller);
    assert_eq!(u32_at(&user, out_many + 8), 0);
    assert_eq!(u64_at(&user, out_many + 16), DW_SIGNAL_SIGNALED.0);

    close_event_for_test(&mut registry, &mut tasks, process, &events, event);
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
fn public_wait_one_preflights_owned_output_before_handle_resolution_and_commits_ready() {
    use deepwyrm_abi::{DW_DEADLINE_NOW, DW_RIGHT_SIGNAL, DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED};

    let (mut registry, mut tasks, execution, process, thread, process_handle) =
        wait_running_fixture();
    let events = EventAuthority::<1>::new();
    let timers = TimerAuthority::<1>::new();
    let channels = ChannelAuthority::<1, 2>::new();
    let waits = WaitRegistry::<8>::new();
    let mut user = FakeUserMemory::new();
    let (event_key, reference) = events.create_event(&mut registry).unwrap();
    let event = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(reference, DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_SIGNAL.0))
        .unwrap();
    let mut operations = WaitOperationRegistry::<FakeOwnedOutput, 1>::new();
    let out = BASE + 0x900;

    user.deny_write = true;
    assert_eq!(
        wait_one_syscall(
            &mut user,
            &mut registry,
            &tasks,
            &events,
            &timers,
            &channels,
            &waits,
            &execution,
            &mut operations,
            None,
            process,
            thread,
            DwHandle(u64::MAX),
            deepwyrm_abi::DwSignals(0),
            DW_DEADLINE_NOW,
            DwUserAddress(out),
        ),
        WaitSyscallAction::Returning(DW_STATUS_INVALID_ARGUMENT)
    );
    assert_eq!(
        wait_one_syscall(
            &mut user,
            &mut registry,
            &tasks,
            &events,
            &timers,
            &channels,
            &waits,
            &execution,
            &mut operations,
            None,
            process,
            thread,
            DwHandle(u64::MAX),
            DW_SIGNAL_SIGNALED,
            DW_DEADLINE_NOW,
            DwUserAddress(out),
        ),
        WaitSyscallAction::Returning(DW_STATUS_BAD_ADDRESS)
    );
    assert_eq!(user.owned_outputs, 0);

    user.deny_write = false;
    assert_eq!(
        events
            .signal(
                event_key,
                deepwyrm_abi::DwSignals(0),
                DW_SIGNAL_SIGNALED,
                &waits,
            )
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        wait_one_syscall(
            &mut user,
            &mut registry,
            &tasks,
            &events,
            &timers,
            &channels,
            &waits,
            &execution,
            &mut operations,
            None,
            process,
            thread,
            event,
            DW_SIGNAL_SIGNALED,
            DW_DEADLINE_NOW,
            DwUserAddress(out),
        ),
        WaitSyscallAction::Returning(DW_STATUS_SUCCESS)
    );
    assert_eq!(user.owned_outputs, 0);
    assert_eq!(u32_at(&user, out), DW_WAIT_RESULT_V1_SIZE);
    assert_eq!(u32_at(&user, out + 8), 0);
    assert_eq!(u64_at(&user, out + 16), DW_SIGNAL_SIGNALED.0);
    close_event_for_test(&mut registry, &mut tasks, process, &events, event);
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
}

#[test]
fn public_timer_wait_handles_level_ready_and_irq_expiry_resume() {
    use deepwyrm_abi::{
        DW_DEADLINE_INFINITE, DW_DEADLINE_NOW, DW_RIGHT_MODIFY, DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED,
        DwRights,
    };

    let (mut registry, mut tasks, execution, process, thread, process_handle) =
        wait_running_fixture();
    let events = EventAuthority::<1>::new();
    let timers = TimerAuthority::<1>::new();
    let channels = ChannelAuthority::<1, 2>::new();
    let waits = WaitRegistry::<8>::new();
    let mut user = FakeUserMemory::new();
    let mut deadlines = AdapterTimerDeadline::<2>::new(10);
    let (timer_key, reference) = timers.create_timer(&mut registry).unwrap();
    let timer = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(reference, DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0))
        .unwrap();
    let mut operations = WaitOperationRegistry::<FakeOwnedOutput, 1>::new();

    let immediate = timers
        .set(
            timer_key,
            deepwyrm_abi::DwDeadline(10),
            &mut deadlines,
            &waits,
        )
        .unwrap();
    assert_eq!(immediate.len(), 0);
    let (wakes, pins) = immediate.into_parts();
    assert!(wakes.into_iter().flatten().next().is_none());
    assert!(pins.into_iter().flatten().next().is_none());

    let ready_out = BASE + 0xc00;
    assert_eq!(
        wait_one_syscall(
            &mut user,
            &mut registry,
            &tasks,
            &events,
            &timers,
            &channels,
            &waits,
            &execution,
            &mut operations,
            None,
            process,
            thread,
            timer,
            DW_SIGNAL_SIGNALED,
            DW_DEADLINE_NOW,
            DwUserAddress(ready_out),
        ),
        WaitSyscallAction::Returning(DW_STATUS_SUCCESS)
    );
    assert_eq!(u64_at(&user, ready_out + 16), DW_SIGNAL_SIGNALED.0);

    let reset = timers
        .set(
            timer_key,
            deepwyrm_abi::DwDeadline(50),
            &mut deadlines,
            &waits,
        )
        .unwrap();
    assert_eq!(reset.len(), 0);
    let (wakes, pins) = reset.into_parts();
    assert!(wakes.into_iter().flatten().next().is_none());
    assert!(pins.into_iter().flatten().next().is_none());

    let blocked_out = BASE + 0xc80;
    let suspended = match wait_one_syscall(
        &mut user,
        &mut registry,
        &tasks,
        &events,
        &timers,
        &channels,
        &waits,
        &execution,
        &mut operations,
        None,
        process,
        thread,
        timer,
        DW_SIGNAL_SIGNALED,
        DW_DEADLINE_INFINITE,
        DwUserAddress(blocked_out),
    ) {
        WaitSyscallAction::Suspended(state) => state,
        other => panic!("armed Timer wait did not suspend: {other:?}"),
    };
    assert_eq!(user.owned_outputs, 1);
    assert_eq!(waits.len(), 1);

    let mut expired = deadlines.expire_at(50).into_iter().flatten();
    let token = expired.next().expect("future Timer arm expires once");
    assert!(expired.next().is_none());
    let wakes = timers.expire(token, &waits).unwrap();
    assert_eq!(wakes.len(), 1);
    assert_eq!(wakes.pin_len(), 0);
    let mut cleanup = CleanupQueue::<16>::new();
    crate::wait::complete_irq_signal_wakes(&execution, wakes);
    assert_eq!(
        resume_wait_syscall(
            &mut user,
            &mut registry,
            &waits,
            &execution,
            &mut operations,
            None,
            suspended.wake_key(),
            &mut cleanup,
        )
        .unwrap(),
        DW_STATUS_SUCCESS
    );
    assert_eq!(user.owned_outputs, 0);
    assert_eq!(waits.len(), 0);
    assert_eq!(u64_at(&user, blocked_out + 16), DW_SIGNAL_SIGNALED.0);

    let final_release = tasks
        .process_handles_mut(process)
        .unwrap()
        .close(&mut registry, timer)
        .unwrap()
        .expect("Timer handle is final after wait cleanup");
    let finalization = timers
        .take_finalization(final_release, &mut deadlines)
        .unwrap();
    crate::time::complete_timer_finalization(&mut registry, finalization);
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
fn public_wait_one_suspend_keeps_owned_output_until_exact_resume() {
    use deepwyrm_abi::{DW_DEADLINE_INFINITE, DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED};

    let (mut registry, mut tasks, execution, process, thread, process_handle) =
        wait_running_fixture();
    let events = EventAuthority::<1>::new();
    let timers = TimerAuthority::<1>::new();
    let channels = ChannelAuthority::<1, 2>::new();
    let waits = WaitRegistry::<8>::new();
    let mut user = FakeUserMemory::new();
    let (event_key, reference) = events.create_event(&mut registry).unwrap();
    let event = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(reference, DW_RIGHT_WAIT)
        .unwrap();
    let mut operations = WaitOperationRegistry::<FakeOwnedOutput, 1>::new();
    let out = BASE + 0x980;

    let suspended = match wait_one_syscall(
        &mut user,
        &mut registry,
        &tasks,
        &events,
        &timers,
        &channels,
        &waits,
        &execution,
        &mut operations,
        None,
        process,
        thread,
        event,
        DW_SIGNAL_SIGNALED,
        DW_DEADLINE_INFINITE,
        DwUserAddress(out),
    ) {
        WaitSyscallAction::Suspended(state) => state,
        other => panic!("unsignaled public wait did not suspend: {other:?}"),
    };
    assert_eq!(user.owned_outputs, 1);
    assert!(operations.contains_thread(thread));
    assert_eq!(
        execution.scheduler_state(thread),
        Some(SchedulerThreadState::Blocked)
    );

    let wakes = events
        .signal(
            event_key,
            deepwyrm_abi::DwSignals(0),
            DW_SIGNAL_SIGNALED,
            &waits,
        )
        .unwrap();
    let mut cleanup = CleanupQueue::<16>::new();
    complete_wait_wakes(&mut registry, &execution, wakes, &mut cleanup);
    assert_eq!(
        resume_wait_syscall(
            &mut user,
            &mut registry,
            &waits,
            &execution,
            &mut operations,
            None,
            suspended.wake_key(),
            &mut cleanup,
        )
        .unwrap(),
        DW_STATUS_SUCCESS
    );
    assert_eq!(user.owned_outputs, 0);
    assert!(!operations.contains_thread(thread));
    assert_eq!(u32_at(&user, out + 8), 0);
    assert_eq!(u64_at(&user, out + 16), DW_SIGNAL_SIGNALED.0);
    close_event_for_test(&mut registry, &mut tasks, process, &events, event);
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
fn public_wait_one_observes_channel_writable_and_peer_closed() {
    use deepwyrm_abi::{DW_DEADLINE_NOW, DW_RIGHT_WAIT, DW_SIGNAL_PEER_CLOSED, DW_SIGNAL_WRITABLE};

    let (mut registry, mut tasks, execution, process, thread, process_handle) =
        wait_running_fixture();
    let events = EventAuthority::<1>::new();
    let timers = TimerAuthority::<1>::new();
    let channels = ChannelAuthority::<2, 4>::new();
    let waits = WaitRegistry::<8>::new();
    let mut user = FakeUserMemory::new();
    let (_keys, [first_ref, second_ref]) = channels.create_pair(&mut registry).unwrap();
    let first = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(first_ref, DW_RIGHT_WAIT)
        .unwrap();
    let second = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(second_ref, DW_RIGHT_WAIT)
        .unwrap();
    let mut operations = WaitOperationRegistry::<FakeOwnedOutput, 1>::new();
    let out = BASE + 0x900;

    assert_eq!(
        wait_one_syscall(
            &mut user,
            &mut registry,
            &tasks,
            &events,
            &timers,
            &channels,
            &waits,
            &execution,
            &mut operations,
            None,
            process,
            thread,
            first,
            DW_SIGNAL_WRITABLE,
            DW_DEADLINE_NOW,
            DwUserAddress(out),
        ),
        WaitSyscallAction::Returning(DW_STATUS_SUCCESS)
    );
    assert_ne!(u64_at(&user, out + 16) & DW_SIGNAL_WRITABLE.0, 0);

    close_channel_for_test(
        &mut registry,
        &mut tasks,
        process,
        &channels,
        &waits,
        second,
    );
    assert_eq!(
        wait_one_syscall(
            &mut user,
            &mut registry,
            &tasks,
            &events,
            &timers,
            &channels,
            &waits,
            &execution,
            &mut operations,
            None,
            process,
            thread,
            first,
            DW_SIGNAL_PEER_CLOSED,
            DW_DEADLINE_NOW,
            DwUserAddress(out),
        ),
        WaitSyscallAction::Returning(DW_STATUS_SUCCESS)
    );
    assert_ne!(u64_at(&user, out + 16) & DW_SIGNAL_PEER_CLOSED.0, 0);
    assert_eq!(user.owned_outputs, 0);

    close_channel_for_test(&mut registry, &mut tasks, process, &channels, &waits, first);
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
}

#[test]
#[allow(
    unsafe_code,
    reason = "the fixture retains the blocked Thread's physical idle continuation and fixed synthetic entry"
)]
fn repeated_duplicate_wait_many_signal_trace_selects_index_zero_once() {
    use deepwyrm_abi::{DW_DEADLINE_INFINITE, DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED, DW_WAIT_MODE_ANY};

    let (mut registry, mut tasks, execution, process, thread, process_handle) =
        wait_running_fixture();
    let events = EventAuthority::<1>::new();
    let timers = TimerAuthority::<1>::new();
    let channels = ChannelAuthority::<1, 2>::new();
    let waits = WaitRegistry::<8>::new();
    let mut user = FakeUserMemory::new();
    let (event_key, reference) = events.create_event(&mut registry).unwrap();
    let event = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(reference, DW_RIGHT_WAIT)
        .unwrap();
    let items = BASE + 0x700;
    let out = BASE + 0x900;
    write_wait_item(&mut user, items, 0, event, DW_SIGNAL_SIGNALED);
    write_wait_item(&mut user, items, 1, event, DW_SIGNAL_SIGNALED);
    let mut operations = WaitOperationRegistry::<FakeOwnedOutput, 1>::new();
    let mut cleanup = CleanupQueue::<16>::new();

    for _ in 0..64 {
        let suspended = match wait_many_syscall(
            &mut user,
            &mut registry,
            &tasks,
            &events,
            &timers,
            &channels,
            &waits,
            &execution,
            &mut operations,
            None,
            process,
            thread,
            DwUserAddress(items),
            2,
            DW_WAIT_MODE_ANY,
            DW_DEADLINE_INFINITE,
            DwUserAddress(out),
        ) {
            WaitSyscallAction::Suspended(state) => state,
            other => panic!("duplicate wait_many did not suspend: {other:?}"),
        };
        assert_eq!(user.owned_outputs, 1);
        assert_eq!(waits.len(), 2);

        let wakes = events
            .signal(
                event_key,
                deepwyrm_abi::DwSignals(0),
                DW_SIGNAL_SIGNALED,
                &waits,
            )
            .unwrap();
        assert_eq!(wakes.len(), 1);
        assert_eq!(wakes.pin_len(), 2);
        complete_wait_wakes(&mut registry, &execution, wakes, &mut cleanup);
        assert!(matches!(
            unsafe { poll_wait_idle_suspend(&tasks, &execution, suspended, 0xffff_8000_0012_3000) }
                .unwrap(),
            crate::syscall::native::NativeIdleSuspendPoll::ResumeCurrent
        ));
        assert_eq!(
            resume_wait_syscall(
                &mut user,
                &mut registry,
                &waits,
                &execution,
                &mut operations,
                None,
                suspended.wake_key(),
                &mut cleanup,
            )
            .unwrap(),
            DW_STATUS_SUCCESS
        );
        assert_eq!(u32_at(&user, out + 8), 0);
        assert_eq!(user.owned_outputs, 0);
        assert_eq!(waits.len(), 0);
        assert!(!operations.contains_thread(thread));

        let reset = events
            .signal(
                event_key,
                DW_SIGNAL_SIGNALED,
                deepwyrm_abi::DwSignals(0),
                &waits,
            )
            .unwrap();
        assert_eq!(reset.len(), 0);
    }

    close_event_for_test(&mut registry, &mut tasks, process, &events, event);
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
fn public_wait_many_obeys_scalar_snapshot_output_then_handle_failure_order() {
    use deepwyrm_abi::{DW_DEADLINE_NOW, DW_SIGNAL_SIGNALED, DW_WAIT_MODE_ALL, DW_WAIT_MODE_ANY};

    let (mut registry, mut tasks, execution, process, thread, process_handle) =
        wait_running_fixture();
    let events = EventAuthority::<1>::new();
    let timers = TimerAuthority::<1>::new();
    let channels = ChannelAuthority::<1, 2>::new();
    let waits = WaitRegistry::<8>::new();
    let mut operations = WaitOperationRegistry::<FakeOwnedOutput, 1>::new();
    let mut user = FakeUserMemory::new();
    let items = BASE + 0x700;
    let out = BASE + 0x900;

    user.deny_write = true;
    assert_eq!(
        wait_many_syscall(
            &mut user,
            &mut registry,
            &tasks,
            &events,
            &timers,
            &channels,
            &waits,
            &execution,
            &mut operations,
            None,
            process,
            thread,
            DwUserAddress(items),
            0,
            DW_WAIT_MODE_ANY,
            DW_DEADLINE_NOW,
            DwUserAddress(out),
        ),
        WaitSyscallAction::Returning(DW_STATUS_INVALID_ARGUMENT)
    );
    assert_eq!(user.owned_outputs, 0);

    assert_eq!(
        wait_many_syscall(
            &mut user,
            &mut registry,
            &tasks,
            &events,
            &timers,
            &channels,
            &waits,
            &execution,
            &mut operations,
            None,
            process,
            thread,
            DwUserAddress(items),
            1,
            DW_WAIT_MODE_ALL,
            DW_DEADLINE_NOW,
            DwUserAddress(out),
        ),
        WaitSyscallAction::Returning(DW_STATUS_NOT_SUPPORTED)
    );
    assert_eq!(user.owned_outputs, 0);

    write_wait_item(
        &mut user,
        items,
        0,
        DwHandle(u64::MAX),
        deepwyrm_abi::DwSignals(0),
    );
    assert_eq!(
        wait_many_syscall(
            &mut user,
            &mut registry,
            &tasks,
            &events,
            &timers,
            &channels,
            &waits,
            &execution,
            &mut operations,
            None,
            process,
            thread,
            DwUserAddress(items),
            1,
            DW_WAIT_MODE_ANY,
            DW_DEADLINE_NOW,
            DwUserAddress(out),
        ),
        WaitSyscallAction::Returning(DW_STATUS_INVALID_ARGUMENT)
    );
    assert_eq!(user.owned_outputs, 0);

    write_wait_item(&mut user, items, 0, DwHandle(u64::MAX), DW_SIGNAL_SIGNALED);
    assert_eq!(
        wait_many_syscall(
            &mut user,
            &mut registry,
            &tasks,
            &events,
            &timers,
            &channels,
            &waits,
            &execution,
            &mut operations,
            None,
            process,
            thread,
            DwUserAddress(items),
            1,
            DW_WAIT_MODE_ANY,
            DW_DEADLINE_NOW,
            DwUserAddress(out),
        ),
        WaitSyscallAction::Returning(DW_STATUS_BAD_ADDRESS)
    );
    assert_eq!(user.owned_outputs, 0);

    user.deny_write = false;
    assert_eq!(
        wait_many_syscall(
            &mut user,
            &mut registry,
            &tasks,
            &events,
            &timers,
            &channels,
            &waits,
            &execution,
            &mut operations,
            None,
            process,
            thread,
            DwUserAddress(items),
            1,
            DW_WAIT_MODE_ANY,
            DW_DEADLINE_NOW,
            DwUserAddress(out),
        ),
        WaitSyscallAction::Returning(DW_STATUS_BAD_HANDLE)
    );
    assert_eq!(user.owned_outputs, 0);

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
}

#[test]
fn wait_one_ready_beats_now_and_unsignaled_now_times_out() {
    use deepwyrm_abi::{DW_DEADLINE_NOW, DW_RIGHT_SIGNAL, DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED};

    let (mut registry, mut tasks, execution, process, thread, process_handle) =
        wait_running_fixture();
    let events = EventAuthority::<1>::new();
    let timers = TimerAuthority::<1>::new();
    let channels = ChannelAuthority::<1, 2>::new();
    let waits = WaitRegistry::<8>::new();
    let (event_key, reference) = events.create_event(&mut registry).unwrap();
    let event = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(reference, DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_SIGNAL.0))
        .unwrap();
    let initial = events
        .signal(
            event_key,
            deepwyrm_abi::DwSignals(0),
            DW_SIGNAL_SIGNALED,
            &waits,
        )
        .unwrap();
    assert_eq!(initial.len(), 0);
    let mut operations = crate::wait::operation::WaitOperationRegistry::<u32, 1>::new();

    match wait_one_begin(
        0x41,
        &mut registry,
        &tasks,
        &events,
        &timers,
        &channels,
        &waits,
        &execution,
        &mut operations,
        None,
        process,
        thread,
        event,
        DW_SIGNAL_SIGNALED,
        DW_DEADLINE_NOW,
    ) {
        WaitSyscallBegin::Returning {
            status,
            output,
            result: Some(result),
        } => {
            assert_eq!(status, DW_STATUS_SUCCESS);
            assert_eq!(output, 0x41);
            assert_eq!(u32::from_le_bytes(result[8..12].try_into().unwrap()), 0);
            assert_eq!(
                u64::from_le_bytes(result[16..24].try_into().unwrap()),
                DW_SIGNAL_SIGNALED.0
            );
        }
        _ => panic!("ready wait_one did not return success"),
    }

    let cleared = events
        .signal(
            event_key,
            DW_SIGNAL_SIGNALED,
            deepwyrm_abi::DwSignals(0),
            &waits,
        )
        .unwrap();
    assert_eq!(cleared.len(), 0);
    match wait_one_begin(
        0x42,
        &mut registry,
        &tasks,
        &events,
        &timers,
        &channels,
        &waits,
        &execution,
        &mut operations,
        None,
        process,
        thread,
        event,
        DW_SIGNAL_SIGNALED,
        DW_DEADLINE_NOW,
    ) {
        WaitSyscallBegin::Returning {
            status,
            output,
            result: None,
        } => {
            assert_eq!(status, DW_STATUS_TIMED_OUT);
            assert_eq!(output, 0x42);
        }
        _ => panic!("unsignaled NOW wait_one did not time out"),
    }
    assert_eq!(operations.len(), 0);
    close_event_for_test(&mut registry, &mut tasks, process, &events, event);
    let mut cleanup = CleanupQueue::<16>::new();
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
fn wait_many_validates_full_array_and_selects_lowest_ready_index() {
    use deepwyrm_abi::{
        DW_DEADLINE_NOW, DW_RIGHT_SIGNAL, DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED, DW_WAIT_MODE_ALL,
        DW_WAIT_MODE_ANY,
    };

    let (mut registry, mut tasks, execution, process, thread, process_handle) =
        wait_running_fixture();
    let events = EventAuthority::<2>::new();
    let timers = TimerAuthority::<1>::new();
    let channels = ChannelAuthority::<1, 2>::new();
    let waits = WaitRegistry::<8>::new();
    let mut user = FakeUserMemory::new();
    let rights = DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_SIGNAL.0);
    let (first_key, first_ref) = events.create_event(&mut registry).unwrap();
    let first = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(first_ref, rights)
        .unwrap();
    let (second_key, second_ref) = events.create_event(&mut registry).unwrap();
    let second = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(second_ref, rights)
        .unwrap();
    assert_eq!(
        events
            .signal(
                first_key,
                deepwyrm_abi::DwSignals(0),
                DW_SIGNAL_SIGNALED,
                &waits
            )
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        events
            .signal(
                second_key,
                deepwyrm_abi::DwSignals(0),
                DW_SIGNAL_SIGNALED,
                &waits
            )
            .unwrap()
            .len(),
        0
    );
    let items = BASE + 0x700;
    write_wait_item(&mut user, items, 0, second, DW_SIGNAL_SIGNALED);
    write_wait_item(&mut user, items, 1, first, DW_SIGNAL_SIGNALED);
    let mut operations = crate::wait::operation::WaitOperationRegistry::<u32, 1>::new();

    for (count, mode, expected) in [
        (0, DW_WAIT_MODE_ANY, DW_STATUS_INVALID_ARGUMENT),
        (1, DW_WAIT_MODE_ALL, DW_STATUS_NOT_SUPPORTED),
        (1, u32::MAX, DW_STATUS_INVALID_ARGUMENT),
        (
            DW_WAIT_MANY_MAX_ITEMS + 1,
            DW_WAIT_MODE_ANY,
            DW_STATUS_INVALID_ARGUMENT,
        ),
    ] {
        match wait_many_begin(
            &mut user,
            0x51,
            &mut registry,
            &tasks,
            &events,
            &timers,
            &channels,
            &waits,
            &execution,
            &mut operations,
            None,
            process,
            thread,
            DwUserAddress(items),
            count,
            mode,
            DW_DEADLINE_NOW,
        ) {
            WaitSyscallBegin::Returning { status, .. } => assert_eq!(status, expected),
            _ => panic!("invalid wait_many request suspended"),
        }
    }

    write_wait_item(&mut user, items, 1, DwHandle(u64::MAX), DW_SIGNAL_SIGNALED);
    match wait_many_begin(
        &mut user,
        0x52,
        &mut registry,
        &tasks,
        &events,
        &timers,
        &channels,
        &waits,
        &execution,
        &mut operations,
        None,
        process,
        thread,
        DwUserAddress(items),
        2,
        DW_WAIT_MODE_ANY,
        DW_DEADLINE_NOW,
    ) {
        WaitSyscallBegin::Returning { status, .. } => assert_eq!(status, DW_STATUS_BAD_HANDLE),
        _ => panic!("invalid later wait item did not fail full validation"),
    }

    write_wait_item(&mut user, items, 1, first, DW_SIGNAL_SIGNALED);
    match wait_many_begin(
        &mut user,
        0x53,
        &mut registry,
        &tasks,
        &events,
        &timers,
        &channels,
        &waits,
        &execution,
        &mut operations,
        None,
        process,
        thread,
        DwUserAddress(items),
        2,
        DW_WAIT_MODE_ANY,
        DW_DEADLINE_NOW,
    ) {
        WaitSyscallBegin::Returning {
            status,
            result: Some(result),
            ..
        } => {
            assert_eq!(status, DW_STATUS_SUCCESS);
            assert_eq!(u32::from_le_bytes(result[8..12].try_into().unwrap()), 0);
        }
        _ => panic!("ready wait_many did not return deterministically"),
    }
    close_event_for_test(&mut registry, &mut tasks, process, &events, first);
    close_event_for_test(&mut registry, &mut tasks, process, &events, second);
    let mut cleanup = CleanupQueue::<16>::new();
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
fn wait_one_suspend_transfers_output_owner_until_signal_resume() {
    use deepwyrm_abi::{DW_DEADLINE_INFINITE, DW_RIGHT_SIGNAL, DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED};

    let (mut registry, mut tasks, execution, process, thread, process_handle) =
        wait_running_fixture();
    let events = EventAuthority::<1>::new();
    let timers = TimerAuthority::<1>::new();
    let channels = ChannelAuthority::<1, 2>::new();
    let waits = WaitRegistry::<8>::new();
    let (event_key, reference) = events.create_event(&mut registry).unwrap();
    let event = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(reference, DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_SIGNAL.0))
        .unwrap();
    let mut operations = crate::wait::operation::WaitOperationRegistry::<u32, 1>::new();
    let wake = match wait_one_begin(
        0x61,
        &mut registry,
        &tasks,
        &events,
        &timers,
        &channels,
        &waits,
        &execution,
        &mut operations,
        None,
        process,
        thread,
        event,
        DW_SIGNAL_SIGNALED,
        DW_DEADLINE_INFINITE,
    ) {
        WaitSyscallBegin::Suspended { wake, .. } => wake,
        _ => panic!("unsignaled infinite wait_one did not suspend"),
    };
    assert!(operations.contains_thread(thread));
    let wakes = events
        .signal(
            event_key,
            deepwyrm_abi::DwSignals(0),
            DW_SIGNAL_SIGNALED,
            &waits,
        )
        .unwrap();
    let mut cleanup = CleanupQueue::<16>::new();
    complete_wait_wakes(&mut registry, &execution, wakes, &mut cleanup);
    let (output, winner, releases) = crate::wait::engine::finish_wait_operation(
        &mut registry,
        &waits,
        &execution,
        &mut operations,
        None,
        wake,
    )
    .unwrap();
    assert_eq!(output, 0x61);
    assert_eq!(
        winner,
        BlockedOperationWinner::Signal {
            item_index: 0,
            observed: DW_SIGNAL_SIGNALED,
        }
    );
    assert!(releases.is_empty());
    assert_eq!(execution.schedule_next().unwrap().current, Some(thread));
    close_event_for_test(&mut registry, &mut tasks, process, &events, event);
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
fn terminal_retirement_precedes_deferred_signal_completion_without_resurrection() {
    use deepwyrm_abi::{
        DW_DEADLINE_INFINITE, DW_RIGHT_MODIFY, DW_RIGHT_WAIT, DW_SIGNAL_SIGNALED,
        DW_TERMINATION_AUTHORIZED,
    };

    let (mut registry, mut tasks, process, process_handle) = process_fixture();
    let events = EventAuthority::<2>::new();
    let timers = TimerAuthority::<1>::new();
    let channels = ChannelAuthority::<2, 4>::new();
    let waits = WaitRegistry::<8>::new();
    let execution = ExecutionDomain::<2>::new(test_stack_bounds::<2>()).unwrap();
    let (event_key, event_ref) = events.create_event(&mut registry).unwrap();
    let event = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(event_ref, DW_RIGHT_WAIT)
        .unwrap();
    let process_pin = resolve_current_handle(
        &tasks,
        &mut registry,
        process,
        process_handle,
        deepwyrm_abi::DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_MODIFY,
    )
    .unwrap();
    let (target, target_ref) = tasks.create_thread(&mut registry, &process_pin).unwrap();
    let (killer, killer_ref) = tasks.create_thread(&mut registry, &process_pin).unwrap();
    let mut cleanup = CleanupQueue::<16>::new();
    release_lookup_pin(&mut registry, process_pin, &mut cleanup);
    let target_handle = tasks
        .process_handles_mut(process)
        .unwrap()
        .install(target_ref, DW_RIGHT_MODIFY)
        .unwrap();
    // Keep the killer's public reference out of the Process table; its execution
    // pin is sufficient for this kernel-model test and the reference is released
    // after its execution resources retire.
    assert!(registry.release_handle(killer_ref).unwrap().is_none());

    execution
        .start_thread(&mut tasks, target, test_start(0xd1))
        .unwrap();
    execution
        .start_thread(&mut tasks, killer, test_start(0xd2))
        .unwrap();
    assert_eq!(execution.schedule_next().unwrap().current, Some(target));

    let mut operations = WaitOperationRegistry::<u32, 2>::new();
    let wake = match wait_one_begin(
        0xfeed_u32,
        &mut registry,
        &tasks,
        &events,
        &timers,
        &channels,
        &waits,
        &execution,
        &mut operations,
        None,
        process,
        target,
        event,
        DW_SIGNAL_SIGNALED,
        DW_DEADLINE_INFINITE,
    ) {
        WaitSyscallBegin::Suspended { wake, decision } => {
            assert_eq!(decision.previous, Some(target));
            assert_eq!(decision.current, Some(killer));
            wake
        }
        _ => panic!("unsignaled target wait did not suspend"),
    };
    assert_eq!(
        execution.scheduler_state(target),
        Some(SchedulerThreadState::Blocked)
    );
    assert_eq!(
        execution.scheduler_state(killer),
        Some(SchedulerThreadState::Running)
    );
    assert!(operations.contains_thread(target));
    assert_eq!(waits.len(), 1);

    let delayed_wakes = events
        .signal(
            event_key,
            deepwyrm_abi::DwSignals(0),
            DW_SIGNAL_SIGNALED,
            &waits,
        )
        .unwrap();
    assert_eq!(waits.len(), 0);

    let mut discarded = None;
    {
        let mut terminal_waits = WaitTerminalCleanup::new(&mut operations, None, |output| {
            discarded = Some(output);
        });
        assert!(
            terminal_outcome(
                thread_terminate(
                    &mut registry,
                    &mut tasks,
                    &execution,
                    &waits,
                    &mut terminal_waits,
                    process,
                    killer,
                    target_handle,
                    DW_TERMINATION_AUTHORIZED,
                    0xd3,
                    &mut cleanup,
                ),
                DW_STATUS_SUCCESS,
                SyscallControl::ReturnToCaller,
            )
            .is_none()
        );
    }
    assert_eq!(discarded, Some(0xfeed));
    assert!(!operations.contains_thread(target));
    assert_eq!(waits.len(), 0);
    assert!(!execution.blocked_operations().has_thread(target));
    assert_eq!(execution.scheduler_state(target), None);
    assert_eq!(
        execution.scheduler_state(killer),
        Some(SchedulerThreadState::Running)
    );
    assert_eq!(
        execution.blocked_operations().winner(wake),
        Err(crate::task::BlockedOperationError::StaleReservation)
    );
    complete_wait_wakes(&mut registry, &execution, delayed_wakes, &mut cleanup);
    assert_eq!(execution.scheduler_state(target), None);

    close_event_for_test(&mut registry, &mut tasks, process, &events, event);
    assert_eq!(
        handle_close(
            &mut registry,
            &mut tasks,
            process,
            target_handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let (killer_stack, killer_context) = tasks.thread_execution_resources(killer).unwrap().unwrap();
    let deferred = terminal_outcome(
        thread_exit(
            &mut registry,
            &mut tasks,
            &execution,
            &waits,
            process,
            killer,
            0,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS,
        SyscallControl::TerminateCurrent,
    );
    assert!(execution.stack_bounds(killer_stack).is_ok());
    assert!(execution.load_context(killer_context).is_ok());
    complete_deferred_current_reclaim(
        &mut registry,
        &execution,
        &waits,
        deferred.unwrap(),
        &mut cleanup,
    );
    assert!(execution.stack_bounds(killer_stack).is_err());
    assert!(execution.load_context(killer_context).is_err());
    finish_task_cleanup(&mut registry, &mut tasks, cleanup);
}

// F10 uses a separate fixture because the target TaskGroup is intentionally
// distinct from the caller's parent. This makes the child-table reservation
// dependency observable without changing the established F5-F9 fixtures.
type F10Tasks = TaskAuthority<2, 3, 2, 8>;

struct F10Fixture {
    registry: ObjectRegistry<16>,
    tasks: F10Tasks,
    regions: AddressRegionObjectAuthority<2, 4>,
    spaces: AddressSpaceAuthority<2, 4>,
    channels: ChannelAuthority<2, 4>,
    waits: WaitRegistry<8>,
    user: FakeUserMemory,
    current: ProcessKey,
    current_process: DwHandle,
    parent_group: DwHandle,
    bootstrap: DwHandle,
    peer: DwHandle,
}

#[allow(
    unsafe_code,
    reason = "the F10 fixture uniquely owns its synthetic AddressSpaceAuthority identities"
)]
fn f10_fixture() -> F10Fixture {
    f10_fixture_with_rights(
        DwRights(DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0),
        DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0),
    )
}

#[allow(
    unsafe_code,
    reason = "the F10 fixture uniquely owns its synthetic AddressSpaceAuthority identities"
)]
fn f10_fixture_with_rights(
    parent_group_rights: DwRights,
    bootstrap_rights: DwRights,
) -> F10Fixture {
    let mut registry = ObjectRegistry::<16>::new();
    let mut tasks = F10Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (current, current_reference) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let current_process = tasks
        .process_handles_mut(current)
        .unwrap()
        .install(
            current_reference,
            DwRights(DW_RIGHT_DUPLICATE.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_MODIFY.0),
        )
        .unwrap();
    let (_parent, parent_reference) = tasks
        .create_child_group(&mut registry, &root_owner)
        .unwrap();
    let parent_group = tasks
        .process_handles_mut(current)
        .unwrap()
        .install(parent_reference, parent_group_rights)
        .unwrap();
    assert!(registry.release_internal(root_owner).unwrap().is_none());

    let channels = ChannelAuthority::<2, 4>::new();
    let mut user = FakeUserMemory::new();
    assert_eq!(
        channel_create(
            &mut user,
            &mut registry,
            &channels,
            &mut tasks,
            current,
            bootstrap_rights,
            DwUserAddress(BASE + 0x180),
            DwUserAddress(BASE + 0x188),
        ),
        DW_STATUS_SUCCESS
    );

    F10Fixture {
        registry,
        tasks,
        regions: AddressRegionObjectAuthority::new(),
        // SAFETY: this test-local authority owns only synthetic identities.
        spaces: unsafe { AddressSpaceAuthority::new() },
        channels,
        waits: WaitRegistry::new(),
        bootstrap: DwHandle(u64_at(&user, BASE + 0x180)),
        peer: DwHandle(u64_at(&user, BASE + 0x188)),
        user,
        current,
        current_process,
        parent_group,
    }
}

fn write_process_create_args(
    user: &mut FakeUserMemory,
    address: u64,
    task_group: DwHandle,
    bootstrap_channel: DwHandle,
    process_rights: DwRights,
    root_region_rights: DwRights,
    child_bootstrap_rights: DwRights,
) {
    use deepwyrm_abi::DW_PROCESS_CREATE_ARGS_V1_SIZE;

    let offset = FakeUserMemory::offset(address, DW_PROCESS_CREATE_ARGS_V1_SIZE as usize);
    let bytes = &mut user.bytes[offset..offset + DW_PROCESS_CREATE_ARGS_V1_SIZE as usize];
    bytes.fill(0);
    bytes[0..4].copy_from_slice(&DW_PROCESS_CREATE_ARGS_V1_SIZE.to_le_bytes());
    bytes[4..8].copy_from_slice(&1_u32.to_le_bytes());
    bytes[8..16].copy_from_slice(&task_group.0.to_le_bytes());
    bytes[16..24].copy_from_slice(&bootstrap_channel.0.to_le_bytes());
    bytes[24..32].copy_from_slice(&process_rights.0.to_le_bytes());
    bytes[32..40].copy_from_slice(&root_region_rights.0.to_le_bytes());
    bytes[40..48].copy_from_slice(&child_bootstrap_rights.0.to_le_bytes());
}

fn f10_rights() -> (DwRights, DwRights, DwRights) {
    use deepwyrm_abi::{DW_RIGHT_INSPECT, DW_RIGHT_READ};
    (DW_RIGHT_INSPECT, DW_RIGHT_INSPECT, DW_RIGHT_READ)
}

fn write_valid_f10_args(fixture: &mut F10Fixture, args_address: u64) {
    let (process_rights, root_rights, bootstrap_rights) = f10_rights();
    write_process_create_args(
        &mut fixture.user,
        args_address,
        fixture.parent_group,
        fixture.bootstrap,
        process_rights,
        root_rights,
        bootstrap_rights,
    );
}

fn assert_f10_failure_preserves_caller(
    fixture: &F10Fixture,
    output_address: u64,
    output_before: [u8; 64],
    caller_handles: usize,
    bootstrap: crate::handle::BasicHandleInfo,
) {
    assert_eq!(fixture.user.owned_outputs, 0);
    assert_eq!(
        fixture.tasks.process_handle_count(fixture.current).unwrap(),
        caller_handles
    );
    assert_eq!(
        fixture
            .tasks
            .process_handles(fixture.current)
            .unwrap()
            .inspect_basic(fixture.bootstrap)
            .unwrap(),
        bootstrap
    );
    let offset = FakeUserMemory::offset(output_address, output_before.len());
    assert_eq!(
        &fixture.user.bytes[offset..offset + output_before.len()],
        &output_before
    );
}

fn close_f10_channel(fixture: &mut F10Fixture, process: ProcessKey, handle: DwHandle) {
    let release = fixture
        .tasks
        .process_handles_mut(process)
        .unwrap()
        .close(&mut fixture.registry, handle)
        .unwrap()
        .unwrap();
    let finalization = fixture
        .channels
        .take_finalization(release, &fixture.waits)
        .unwrap();
    let completion = crate::ipc::complete_channel_finalization(&mut fixture.registry, finalization);
    assert_eq!(completion.into_parts().0.len(), 0);
}

fn close_f10_fixture_with_open_channels(
    mut fixture: F10Fixture,
    bootstrap_open: bool,
    peer_open: bool,
    parent_group_open: bool,
) {
    let mut cleanup = CleanupQueue::<16>::new();
    let current = fixture.current;
    let bootstrap = fixture.bootstrap;
    let peer = fixture.peer;
    let parent_group = fixture.parent_group;
    let current_process = fixture.current_process;
    if bootstrap_open {
        close_f10_channel(&mut fixture, current, bootstrap);
    }
    if peer_open {
        close_f10_channel(&mut fixture, current, peer);
    }
    if parent_group_open {
        assert_eq!(
            handle_close(
                &mut fixture.registry,
                &mut fixture.tasks,
                current,
                parent_group,
                &mut cleanup,
            ),
            DW_STATUS_SUCCESS
        );
    }
    assert_eq!(
        handle_close(
            &mut fixture.registry,
            &mut fixture.tasks,
            current,
            current_process,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    finish_f10_task_cleanup(&mut fixture.registry, &mut fixture.tasks, cleanup);
}

fn close_f10_fixture(fixture: F10Fixture) {
    close_f10_fixture_with_open_channels(fixture, true, true, true);
}

fn finish_f10_task_cleanup<const OBJECTS: usize>(
    registry: &mut ObjectRegistry<OBJECTS>,
    tasks: &mut F10Tasks,
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

fn retire_f10_created_process(
    fixture: &mut F10Fixture,
    child: ProcessKey,
    result_process: DwHandle,
    result_root: DwHandle,
    child_bootstrap: DwHandle,
    cleanup: &mut CleanupQueue<16>,
) {
    close_f10_channel(fixture, child, child_bootstrap);
    for handle in [result_root, result_process] {
        assert_eq!(
            handle_close(
                &mut fixture.registry,
                &mut fixture.tasks,
                fixture.current,
                handle,
                cleanup,
            ),
            DW_STATUS_SUCCESS
        );
    }

    let effects = fixture
        .tasks
        .terminate_process_authorized(&mut fixture.registry, child, 0x10)
        .unwrap();
    assert_eq!(effects.drained.final_release_count(), 0);
    let (process_pin, thread_pins, resources) = effects.pins.into_parts();
    assert!(thread_pins.into_iter().flatten().next().is_none());
    assert!(resources.into_iter().flatten().next().is_none());
    cleanup.push_optional(
        fixture
            .registry
            .release_internal(process_pin.unwrap())
            .unwrap(),
    );

    let blocked = crate::task::BlockedOperationRegistry::<2>::new();
    let drained = blocked.drained(child).unwrap();
    let runtime_pin = fixture
        .regions
        .retire_exited_root(&mut fixture.tasks, child, &blocked, drained)
        .unwrap();
    let root_final = fixture
        .registry
        .release_internal(runtime_pin)
        .unwrap()
        .unwrap();
    let root_finalization = fixture
        .regions
        .take_finalization(&mut fixture.spaces, root_final)
        .unwrap();
    cleanup.push_optional(complete_address_region_finalization(
        &mut fixture.registry,
        root_finalization,
    ));
    let completed = core::mem::replace(cleanup, CleanupQueue::new());
    finish_f10_task_cleanup(&mut fixture.registry, &mut fixture.tasks, completed);
    assert_eq!(
        fixture.tasks.process_info(child),
        Err(crate::task::TaskError::InvalidTask)
    );
}

struct NativeProcessCreateHarness<'a> {
    user: &'a mut FakeUserMemory,
    registry: &'a mut ObjectRegistry<16>,
    tasks: &'a mut F10Tasks,
    regions: &'a mut AddressRegionObjectAuthority<2, 4>,
    spaces: &'a mut AddressSpaceAuthority<2, 4>,
    current: ProcessKey,
    cleanup: &'a mut CleanupQueue<16>,
}

impl crate::syscall::native::NativeSyscallHandler for NativeProcessCreateHarness<'_> {
    fn handle(
        &mut self,
        request: crate::syscall::native::NativeSyscallRequest,
    ) -> crate::syscall::native::NativeSyscallResult {
        let status = match request {
            crate::syscall::native::NativeSyscallRequest::ProcessCreate {
                args,
                args_size,
                out_result,
                result_size,
            } => process_create(
                self.user,
                self.registry,
                self.tasks,
                self.regions,
                self.spaces,
                self.current,
                args,
                args_size,
                out_result,
                result_size,
                self.cleanup,
            ),
            _ => panic!("native F10 harness received a non-ProcessCreate request"),
        };
        crate::syscall::native::NativeSyscallResult::returning(status)
    }
}

#[test]
fn native_process_create_id_routes_through_the_real_transaction() {
    use crate::syscall::RawSyscallArguments;
    use crate::syscall::native::dispatch_native;
    use deepwyrm_abi::{
        DW_OBJECT_TYPE_PROCESS, DW_PROCESS_CREATE_ARGS_V1_SIZE, DW_PROCESS_CREATE_RESULT_V1_SIZE,
        DwKnownSyscall,
    };

    const ARGS: u64 = BASE + 0x600;
    const OUT: u64 = BASE + 0x700;

    let mut fixture = f10_fixture();
    write_valid_f10_args(&mut fixture, ARGS);
    let mut cleanup = CleanupQueue::<16>::new();
    let result = {
        let mut harness = NativeProcessCreateHarness {
            user: &mut fixture.user,
            registry: &mut fixture.registry,
            tasks: &mut fixture.tasks,
            regions: &mut fixture.regions,
            spaces: &mut fixture.spaces,
            current: fixture.current,
            cleanup: &mut cleanup,
        };
        dispatch_native(
            &mut harness,
            DwKnownSyscall::ProcessCreate.id(),
            RawSyscallArguments::new([
                ARGS,
                u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
                OUT,
                u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
                0,
                0,
            ]),
        )
    };
    assert_eq!(result.status, DW_STATUS_SUCCESS);
    assert_eq!(result.control, SyscallControl::ReturnToCaller);
    let result_process = DwHandle(u64_at(&fixture.user, OUT + 8));
    let result_root = DwHandle(u64_at(&fixture.user, OUT + 16));
    let child_bootstrap = DwHandle(u64_at(&fixture.user, OUT + 24));
    let child_pin = resolve_current_handle(
        &fixture.tasks,
        &mut fixture.registry,
        fixture.current,
        result_process,
        DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_INSPECT,
    )
    .unwrap();
    let child = ProcessKey::from_object_id(child_pin.id());
    release_lookup_pin(&mut fixture.registry, child_pin, &mut cleanup);
    retire_f10_created_process(
        &mut fixture,
        child,
        result_process,
        result_root,
        child_bootstrap,
        &mut cleanup,
    );
    close_f10_fixture_with_open_channels(fixture, false, true, true);

    let mut fixture = f10_fixture();
    write_valid_f10_args(&mut fixture, ARGS);
    fixture.user.bytes[FakeUserMemory::offset(OUT, 64)..FakeUserMemory::offset(OUT, 64) + 64]
        .fill(0xa5);
    let handles = fixture.tasks.process_handle_count(fixture.current).unwrap();
    let source = fixture
        .tasks
        .process_handles(fixture.current)
        .unwrap()
        .inspect_basic(fixture.bootstrap)
        .unwrap();
    fixture.user.deny_write = true;
    let mut cleanup = CleanupQueue::<16>::new();
    let result = {
        let mut harness = NativeProcessCreateHarness {
            user: &mut fixture.user,
            registry: &mut fixture.registry,
            tasks: &mut fixture.tasks,
            regions: &mut fixture.regions,
            spaces: &mut fixture.spaces,
            current: fixture.current,
            cleanup: &mut cleanup,
        };
        dispatch_native(
            &mut harness,
            DwKnownSyscall::ProcessCreate.id(),
            RawSyscallArguments::new([
                ARGS,
                u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
                OUT,
                u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
                0,
                0,
            ]),
        )
    };
    assert_eq!(result.status, DW_STATUS_BAD_ADDRESS);
    assert_eq!(result.control, SyscallControl::ReturnToCaller);
    assert_f10_failure_preserves_caller(&fixture, OUT, [0xa5; 64], handles, source);
    fixture.user.deny_write = false;
    finish_f10_task_cleanup(&mut fixture.registry, &mut fixture.tasks, cleanup);
    close_f10_fixture(fixture);
}

#[test]
fn process_create_validates_record_output_and_handle_order_without_publication() {
    use deepwyrm_abi::{
        DW_PROCESS_CREATE_ARGS_V1_SIZE, DW_PROCESS_CREATE_RESULT_V1_SIZE, DW_RIGHT_DUPLICATE,
    };

    const ARGS: u64 = BASE + 0x600;
    const OUT: u64 = BASE + 0x700;
    for case in [
        (
            "args-size",
            DW_STATUS_INVALID_ARGUMENT,
            0_u64,
            u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
        ),
        (
            "result-size",
            DW_STATUS_INVALID_ARGUMENT,
            u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
            0_u64,
        ),
    ] {
        let mut fixture = f10_fixture();
        write_valid_f10_args(&mut fixture, ARGS);
        fixture.user.bytes[FakeUserMemory::offset(OUT, 64)..FakeUserMemory::offset(OUT, 64) + 64]
            .fill(0xa5);
        let before = [0xa5; 64];
        let handles = fixture.tasks.process_handle_count(fixture.current).unwrap();
        let bootstrap = fixture
            .tasks
            .process_handles(fixture.current)
            .unwrap()
            .inspect_basic(fixture.bootstrap)
            .unwrap();
        assert_eq!(
            process_create(
                &mut fixture.user,
                &mut fixture.registry,
                &mut fixture.tasks,
                &mut fixture.regions,
                &mut fixture.spaces,
                fixture.current,
                DwUserAddress(ARGS),
                case.2,
                DwUserAddress(OUT),
                case.3,
                &mut CleanupQueue::new(),
            ),
            case.1,
            "{0}",
            case.0
        );
        assert_f10_failure_preserves_caller(&fixture, OUT, before, handles, bootstrap);
        close_f10_fixture(fixture);
    }

    let malformed = [
        (0_usize, 0_u8), // size
        (4, 2),          // version
        (48, 1),         // flags
        (56, 1),         // reserved
    ];
    for (offset, value) in malformed {
        let mut fixture = f10_fixture();
        write_valid_f10_args(&mut fixture, ARGS);
        fixture.user.bytes[FakeUserMemory::offset(ARGS + offset as u64, 1)] = value;
        let handles = fixture.tasks.process_handle_count(fixture.current).unwrap();
        let bootstrap = fixture
            .tasks
            .process_handles(fixture.current)
            .unwrap()
            .inspect_basic(fixture.bootstrap)
            .unwrap();
        assert_eq!(
            process_create(
                &mut fixture.user,
                &mut fixture.registry,
                &mut fixture.tasks,
                &mut fixture.regions,
                &mut fixture.spaces,
                fixture.current,
                DwUserAddress(ARGS),
                u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
                DwUserAddress(OUT),
                u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
                &mut CleanupQueue::new()
            ),
            DW_STATUS_INVALID_ARGUMENT
        );
        assert_f10_failure_preserves_caller(&fixture, OUT, [0; 64], handles, bootstrap);
        close_f10_fixture(fixture);
    }

    for (which, rights, expected) in [
        (24_u64, DwRights(0), DW_STATUS_INVALID_ARGUMENT),
        (32, DwRights(1 << 63), DW_STATUS_INVALID_ARGUMENT),
        (40, DwRights(DW_RIGHT_DUPLICATE.0), DW_STATUS_ACCESS_DENIED),
    ] {
        let mut fixture = f10_fixture();
        write_valid_f10_args(&mut fixture, ARGS);
        let offset = FakeUserMemory::offset(ARGS + which, 8);
        fixture.user.bytes[offset..offset + 8].copy_from_slice(&rights.0.to_le_bytes());
        let handles = fixture.tasks.process_handle_count(fixture.current).unwrap();
        let bootstrap = fixture
            .tasks
            .process_handles(fixture.current)
            .unwrap()
            .inspect_basic(fixture.bootstrap)
            .unwrap();
        assert_eq!(
            process_create(
                &mut fixture.user,
                &mut fixture.registry,
                &mut fixture.tasks,
                &mut fixture.regions,
                &mut fixture.spaces,
                fixture.current,
                DwUserAddress(ARGS),
                u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
                DwUserAddress(OUT),
                u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
                &mut CleanupQueue::new()
            ),
            expected
        );
        assert_f10_failure_preserves_caller(&fixture, OUT, [0; 64], handles, bootstrap);
        close_f10_fixture(fixture);
    }

    for (name, deny_read, deny_write) in
        [("copy-in", true, false), ("output-preflight", false, true)]
    {
        let mut fixture = f10_fixture();
        write_valid_f10_args(&mut fixture, ARGS);
        fixture.user.bytes[FakeUserMemory::offset(OUT, 64)..FakeUserMemory::offset(OUT, 64) + 64]
            .fill(0xa5);
        let generations = fixture.registry.test_slot_generations();
        let handles = fixture.tasks.process_handle_count(fixture.current).unwrap();
        let bootstrap = fixture
            .tasks
            .process_handles(fixture.current)
            .unwrap()
            .inspect_basic(fixture.bootstrap)
            .unwrap();
        fixture.user.deny_read = deny_read;
        fixture.user.deny_write = deny_write;
        assert_eq!(
            process_create(
                &mut fixture.user,
                &mut fixture.registry,
                &mut fixture.tasks,
                &mut fixture.regions,
                &mut fixture.spaces,
                fixture.current,
                DwUserAddress(ARGS),
                u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
                DwUserAddress(OUT),
                u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
                &mut CleanupQueue::new()
            ),
            DW_STATUS_BAD_ADDRESS,
            "{name}"
        );
        assert_eq!(
            fixture.registry.test_slot_generations(),
            generations,
            "{name}"
        );
        assert_f10_failure_preserves_caller(&fixture, OUT, [0xa5; 64], handles, bootstrap);
        fixture.user.deny_read = false;
        fixture.user.deny_write = false;
        close_f10_fixture(fixture);
    }
}

#[test]
fn process_create_resolves_authorities_in_contract_order_without_publication() {
    use deepwyrm_abi::{DW_PROCESS_CREATE_ARGS_V1_SIZE, DW_PROCESS_CREATE_RESULT_V1_SIZE};

    const ARGS: u64 = BASE + 0x600;
    const OUT: u64 = BASE + 0x700;

    for (name, task_group, bootstrap_channel) in [
        ("task-group-wrong-type", "bootstrap", "bootstrap"),
        ("bootstrap-wrong-type", "parent", "parent"),
    ] {
        let mut fixture = f10_fixture();
        let (process_rights, root_rights, child_rights) = f10_rights();
        let task_group = if task_group == "bootstrap" {
            fixture.bootstrap
        } else {
            fixture.parent_group
        };
        let bootstrap_channel = if bootstrap_channel == "bootstrap" {
            fixture.bootstrap
        } else {
            fixture.parent_group
        };
        write_process_create_args(
            &mut fixture.user,
            ARGS,
            task_group,
            bootstrap_channel,
            process_rights,
            root_rights,
            child_rights,
        );
        fixture.user.bytes[FakeUserMemory::offset(OUT, 64)..FakeUserMemory::offset(OUT, 64) + 64]
            .fill(0xa5);
        let handles = fixture.tasks.process_handle_count(fixture.current).unwrap();
        let source = fixture
            .tasks
            .process_handles(fixture.current)
            .unwrap()
            .inspect_basic(fixture.bootstrap)
            .unwrap();
        assert_eq!(
            process_create(
                &mut fixture.user,
                &mut fixture.registry,
                &mut fixture.tasks,
                &mut fixture.regions,
                &mut fixture.spaces,
                fixture.current,
                DwUserAddress(ARGS),
                u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
                DwUserAddress(OUT),
                u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
                &mut CleanupQueue::new(),
            ),
            DW_STATUS_WRONG_OBJECT_TYPE,
            "{name}"
        );
        assert_f10_failure_preserves_caller(&fixture, OUT, [0xa5; 64], handles, source);
        close_f10_fixture(fixture);
    }

    for (name, parent_rights, source_rights, expected) in [
        (
            "task-group-missing-modify",
            DwRights(DW_RIGHT_INSPECT.0),
            DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0),
            DW_STATUS_ACCESS_DENIED,
        ),
        (
            "bootstrap-missing-transfer",
            DwRights(DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0),
            DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_INSPECT.0),
            DW_STATUS_ACCESS_DENIED,
        ),
    ] {
        let mut fixture = f10_fixture_with_rights(parent_rights, source_rights);
        write_valid_f10_args(&mut fixture, ARGS);
        fixture.user.bytes[FakeUserMemory::offset(OUT, 64)..FakeUserMemory::offset(OUT, 64) + 64]
            .fill(0xa5);
        let handles = fixture.tasks.process_handle_count(fixture.current).unwrap();
        let source = fixture
            .tasks
            .process_handles(fixture.current)
            .unwrap()
            .inspect_basic(fixture.bootstrap)
            .unwrap();
        assert_eq!(
            process_create(
                &mut fixture.user,
                &mut fixture.registry,
                &mut fixture.tasks,
                &mut fixture.regions,
                &mut fixture.spaces,
                fixture.current,
                DwUserAddress(ARGS),
                u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
                DwUserAddress(OUT),
                u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
                &mut CleanupQueue::new(),
            ),
            expected,
            "{name}"
        );
        assert_f10_failure_preserves_caller(&fixture, OUT, [0xa5; 64], handles, source);
        close_f10_fixture(fixture);
    }

    let mut fixture = f10_fixture();
    write_valid_f10_args(&mut fixture, ARGS);
    fixture.user.bytes[FakeUserMemory::offset(OUT, 64)..FakeUserMemory::offset(OUT, 64) + 64]
        .fill(0xa5);
    let handles = fixture.tasks.process_handle_count(fixture.current).unwrap();
    let source = fixture
        .tasks
        .process_handles(fixture.current)
        .unwrap()
        .inspect_basic(fixture.bootstrap)
        .unwrap();
    let mut cleanup = CleanupQueue::<16>::new();
    let parent_pin = resolve_current_handle(
        &fixture.tasks,
        &mut fixture.registry,
        fixture.current,
        fixture.parent_group,
        DW_OBJECT_TYPE_TASK_GROUP,
        DW_RIGHT_INSPECT,
    )
    .unwrap();
    let parent = TaskGroupKey::from_object_id(parent_pin.id());
    release_lookup_pin(&mut fixture.registry, parent_pin, &mut cleanup);
    assert_eq!(
        fixture
            .tasks
            .terminate_group(&mut fixture.registry, parent)
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        process_create(
            &mut fixture.user,
            &mut fixture.registry,
            &mut fixture.tasks,
            &mut fixture.regions,
            &mut fixture.spaces,
            fixture.current,
            DwUserAddress(ARGS),
            u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
            DwUserAddress(OUT),
            u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
            &mut cleanup,
        ),
        DW_STATUS_BAD_STATE,
        "terminated task group"
    );
    assert_f10_failure_preserves_caller(&fixture, OUT, [0xa5; 64], handles, source);
    finish_f10_task_cleanup(&mut fixture.registry, &mut fixture.tasks, cleanup);
    close_f10_fixture(fixture);

    let mut fixture = f10_fixture();
    write_valid_f10_args(&mut fixture, ARGS);
    fixture.user.bytes[FakeUserMemory::offset(OUT, 64)..FakeUserMemory::offset(OUT, 64) + 64]
        .fill(0xa5);
    let mut cleanup = CleanupQueue::<16>::new();
    assert_eq!(
        handle_close(
            &mut fixture.registry,
            &mut fixture.tasks,
            fixture.current,
            fixture.parent_group,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let handles = fixture.tasks.process_handle_count(fixture.current).unwrap();
    let source = fixture
        .tasks
        .process_handles(fixture.current)
        .unwrap()
        .inspect_basic(fixture.bootstrap)
        .unwrap();
    assert_eq!(
        process_create(
            &mut fixture.user,
            &mut fixture.registry,
            &mut fixture.tasks,
            &mut fixture.regions,
            &mut fixture.spaces,
            fixture.current,
            DwUserAddress(ARGS),
            u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
            DwUserAddress(OUT),
            u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
            &mut cleanup,
        ),
        DW_STATUS_BAD_HANDLE,
        "stale task group"
    );
    assert_f10_failure_preserves_caller(&fixture, OUT, [0xa5; 64], handles, source);
    finish_f10_task_cleanup(&mut fixture.registry, &mut fixture.tasks, cleanup);
    close_f10_fixture_with_open_channels(fixture, true, true, false);

    let mut fixture = f10_fixture();
    write_valid_f10_args(&mut fixture, ARGS);
    fixture.user.bytes[FakeUserMemory::offset(OUT, 64)..FakeUserMemory::offset(OUT, 64) + 64]
        .fill(0xa5);
    let mut cleanup = CleanupQueue::<16>::new();
    let current = fixture.current;
    let bootstrap = fixture.bootstrap;
    close_f10_channel(&mut fixture, current, bootstrap);
    let handles = fixture.tasks.process_handle_count(fixture.current).unwrap();
    assert_eq!(
        process_create(
            &mut fixture.user,
            &mut fixture.registry,
            &mut fixture.tasks,
            &mut fixture.regions,
            &mut fixture.spaces,
            fixture.current,
            DwUserAddress(ARGS),
            u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
            DwUserAddress(OUT),
            u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
            &mut cleanup,
        ),
        DW_STATUS_BAD_HANDLE,
        "stale bootstrap"
    );
    assert_eq!(fixture.user.owned_outputs, 0);
    assert_eq!(
        fixture.tasks.process_handle_count(fixture.current).unwrap(),
        handles
    );
    assert_eq!(
        fixture
            .tasks
            .process_handles(fixture.current)
            .unwrap()
            .inspect_basic(fixture.bootstrap),
        Err(crate::handle::HandleTableError::InvalidHandle)
    );
    assert_eq!(
        &fixture.user.bytes[FakeUserMemory::offset(OUT, 64)..FakeUserMemory::offset(OUT, 64) + 64],
        &[0xa5; 64]
    );
    finish_f10_task_cleanup(&mut fixture.registry, &mut fixture.tasks, cleanup);
    close_f10_fixture_with_open_channels(fixture, false, true, true);
}

#[test]
fn process_create_parent_result_capacity_failure_rolls_back_before_source_move() {
    use deepwyrm_abi::{DW_PROCESS_CREATE_ARGS_V1_SIZE, DW_PROCESS_CREATE_RESULT_V1_SIZE};

    const ARGS: u64 = BASE + 0x600;
    const OUT: u64 = BASE + 0x700;
    let mut fixture = f10_fixture();
    write_valid_f10_args(&mut fixture, ARGS);
    fixture.user.bytes[FakeUserMemory::offset(OUT, 64)..FakeUserMemory::offset(OUT, 64) + 64]
        .fill(0xa5);
    let mut fillers = [DwHandle(0); 3];
    for (index, filler) in fillers.iter_mut().enumerate() {
        let output = BASE + 0x300 + u64::try_from(index).unwrap() * 8;
        assert_eq!(
            handle_duplicate(
                &mut fixture.user,
                &mut fixture.registry,
                &mut fixture.tasks,
                fixture.current,
                fixture.current_process,
                DW_RIGHT_INSPECT,
                DwUserAddress(output),
            ),
            DW_STATUS_SUCCESS
        );
        *filler = DwHandle(u64_at(&fixture.user, output));
    }
    assert_eq!(
        fixture.tasks.process_handle_count(fixture.current).unwrap(),
        7
    );
    let source = fixture
        .tasks
        .process_handles(fixture.current)
        .unwrap()
        .inspect_basic(fixture.bootstrap)
        .unwrap();
    let mut cleanup = CleanupQueue::<16>::new();
    assert_eq!(
        process_create(
            &mut fixture.user,
            &mut fixture.registry,
            &mut fixture.tasks,
            &mut fixture.regions,
            &mut fixture.spaces,
            fixture.current,
            DwUserAddress(ARGS),
            u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
            DwUserAddress(OUT),
            u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
            &mut cleanup,
        ),
        DW_STATUS_NO_RESOURCES
    );
    assert_f10_failure_preserves_caller(&fixture, OUT, [0xa5; 64], 7, source);
    for filler in fillers {
        assert_eq!(
            handle_close(
                &mut fixture.registry,
                &mut fixture.tasks,
                fixture.current,
                filler,
                &mut cleanup,
            ),
            DW_STATUS_SUCCESS
        );
    }
    finish_f10_task_cleanup(&mut fixture.registry, &mut fixture.tasks, cleanup);
    close_f10_fixture(fixture);
}

#[test]
fn process_create_injected_precommit_boundaries_rollback_every_authority() {
    use deepwyrm_abi::{DW_PROCESS_CREATE_ARGS_V1_SIZE, DW_PROCESS_CREATE_RESULT_V1_SIZE};

    const ARGS: u64 = BASE + 0x600;
    const OUT: u64 = BASE + 0x700;
    for stage in [
        ProcessCreatePreparation::BootstrapMove,
        ProcessCreatePreparation::ProcessShell,
        ProcessCreatePreparation::ChildBootstrapSlot,
        ProcessCreatePreparation::RootRegion,
        ProcessCreatePreparation::ParentResultSlots,
    ] {
        let mut fixture = f10_fixture();
        write_valid_f10_args(&mut fixture, ARGS);
        fixture.user.bytes[FakeUserMemory::offset(OUT, 64)..FakeUserMemory::offset(OUT, 64) + 64]
            .fill(0xa5);
        let caller_handles = fixture.tasks.process_handle_count(fixture.current).unwrap();
        let bootstrap = fixture
            .tasks
            .process_handles(fixture.current)
            .unwrap()
            .inspect_basic(fixture.bootstrap)
            .unwrap();
        let generations = fixture.registry.test_slot_generations();

        // Three retries exercise the two spare Process/root/address-space slots.
        // A cancelled reservation leak would turn one of these into an early
        // capacity failure instead of reaching this exact injection boundary.
        for retry in 0..3 {
            let mut cleanup = CleanupQueue::<16>::new();
            let mut observed = false;
            assert_eq!(
                process_create_transaction(
                    &mut fixture.user,
                    &mut fixture.registry,
                    &mut fixture.tasks,
                    &mut fixture.regions,
                    &mut fixture.spaces,
                    fixture.current,
                    DwUserAddress(ARGS),
                    u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
                    DwUserAddress(OUT),
                    u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
                    &mut cleanup,
                    |candidate| {
                        if candidate == stage {
                            observed = true;
                            Err(DW_STATUS_NO_RESOURCES)
                        } else {
                            Ok(())
                        }
                    },
                ),
                DW_STATUS_NO_RESOURCES,
                "{stage:?} retry {retry}"
            );
            assert!(observed, "{stage:?} retry {retry} was not reached");
            assert_f10_failure_preserves_caller(
                &fixture,
                OUT,
                [0xa5; 64],
                caller_handles,
                bootstrap,
            );
            finish_f10_task_cleanup(&mut fixture.registry, &mut fixture.tasks, cleanup);
        }
        let after_failures = fixture.registry.test_slot_generations();
        assert!(
            after_failures
                .iter()
                .zip(generations)
                .all(|(after, before)| after >= &before),
            "{stage:?} rollback regressed an object generation"
        );

        // The ordinary success probe proves that cancellation returned every
        // Process/root/address-space capacity, not merely caller-visible state.
        let mut cleanup = CleanupQueue::<16>::new();
        assert_eq!(
            process_create(
                &mut fixture.user,
                &mut fixture.registry,
                &mut fixture.tasks,
                &mut fixture.regions,
                &mut fixture.spaces,
                fixture.current,
                DwUserAddress(ARGS),
                u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
                DwUserAddress(OUT),
                u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
                &mut cleanup,
            ),
            DW_STATUS_SUCCESS,
            "{stage:?} capacity retry"
        );
        let child_pin = resolve_current_handle(
            &fixture.tasks,
            &mut fixture.registry,
            fixture.current,
            DwHandle(u64_at(&fixture.user, OUT + 8)),
            DW_OBJECT_TYPE_PROCESS,
            DW_RIGHT_INSPECT,
        )
        .unwrap();
        let child = ProcessKey::from_object_id(child_pin.id());
        release_lookup_pin(&mut fixture.registry, child_pin, &mut cleanup);
        let result_process = DwHandle(u64_at(&fixture.user, OUT + 8));
        let result_root = DwHandle(u64_at(&fixture.user, OUT + 16));
        let child_bootstrap = DwHandle(u64_at(&fixture.user, OUT + 24));
        retire_f10_created_process(
            &mut fixture,
            child,
            result_process,
            result_root,
            child_bootstrap,
            &mut cleanup,
        );
        close_f10_fixture_with_open_channels(fixture, false, true, true);
    }
}

#[test]
fn process_create_commits_typed_results_and_child_bootstrap_metadata() {
    use deepwyrm_abi::{
        DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_PROCESS, DW_PROCESS_CREATE_ARGS_V1_SIZE,
        DW_PROCESS_CREATE_RESULT_V1_SIZE, DW_RIGHT_READ, DW_TASK_STATE_CREATED,
    };

    const ARGS: u64 = BASE + 0x600;
    const OUT: u64 = BASE + 0x700;
    let mut fixture = f10_fixture();
    write_valid_f10_args(&mut fixture, ARGS);
    let (process_rights, root_rights, bootstrap_rights) = f10_rights();
    let mut cleanup = CleanupQueue::<16>::new();
    assert_eq!(
        process_create(
            &mut fixture.user,
            &mut fixture.registry,
            &mut fixture.tasks,
            &mut fixture.regions,
            &mut fixture.spaces,
            fixture.current,
            DwUserAddress(ARGS),
            u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
            DwUserAddress(OUT),
            u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_eq!(fixture.user.owned_outputs, 0);
    let result_process = DwHandle(u64_at(&fixture.user, OUT + 8));
    let result_root = DwHandle(u64_at(&fixture.user, OUT + 16));
    let child_bootstrap = DwHandle(u64_at(&fixture.user, OUT + 24));
    assert_eq!(u32_at(&fixture.user, OUT), DW_PROCESS_CREATE_RESULT_V1_SIZE);
    assert_eq!(u32_at(&fixture.user, OUT + 4), 1);
    assert_eq!(
        &fixture.user.bytes
            [FakeUserMemory::offset(OUT + 32, 32)..FakeUserMemory::offset(OUT + 32, 32) + 32],
        &[0; 32]
    );

    let parent_handles = fixture.tasks.process_handles(fixture.current).unwrap();
    assert_eq!(
        parent_handles
            .inspect_basic(result_process)
            .unwrap()
            .object_type,
        DW_OBJECT_TYPE_PROCESS
    );
    assert_eq!(
        parent_handles.inspect_basic(result_process).unwrap().rights,
        process_rights
    );
    assert_eq!(
        parent_handles
            .inspect_basic(result_root)
            .unwrap()
            .object_type,
        DW_OBJECT_TYPE_ADDRESS_REGION
    );
    assert_eq!(
        parent_handles.inspect_basic(result_root).unwrap().rights,
        root_rights
    );
    assert_eq!(
        parent_handles.inspect_basic(fixture.bootstrap),
        Err(crate::handle::HandleTableError::InvalidHandle)
    );

    let child_pin = resolve_current_handle(
        &fixture.tasks,
        &mut fixture.registry,
        fixture.current,
        result_process,
        DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_INSPECT,
    )
    .unwrap();
    let child = ProcessKey::from_object_id(child_pin.id());
    release_lookup_pin(&mut fixture.registry, child_pin, &mut cleanup);
    assert_eq!(
        fixture.tasks.process_info(child).unwrap().state,
        DW_TASK_STATE_CREATED
    );
    assert!(fixture.tasks.root_region(child).unwrap().is_some());
    let child_bootstrap_pin = fixture
        .tasks
        .process_handles(child)
        .unwrap()
        .lookup(
            &mut fixture.registry,
            child_bootstrap,
            AcceptedObjectTypes::One(deepwyrm_abi::DW_OBJECT_TYPE_CHANNEL),
            DW_RIGHT_READ,
        )
        .unwrap();
    assert_eq!(child_bootstrap_pin.rights(), bootstrap_rights);
    release_lookup_pin(
        &mut fixture.registry,
        child_bootstrap_pin.into_internal(),
        &mut cleanup,
    );

    // The bootstrap raw value is child-table metadata, not an authority in the
    // creating table. Only the moved source is required to be stale there.
    retire_f10_created_process(
        &mut fixture,
        child,
        result_process,
        result_root,
        child_bootstrap,
        &mut cleanup,
    );

    // Reuse the surviving peer as the second source. This immediately proves
    // that the terminated child returned both Process and root-region capacity.
    write_process_create_args(
        &mut fixture.user,
        ARGS,
        fixture.parent_group,
        fixture.peer,
        process_rights,
        root_rights,
        bootstrap_rights,
    );
    assert_eq!(
        process_create(
            &mut fixture.user,
            &mut fixture.registry,
            &mut fixture.tasks,
            &mut fixture.regions,
            &mut fixture.spaces,
            fixture.current,
            DwUserAddress(ARGS),
            u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
            DwUserAddress(OUT),
            u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    let retry_process = DwHandle(u64_at(&fixture.user, OUT + 8));
    let retry_root = DwHandle(u64_at(&fixture.user, OUT + 16));
    let retry_bootstrap = DwHandle(u64_at(&fixture.user, OUT + 24));
    let retry_pin = resolve_current_handle(
        &fixture.tasks,
        &mut fixture.registry,
        fixture.current,
        retry_process,
        DW_OBJECT_TYPE_PROCESS,
        DW_RIGHT_INSPECT,
    )
    .unwrap();
    let retry_child = ProcessKey::from_object_id(retry_pin.id());
    release_lookup_pin(&mut fixture.registry, retry_pin, &mut cleanup);
    retire_f10_created_process(
        &mut fixture,
        retry_child,
        retry_process,
        retry_root,
        retry_bootstrap,
        &mut cleanup,
    );
    close_f10_fixture_with_open_channels(fixture, false, false, true);
}
