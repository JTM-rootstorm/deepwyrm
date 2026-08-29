extern crate std;

use super::*;
use crate::handle::{AcceptedObjectTypes, HandleTableError};
use crate::memory::address_region::AtomicWaitKey;
use crate::memory::user_range::{UserAccess, UserPageChunk, UserRange};
use crate::memory::usercopy::{PinnedUserBatchPages, PinnedUserPages, UserPageAccess};
use crate::task::{SchedulerThreadState, ThreadStartState};
use crate::time::{DeadlineQueue, DeadlineRegistration, TimerDeadlineError, TimerExpiryToken};
use crate::wait::engine::{WaitDeadlineError, claim_timeout_and_wake};
use deepwyrm_abi::{
    DW_CHANNEL_MAX_PAYLOAD, DW_CHANNEL_RECEIVE_RESULT_V1_SIZE, DW_DEADLINE_INFINITE,
    DW_HANDLE_TRANSFER_MOVE, DW_OBJECT_TYPE_CHANNEL, DW_OBJECT_TYPE_EVENT,
    DW_PROCESS_CREATE_ARGS_V1_SIZE, DW_PROCESS_CREATE_RESULT_V1_SIZE, DW_RIGHT_INSPECT,
    DW_RIGHT_MODIFY, DW_RIGHT_READ, DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE,
    DW_SIGNAL_SIGNALED, DW_STATUS_SUCCESS, DW_STATUS_TIMED_OUT, DW_TASK_STATE_CREATED, DwHandle,
    DwHandleTransferV1, DwRights,
};
use std::vec;
use std::vec::Vec;

const BASE: u64 = 0x4000;
const USER_BYTES: usize = 0x3000;
const OBJECTS: usize = 32;
const EXECUTION: usize = 2;
const WAITERS: usize = 8;
const ATOMIC_WAITERS: usize = 4;

type Tasks = TaskAuthority<3, 3, 2, 16>;
type Services = FServiceState<FakeOwnedOutput, FakeAtomicPin, OBJECTS, ATOMIC_WAITERS, EXECUTION>;

struct FakeUserMemory {
    bytes: [u8; USER_BYTES],
    owned_outputs: usize,
    atomic_value: u32,
    atomic_pins: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FakeOwnedOutput {
    range: UserRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FakeAtomicPin {
    address: DwUserAddress,
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
            bytes: [0; USER_BYTES],
            owned_outputs: 0,
            atomic_value: 0,
            atomic_pins: 0,
        }
    }

    fn checked_offset(address: u64, len: usize) -> Result<usize, ()> {
        let offset = address.checked_sub(BASE).ok_or(())?;
        let offset = usize::try_from(offset).map_err(|_| ())?;
        if offset.checked_add(len).is_some_and(|end| end <= USER_BYTES) {
            Ok(offset)
        } else {
            Err(())
        }
    }

    fn offset(address: u64, len: usize) -> usize {
        Self::checked_offset(address, len).expect("test userspace range is in bounds")
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
        if !range.access().includes(UserAccess::WRITE) {
            return Err(());
        }
        let len = usize::try_from(range.byte_len()).map_err(|_| ())?;
        let _ = Self::checked_offset(range.start(), len)?;
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
        self.owned_outputs -= 1;
    }

    fn discard_owned_output(&mut self, _output: Self::OwnedOutput) {
        self.owned_outputs -= 1;
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
            for right_range in ranges[left + 1..].iter().flatten().copied() {
                if !left_range.is_empty()
                    && !right_range.is_empty()
                    && left_range.start() < right_range.end_exclusive()
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
        let len = usize::try_from(chunk.byte_len()).map_err(|_| ())?;
        let _ = FakeUserMemory::checked_offset(chunk.address(), len)?;
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
        let end = chunk.address().checked_add(chunk.byte_len()).ok_or(())?;
        if chunk.address() < range.start() || end > range.end_exclusive() {
            return Err(());
        }
        let len = usize::try_from(chunk.byte_len()).map_err(|_| ())?;
        let _ = FakeUserMemory::checked_offset(chunk.address(), len)?;
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

impl FAtomicUserAccess for FakeUserMemory {
    type AtomicPin = FakeAtomicPin;

    fn pin_atomic_u32(&mut self, address: DwUserAddress) -> Result<Self::AtomicPin, DwStatus> {
        if address.0 & 3 != 0 || Self::checked_offset(address.0, 4).is_err() {
            return Err(DW_STATUS_BAD_ADDRESS);
        }
        self.atomic_pins += 1;
        Ok(FakeAtomicPin { address })
    }

    fn load_atomic_u32_acquire(&mut self, pin: &Self::AtomicPin) -> u32 {
        assert_eq!(pin.address.0 & 3, 0);
        self.atomic_value
    }

    fn release_atomic_u32(&mut self, _pin: Self::AtomicPin) {
        self.atomic_pins = self
            .atomic_pins
            .checked_sub(1)
            .expect("atomic pin release underflow");
    }
}

struct TestWaitDeadlines<const N: usize> {
    queue: DeadlineQueue<N>,
}

impl<const N: usize> TestWaitDeadlines<N> {
    fn new() -> Self {
        Self {
            queue: DeadlineQueue::new(),
        }
    }
}

impl<const N: usize> WaitDeadlineAuthority for TestWaitDeadlines<N> {
    fn register_wait_deadline(
        &mut self,
        deadline_ns: u64,
        wake: crate::task::BlockWakeKey,
    ) -> Result<DeadlineRegistration, WaitDeadlineError> {
        self.queue
            .register(deadline_ns, wake)
            .map_err(|error| match error {
                crate::time::DeadlineQueueError::Capacity => WaitDeadlineError::Capacity,
                _ => WaitDeadlineError::Fault,
            })
    }

    fn cancel_wait_deadline(
        &mut self,
        registration: DeadlineRegistration,
    ) -> Result<(), WaitDeadlineError> {
        self.queue
            .cancel_if_live(registration)
            .map(|_| ())
            .map_err(|_| WaitDeadlineError::Fault)
    }
}

struct TestTimerDeadlines<const N: usize> {
    now_ns: u64,
    queue: DeadlineQueue<N, TimerExpiryToken>,
}

impl<const N: usize> TestTimerDeadlines<N> {
    fn new(now_ns: u64) -> Self {
        Self {
            now_ns,
            queue: DeadlineQueue::new(),
        }
    }
}

impl<const N: usize> TimerDeadlineAuthority for TestTimerDeadlines<N> {
    fn replace_timer_deadline(
        &mut self,
        old: Option<&DeadlineRegistration>,
        deadline_ns: u64,
        token: TimerExpiryToken,
    ) -> Result<Option<DeadlineRegistration>, TimerDeadlineError> {
        if deadline_ns <= self.now_ns {
            if let Some(old) = old {
                self.queue
                    .cancel_if_live_ref(old)
                    .map_err(|_| TimerDeadlineError::Fault)?;
            }
            return Ok(None);
        }
        if let Some(old) = old
            && let Some(registration) = self
                .queue
                .replace_if_live(old, deadline_ns, token)
                .map_err(|error| match error {
                    crate::time::DeadlineQueueError::Capacity => TimerDeadlineError::Capacity,
                    _ => TimerDeadlineError::Fault,
                })?
        {
            return Ok(Some(registration));
        }
        self.queue
            .register(deadline_ns, token)
            .map(Some)
            .map_err(|error| match error {
                crate::time::DeadlineQueueError::Capacity => TimerDeadlineError::Capacity,
                _ => TimerDeadlineError::Fault,
            })
    }

    fn cancel_timer_deadline(
        &mut self,
        registration: &DeadlineRegistration,
    ) -> Result<(), TimerDeadlineError> {
        self.queue
            .cancel_if_live_ref(registration)
            .map(|_| ())
            .map_err(|_| TimerDeadlineError::Fault)
    }
}

struct Fixture {
    registry: ObjectRegistry<OBJECTS>,
    tasks: Tasks,
    execution: ExecutionDomain<EXECUTION>,
    channels: ChannelAuthority<4, 4>,
    events: EventAuthority<4>,
    timers: TimerAuthority<4>,
    waits: WaitRegistry<WAITERS>,
    regions: AddressRegionObjectAuthority<4, 8>,
    spaces: AddressSpaceAuthority<4, 8>,
    wait_deadlines: TestWaitDeadlines<8>,
    timer_deadlines: TestTimerDeadlines<8>,
    staging: Vec<u8>,
    user: FakeUserMemory,
    services: Services,
    control: NativeWaitControl,
    process: ProcessKey,
    thread: ThreadKey,
}

impl Fixture {
    #[allow(
        unsafe_code,
        reason = "the test fixture uniquely owns synthetic AddressSpaceAuthority identities"
    )]
    fn new() -> Self {
        let mut registry = ObjectRegistry::new();
        let mut tasks = Tasks::new();
        let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
        let (process, process_reference) =
            tasks.create_process(&mut registry, &root_owner).unwrap();
        let process_owner = registry
            .retain_internal_from_handle(&process_reference)
            .unwrap();
        let (thread, thread_reference) =
            tasks.create_thread(&mut registry, &process_owner).unwrap();
        assert!(registry.release_handle(thread_reference).unwrap().is_none());
        assert!(
            registry
                .release_handle(process_reference)
                .unwrap()
                .is_none()
        );
        assert!(registry.release_internal(process_owner).unwrap().is_none());
        assert!(registry.release_internal(root_owner).unwrap().is_none());

        let execution = ExecutionDomain::new(test_stack_bounds()).unwrap();
        execution
            .start_thread(
                &mut tasks,
                thread,
                ThreadStartState::from_validated_user_state(
                    0x0000_0000_4000_0000,
                    0x0000_0000_5000_0000,
                    0,
                    0,
                ),
            )
            .unwrap();
        assert_eq!(execution.schedule_next().unwrap().current, Some(thread));

        Self {
            registry,
            tasks,
            execution,
            channels: ChannelAuthority::new(),
            events: EventAuthority::new(),
            timers: TimerAuthority::new(),
            waits: WaitRegistry::new(),
            regions: AddressRegionObjectAuthority::new(),
            spaces: unsafe { AddressSpaceAuthority::new() },
            wait_deadlines: TestWaitDeadlines::new(),
            timer_deadlines: TestTimerDeadlines::new(0),
            staging: vec![0; DW_CHANNEL_MAX_PAYLOAD as usize],
            user: FakeUserMemory::new(),
            services: Services::new(),
            control: NativeWaitControl::new(),
            process,
            thread,
        }
    }

    fn dispatch(&mut self, request: NativeSyscallRequest) -> FServiceDispatch<OBJECTS> {
        let prepared = self
            .services
            .prepare_dispatch(request, self.thread, 1)
            .unwrap();
        self.services.dispatch_prepared(
            &mut self.control,
            prepared,
            &mut self.user,
            &mut self.registry,
            &mut self.tasks,
            &self.execution,
            &self.channels,
            &self.events,
            &self.timers,
            None,
            &self.waits,
            &mut self.regions,
            &mut self.spaces,
            self.process,
            self.thread,
            crate::cpu::CpuIndex::BOOTSTRAP,
            1,
            Some(&mut self.wait_deadlines),
            &mut self.timer_deadlines,
            &mut self.staging,
            || Ok(0x1122_3344_5566_7788),
        )
    }

    fn handled(&mut self, request: NativeSyscallRequest) -> NativeSyscallResult {
        let (route, cleanup) = self.dispatch(request).into_parts();
        assert_empty_cleanup(cleanup);
        match route {
            FServiceRoute::Handled(result) => result,
            FServiceRoute::Fallthrough(request) => {
                panic!("F request unexpectedly fell through: {request:?}")
            }
        }
    }
}

fn test_stack_bounds() -> [crate::memory::kernel_stack::KernelStackBounds; EXECUTION] {
    core::array::from_fn(|index| {
        let guard = 0xffff_9700_0000_0000 + u64::try_from(index).unwrap() * 0x11_000;
        crate::memory::kernel_stack::KernelStackBounds::new(guard, guard + 0x1000, guard + 0x11_000)
            .unwrap()
    })
}

fn assert_empty_cleanup(cleanup: CleanupQueue<OBJECTS>) {
    assert!(
        cleanup
            .into_releases()
            .into_iter()
            .all(|release| release.is_none())
    );
}

fn u64_at(user: &FakeUserMemory, address: u64) -> u64 {
    let offset = FakeUserMemory::offset(address, 8);
    u64::from_le_bytes(user.bytes[offset..offset + 8].try_into().unwrap())
}

fn u32_at(user: &FakeUserMemory, address: u64) -> u32 {
    let offset = FakeUserMemory::offset(address, 4);
    u32::from_le_bytes(user.bytes[offset..offset + 4].try_into().unwrap())
}

fn write_handle_transfer(user: &mut FakeUserMemory, address: u64, transfer: DwHandleTransferV1) {
    let offset = FakeUserMemory::offset(address, deepwyrm_abi::DW_HANDLE_TRANSFER_V1_SIZE as usize);
    user.bytes[offset..offset + 8].copy_from_slice(&transfer.handle.0.to_le_bytes());
    user.bytes[offset + 8..offset + 16].copy_from_slice(&transfer.requested_rights.0.to_le_bytes());
    user.bytes[offset + 16..offset + 20].copy_from_slice(&transfer.operation.0.to_le_bytes());
    user.bytes[offset + 20..offset + 24].copy_from_slice(&transfer.reserved0.to_le_bytes());
    user.bytes[offset + 24..offset + 32].copy_from_slice(&transfer.reserved[0].to_le_bytes());
    user.bytes[offset + 32..offset + 40].copy_from_slice(&transfer.reserved[1].to_le_bytes());
}

fn close_event(fixture: &mut Fixture, handle: DwHandle) {
    let release = fixture
        .tasks
        .process_handles_mut(fixture.process)
        .unwrap()
        .close(&mut fixture.registry, handle)
        .unwrap()
        .unwrap();
    let finalization = fixture.events.take_finalization(release).unwrap();
    crate::wait::complete_event_finalization(&mut fixture.registry, finalization);
}

fn close_timer(fixture: &mut Fixture, handle: DwHandle) {
    let release = fixture
        .tasks
        .process_handles_mut(fixture.process)
        .unwrap()
        .close(&mut fixture.registry, handle)
        .unwrap()
        .unwrap();
    let finalization = fixture
        .timers
        .take_finalization(release, &mut fixture.timer_deadlines)
        .unwrap();
    crate::time::complete_timer_finalization(&mut fixture.registry, finalization);
}

fn close_channel(fixture: &mut Fixture, handle: DwHandle) {
    close_channel_for_process(fixture, fixture.process, handle);
}

fn close_channel_for_process(fixture: &mut Fixture, process: ProcessKey, handle: DwHandle) {
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
    let (wakes, releases) = completion.into_parts();
    assert_eq!(wakes.len(), 0);
    assert!(releases.into_iter().flatten().next().is_none());
}

fn stable_atomic_key(registry: &mut ObjectRegistry<OBJECTS>) -> AtomicWaitKey {
    let creation = registry
        .create(deepwyrm_abi::DW_OBJECT_TYPE_MEMORY_OBJECT)
        .unwrap();
    let key = AtomicWaitKey::new(creation.id(), 0x80);
    registry.cancel_creation(creation).unwrap();
    key
}

fn write_process_create_args(
    user: &mut FakeUserMemory,
    address: u64,
    group: DwHandle,
    bootstrap: DwHandle,
) {
    let offset = FakeUserMemory::offset(address, DW_PROCESS_CREATE_ARGS_V1_SIZE as usize);
    let bytes = &mut user.bytes[offset..offset + DW_PROCESS_CREATE_ARGS_V1_SIZE as usize];
    bytes.fill(0);
    bytes[0..4].copy_from_slice(&DW_PROCESS_CREATE_ARGS_V1_SIZE.to_le_bytes());
    bytes[4..8].copy_from_slice(&1_u32.to_le_bytes());
    bytes[8..16].copy_from_slice(&group.0.to_le_bytes());
    bytes[16..24].copy_from_slice(&bootstrap.0.to_le_bytes());
    bytes[24..32].copy_from_slice(&DW_RIGHT_INSPECT.0.to_le_bytes());
    bytes[32..40].copy_from_slice(&DW_RIGHT_INSPECT.0.to_le_bytes());
    bytes[40..48].copy_from_slice(&DW_RIGHT_READ.0.to_le_bytes());
}

fn finish_task_cleanup(fixture: &mut Fixture, cleanup: CleanupQueue<OBJECTS>) {
    for release in cleanup.into_releases().into_iter().flatten() {
        let mut pending = Some(release);
        while let Some(release) = pending.take() {
            let finalization = fixture.tasks.take_finalization(release).unwrap();
            pending = crate::task::complete_task_finalization(&mut fixture.registry, finalization);
        }
    }
}

fn close_task_handle(fixture: &mut Fixture, handle: DwHandle) {
    let mut cleanup = CleanupQueue::<OBJECTS>::new();
    assert_eq!(
        super::super::adapters::handle_close(
            &mut fixture.registry,
            &mut fixture.tasks,
            fixture.process,
            handle,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    finish_task_cleanup(fixture, cleanup);
}

fn retire_created_process(
    fixture: &mut Fixture,
    child: ProcessKey,
    process_handle: DwHandle,
    root_handle: DwHandle,
    child_bootstrap: DwHandle,
    peer: DwHandle,
    child_group: DwHandle,
) {
    close_channel_for_process(fixture, child, child_bootstrap);
    close_channel(fixture, peer);

    let mut cleanup = CleanupQueue::<OBJECTS>::new();
    for handle in [root_handle, process_handle] {
        assert_eq!(
            super::super::adapters::handle_close(
                &mut fixture.registry,
                &mut fixture.tasks,
                fixture.process,
                handle,
                &mut cleanup,
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

    let blocked = crate::task::BlockedOperationRegistry::<EXECUTION>::new();
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
    cleanup.push_optional(
        crate::memory::address_region::complete_address_region_finalization(
            &mut fixture.registry,
            root_finalization,
        ),
    );
    finish_task_cleanup(fixture, cleanup);
    close_task_handle(fixture, child_group);
}

#[test]
fn f_routes_its_public_owners_and_preserves_e_fallthrough() {
    let mut fixture = Fixture::new();
    let basic = NativeSyscallRequest::HandleClose {
        handle: DwHandle(u64::MAX),
    };
    let (route, cleanup) = fixture.dispatch(basic).into_parts();
    assert_eq!(route, FServiceRoute::Fallthrough(basic));
    assert_empty_cleanup(cleanup);

    let clock = fixture.handled(NativeSyscallRequest::ClockGet {
        clock_id: deepwyrm_abi::DW_CLOCK_MONOTONIC_ACTIVE,
        out_nanoseconds: DwUserAddress(BASE + 0x80),
    });
    assert_eq!(clock.status, DW_STATUS_SUCCESS);
    assert_eq!(u64_at(&fixture.user, BASE + 0x80), 0x1122_3344_5566_7788);

    let timer_rights = DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_MODIFY.0);
    assert_eq!(
        fixture
            .handled(NativeSyscallRequest::TimerCreate {
                requested_rights: timer_rights,
                out_timer: DwUserAddress(BASE + 0x90),
            })
            .status,
        DW_STATUS_SUCCESS
    );
    let timer = DwHandle(u64_at(&fixture.user, BASE + 0x90));
    assert_eq!(
        fixture
            .handled(NativeSyscallRequest::TimerSet {
                timer,
                deadline: DwDeadline(50),
            })
            .status,
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        fixture
            .handled(NativeSyscallRequest::TimerCancel { timer })
            .status,
        DW_STATUS_SUCCESS
    );
    close_timer(&mut fixture, timer);
}

#[test]
fn channel_dispatch_moves_a_reduced_right_event_and_receives_it() {
    let mut fixture = Fixture::new();
    let channel_rights = DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_TRANSFER.0);
    assert_eq!(
        fixture
            .handled(NativeSyscallRequest::ChannelCreate {
                requested_rights: channel_rights,
                out_endpoint0: DwUserAddress(BASE + 0x100),
                out_endpoint1: DwUserAddress(BASE + 0x108),
            })
            .status,
        DW_STATUS_SUCCESS
    );
    let sender = DwHandle(u64_at(&fixture.user, BASE + 0x100));
    let receiver = DwHandle(u64_at(&fixture.user, BASE + 0x108));

    let event_rights = DwRights(DW_RIGHT_WAIT.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0);
    assert_eq!(
        fixture
            .handled(NativeSyscallRequest::EventCreate {
                requested_rights: event_rights,
                out_event: DwUserAddress(BASE + 0x110),
            })
            .status,
        DW_STATUS_SUCCESS
    );
    let source = DwHandle(u64_at(&fixture.user, BASE + 0x110));
    write_handle_transfer(
        &mut fixture.user,
        BASE + 0x200,
        DwHandleTransferV1 {
            handle: source,
            requested_rights: DW_RIGHT_WAIT,
            operation: DW_HANDLE_TRANSFER_MOVE,
            reserved0: 0,
            reserved: [0; 2],
        },
    );
    fixture.user.bytes[FakeUserMemory::offset(BASE + 0x280, 1)] = 0x6b;

    assert_eq!(
        fixture
            .handled(NativeSyscallRequest::ChannelSend {
                channel: sender,
                bytes: DwUserAddress(BASE + 0x280),
                byte_len: 1,
                transfers: DwUserAddress(BASE + 0x200),
                transfer_count: 1,
                flags: 0,
            })
            .status,
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        fixture
            .tasks
            .process_handles(fixture.process)
            .unwrap()
            .inspect_basic(source),
        Err(HandleTableError::InvalidHandle)
    );

    assert_eq!(
        fixture
            .handled(NativeSyscallRequest::ChannelReceive {
                channel: receiver,
                out_bytes: DwUserAddress(BASE + 0x300),
                byte_capacity: 1,
                out_handles: DwUserAddress(BASE + 0x380),
                handle_capacity: 1,
                out_result: DwUserAddress(BASE + 0x400),
            })
            .status,
        DW_STATUS_SUCCESS
    );
    assert_eq!(
        fixture.user.bytes[FakeUserMemory::offset(BASE + 0x300, 1)],
        0x6b
    );
    let received = DwHandle(u64_at(&fixture.user, BASE + 0x380));
    assert_ne!(received, source);
    assert_eq!(u64_at(&fixture.user, BASE + 0x388), DW_RIGHT_WAIT.0);
    assert_eq!(u32_at(&fixture.user, BASE + 0x390), DW_OBJECT_TYPE_EVENT.0);
    assert_eq!(u32_at(&fixture.user, BASE + 0x400 + 8), 1);
    assert_eq!(u32_at(&fixture.user, BASE + 0x400 + 12), 1);
    assert_eq!(
        DW_CHANNEL_RECEIVE_RESULT_V1_SIZE,
        u32_at(&fixture.user, BASE + 0x400)
    );
    close_event(&mut fixture, received);
    close_channel(&mut fixture, sender);
    close_channel(&mut fixture, receiver);
}

#[test]
#[allow(
    unsafe_code,
    reason = "the fixture's running Thread is the physical carrier and the synthetic entry is fixed for this suspension test"
)]
fn finite_wait_dispatch_idles_times_out_and_resumes_exact_owner() {
    let mut fixture = Fixture::new();
    assert_eq!(
        fixture
            .handled(NativeSyscallRequest::EventCreate {
                requested_rights: DW_RIGHT_WAIT,
                out_event: DwUserAddress(BASE + 0x500),
            })
            .status,
        DW_STATUS_SUCCESS
    );
    let event = DwHandle(u64_at(&fixture.user, BASE + 0x500));
    let wait = fixture.handled(NativeSyscallRequest::WaitOne {
        handle: event,
        signals: DW_SIGNAL_SIGNALED,
        deadline: DwDeadline(50),
        out_result: DwUserAddress(BASE + 0x580),
    });
    assert_eq!(wait.status, DW_STATUS_SUCCESS);
    assert_eq!(
        wait.control,
        super::super::native::SyscallControl::SuspendCurrent
    );
    assert_eq!(
        fixture.services.operation_owner(fixture.thread),
        Ok(FServiceOperationOwner::GenericWait)
    );
    assert!(!fixture.services.is_quiescent());
    let wake = fixture
        .services
        .wait_operations
        .wake_key_for_thread(fixture.thread)
        .unwrap();
    assert!(matches!(
        unsafe {
            fixture.services.prepare_suspend(
                &mut fixture.control,
                &fixture.tasks,
                &fixture.execution,
                0xffff_8000_0012_3000,
            )
        }
        .unwrap(),
        NativeSuspendPlan::IdleCurrent
    ));
    let mut expired = [None; 8];
    assert_eq!(fixture.wait_deadlines.queue.expire(50, &mut expired), 1);
    assert_eq!(expired[0], Some(wake));
    assert!(claim_timeout_and_wake(&fixture.execution, wake).unwrap());
    assert!(matches!(
        unsafe {
            fixture.services.poll_idle_suspend(
                &mut fixture.control,
                &fixture.tasks,
                &fixture.execution,
                0xffff_8000_0012_3000,
            )
        }
        .unwrap(),
        NativeIdleSuspendPoll::ResumeCurrent
    ));
    let resumed = fixture
        .services
        .resume_suspended(
            &mut fixture.user,
            &mut fixture.registry,
            &mut fixture.tasks,
            &fixture.waits,
            &fixture.execution,
            fixture.thread,
            Some(&mut fixture.wait_deadlines),
        )
        .unwrap();
    let (status, cleanup) = resumed.into_parts();
    assert_eq!(status, DW_STATUS_TIMED_OUT);
    assert_empty_cleanup(cleanup);
    assert_eq!(
        fixture.services.operation_owner(fixture.thread),
        Err(FServiceOwnerError::Missing)
    );
    assert_eq!(fixture.user.owned_outputs, 0);
    assert!(fixture.control.is_clear());
    assert!(fixture.services.is_quiescent());
    assert_eq!(fixture.wait_deadlines.queue.earliest(), None);
    close_event(&mut fixture, event);
}

#[test]
#[allow(
    unsafe_code,
    reason = "the fixture's running Thread is the physical carrier and the synthetic entry is fixed for this suspension test"
)]
fn atomic_mismatch_then_suspend_wake_and_resume_has_one_exact_owner() {
    let mut fixture = Fixture::new();
    let key = stable_atomic_key(&mut fixture.registry);
    let address = DwUserAddress(BASE + 0x700);

    fixture.user.atomic_value = 6;
    let pin = fixture.user.pin_atomic_u32(address).unwrap();
    let mismatch = begin_atomic_wait(
        pin,
        key,
        7,
        WaitDeadline::Now,
        &fixture.services.atomic_waits,
        &mut fixture.tasks,
        &fixture.execution,
        &mut fixture.services.atomic_operations,
        None,
        crate::cpu::CpuIndex::BOOTSTRAP,
        fixture.process,
        fixture.thread,
        |pin| fixture.user.load_atomic_u32_acquire(pin),
    )
    .unwrap_or_else(|failure| panic!("atomic mismatch failed: {:?}", failure.error));
    let AtomicWaitBegin::Mismatch(pin) = mismatch else {
        panic!("mismatching atomic word unexpectedly blocked")
    };
    fixture.user.release_atomic_u32(pin);
    assert_eq!(fixture.user.atomic_pins, 0);

    fixture.user.atomic_value = 7;
    let pin = fixture.user.pin_atomic_u32(address).unwrap();
    let suspended = begin_atomic_wait(
        pin,
        key,
        7,
        WaitDeadline::Infinite,
        &fixture.services.atomic_waits,
        &mut fixture.tasks,
        &fixture.execution,
        &mut fixture.services.atomic_operations,
        None,
        crate::cpu::CpuIndex::BOOTSTRAP,
        fixture.process,
        fixture.thread,
        |pin| fixture.user.load_atomic_u32_acquire(pin),
    )
    .unwrap_or_else(|failure| panic!("atomic suspend failed: {:?}", failure.error));
    let AtomicWaitBegin::Suspended { wake, decision } = suspended else {
        panic!("matching infinite atomic wait did not suspend")
    };
    let accepted = fixture
        .control
        .accept(super::super::adapters::WaitSyscallAction::Suspended(
            super::super::adapters::WaitSuspendState::new(wake, decision),
        ));
    assert_eq!(
        accepted.control,
        super::super::native::SyscallControl::SuspendCurrent
    );
    assert_eq!(
        fixture.services.operation_owner(fixture.thread),
        Ok(FServiceOperationOwner::AtomicWait)
    );
    assert!(!fixture.services.is_quiescent());
    assert!(matches!(
        unsafe {
            fixture.services.prepare_suspend(
                &mut fixture.control,
                &fixture.tasks,
                &fixture.execution,
                0xffff_8000_0012_3000,
            )
        }
        .unwrap(),
        NativeSuspendPlan::IdleCurrent
    ));
    assert_eq!(
        wake_atomic_waiters(&fixture.services.atomic_waits, &fixture.execution, key, 1,).unwrap(),
        1
    );
    assert!(matches!(
        unsafe {
            fixture.services.poll_idle_suspend(
                &mut fixture.control,
                &fixture.tasks,
                &fixture.execution,
                0xffff_8000_0012_3000,
            )
        }
        .unwrap(),
        NativeIdleSuspendPoll::ResumeCurrent
    ));
    let resumed = fixture
        .services
        .resume_suspended(
            &mut fixture.user,
            &mut fixture.registry,
            &mut fixture.tasks,
            &fixture.waits,
            &fixture.execution,
            fixture.thread,
            None,
        )
        .unwrap();
    let (status, cleanup) = resumed.into_parts();
    assert_eq!(status, DW_STATUS_SUCCESS);
    assert_empty_cleanup(cleanup);
    assert_eq!(fixture.user.atomic_pins, 0);
    assert_eq!(
        fixture.services.operation_owner(fixture.thread),
        Err(FServiceOwnerError::Missing)
    );
    assert!(fixture.services.is_quiescent());
}

#[test]
fn process_create_dispatch_publishes_created_root_and_child_bootstrap() {
    let mut fixture = Fixture::new();
    let (_root, root_owner) = fixture
        .tasks
        .create_root_group(&mut fixture.registry)
        .unwrap();
    let (_group, group_reference) = fixture
        .tasks
        .create_child_group(&mut fixture.registry, &root_owner)
        .unwrap();
    let child_group = fixture
        .tasks
        .process_handles_mut(fixture.process)
        .unwrap()
        .install(
            group_reference,
            DwRights(DW_RIGHT_INSPECT.0 | DW_RIGHT_MODIFY.0),
        )
        .unwrap();
    assert!(
        fixture
            .registry
            .release_internal(root_owner)
            .unwrap()
            .is_none()
    );

    let bootstrap_rights =
        DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_TRANSFER.0 | DW_RIGHT_INSPECT.0);
    assert_eq!(
        fixture
            .handled(NativeSyscallRequest::ChannelCreate {
                requested_rights: bootstrap_rights,
                out_endpoint0: DwUserAddress(BASE + 0x800),
                out_endpoint1: DwUserAddress(BASE + 0x808),
            })
            .status,
        DW_STATUS_SUCCESS
    );
    let bootstrap = DwHandle(u64_at(&fixture.user, BASE + 0x800));
    let peer = DwHandle(u64_at(&fixture.user, BASE + 0x808));
    write_process_create_args(&mut fixture.user, BASE + 0x880, child_group, bootstrap);
    assert_eq!(
        fixture
            .handled(NativeSyscallRequest::ProcessCreate {
                args: DwUserAddress(BASE + 0x880),
                args_size: u64::from(DW_PROCESS_CREATE_ARGS_V1_SIZE),
                out_result: DwUserAddress(BASE + 0x900),
                result_size: u64::from(DW_PROCESS_CREATE_RESULT_V1_SIZE),
            })
            .status,
        DW_STATUS_SUCCESS
    );
    let process_handle = DwHandle(u64_at(&fixture.user, BASE + 0x908));
    let root_handle = DwHandle(u64_at(&fixture.user, BASE + 0x910));
    let child_bootstrap = DwHandle(u64_at(&fixture.user, BASE + 0x918));
    let process_pin = fixture
        .tasks
        .process_handles(fixture.process)
        .unwrap()
        .lookup(
            &mut fixture.registry,
            process_handle,
            AcceptedObjectTypes::One(deepwyrm_abi::DW_OBJECT_TYPE_PROCESS),
            DW_RIGHT_INSPECT,
        )
        .unwrap();
    let child = ProcessKey::from_object_id(process_pin.object_id());
    assert!(
        fixture
            .registry
            .release_internal(process_pin.into_internal())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fixture.tasks.process_info(child).unwrap().state,
        DW_TASK_STATE_CREATED
    );
    assert!(fixture.tasks.root_region(child).unwrap().is_some());
    assert_eq!(
        fixture
            .tasks
            .process_handles(fixture.process)
            .unwrap()
            .inspect_basic(root_handle)
            .unwrap()
            .object_type,
        deepwyrm_abi::DW_OBJECT_TYPE_ADDRESS_REGION
    );
    let child_pin = fixture
        .tasks
        .process_handles(child)
        .unwrap()
        .lookup(
            &mut fixture.registry,
            child_bootstrap,
            AcceptedObjectTypes::One(DW_OBJECT_TYPE_CHANNEL),
            DW_RIGHT_READ,
        )
        .unwrap();
    assert_eq!(child_pin.object_type(), DW_OBJECT_TYPE_CHANNEL);
    assert_eq!(child_pin.rights(), DW_RIGHT_READ);
    assert!(
        fixture
            .registry
            .release_internal(child_pin.into_internal())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fixture
            .tasks
            .process_handles(fixture.process)
            .unwrap()
            .inspect_basic(bootstrap),
        Err(HandleTableError::InvalidHandle)
    );

    let payload = b"ordinary-init0-channel-contract-datagram";
    assert_eq!(payload.len(), 40);
    let input = FakeUserMemory::offset(BASE + 0xa00, payload.len());
    fixture.user.bytes[input..input + payload.len()].copy_from_slice(payload);
    let mut cleanup = CleanupQueue::<OBJECTS>::new();
    assert_eq!(
        super::super::adapters::channel_send(
            &mut fixture.user,
            &mut fixture.staging,
            &mut fixture.registry,
            &fixture.channels,
            &fixture.waits,
            &mut fixture.tasks,
            &fixture.execution,
            fixture.process,
            peer,
            DwUserAddress(BASE + 0xa00),
            u32::try_from(payload.len()).unwrap(),
            DwUserAddress(0),
            0,
            0,
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_empty_cleanup(cleanup);

    let mut cleanup = CleanupQueue::<OBJECTS>::new();
    assert_eq!(
        super::super::adapters::channel_receive(
            &mut fixture.user,
            &mut fixture.staging,
            &mut fixture.registry,
            &fixture.channels,
            &fixture.waits,
            &mut fixture.tasks,
            &fixture.execution,
            child,
            child_bootstrap,
            DwUserAddress(BASE + 0xa80),
            u32::try_from(payload.len()).unwrap(),
            DwUserAddress(0),
            0,
            DwUserAddress(BASE + 0xb00),
            &mut cleanup,
        ),
        DW_STATUS_SUCCESS
    );
    assert_empty_cleanup(cleanup);
    let output = FakeUserMemory::offset(BASE + 0xa80, payload.len());
    assert_eq!(&fixture.user.bytes[output..output + payload.len()], payload);
    assert_eq!(u32_at(&fixture.user, BASE + 0xb00 + 8), 40);
    assert_eq!(u32_at(&fixture.user, BASE + 0xb00 + 12), 0);
    assert_eq!(u32_at(&fixture.user, BASE + 0xb00 + 16), 40);
    assert_eq!(u32_at(&fixture.user, BASE + 0xb00 + 20), 0);

    retire_created_process(
        &mut fixture,
        child,
        process_handle,
        root_handle,
        child_bootstrap,
        peer,
        child_group,
    );
}

#[test]
fn terminal_generic_and_atomic_cleanup_leave_the_service_quiescent() {
    let mut generic = Fixture::new();
    let (_event_key, event_reference) = generic.events.create_event(&mut generic.registry).unwrap();
    let event = generic
        .tasks
        .process_handles_mut(generic.process)
        .unwrap()
        .install(event_reference, DW_RIGHT_WAIT)
        .unwrap();
    let action = super::super::adapters::wait_one_syscall(
        &mut generic.user,
        &mut generic.registry,
        &mut generic.tasks,
        &generic.events,
        &generic.timers,
        &generic.channels,
        &generic.waits,
        &generic.execution,
        &mut generic.services.wait_operations,
        None,
        generic.process,
        generic.thread,
        event,
        DW_SIGNAL_SIGNALED,
        DW_DEADLINE_INFINITE,
        DwUserAddress(BASE + 0xa00),
    );
    assert!(matches!(
        action,
        super::super::adapters::WaitSyscallAction::Suspended(_)
    ));
    assert_eq!(
        generic.services.operation_owner(generic.thread),
        Ok(FServiceOperationOwner::GenericWait)
    );
    assert!(!generic.services.is_quiescent());
    let mut cleanup = CleanupQueue::<OBJECTS>::new();
    {
        let user = &mut generic.user;
        let mut terminal = generic.services.terminal_cleanup(
            None,
            |output| user.discard_owned_output(output),
            |_| panic!("generic terminal cleanup cannot own an atomic pin"),
        );
        terminal.cleanup_terminal_wait(
            &mut generic.registry,
            &mut generic.tasks,
            &generic.waits,
            &generic.execution,
            generic.thread,
            &mut cleanup,
        );
    }
    assert_empty_cleanup(cleanup);
    assert_eq!(generic.user.owned_outputs, 0);
    assert_eq!(
        generic.services.operation_owner(generic.thread),
        Err(FServiceOwnerError::Missing)
    );
    assert!(generic.services.is_quiescent());
    close_event(&mut generic, event);

    let mut atomic = Fixture::new();
    let key = stable_atomic_key(&mut atomic.registry);
    atomic.user.atomic_value = 9;
    let pin = atomic
        .user
        .pin_atomic_u32(DwUserAddress(BASE + 0xb00))
        .unwrap();
    let suspended = begin_atomic_wait(
        pin,
        key,
        9,
        WaitDeadline::Infinite,
        &atomic.services.atomic_waits,
        &mut atomic.tasks,
        &atomic.execution,
        &mut atomic.services.atomic_operations,
        None,
        crate::cpu::CpuIndex::BOOTSTRAP,
        atomic.process,
        atomic.thread,
        |pin| atomic.user.load_atomic_u32_acquire(pin),
    )
    .unwrap_or_else(|failure| panic!("terminal atomic setup failed: {:?}", failure.error));
    assert!(matches!(suspended, AtomicWaitBegin::Suspended { .. }));
    assert_eq!(
        atomic.services.operation_owner(atomic.thread),
        Ok(FServiceOperationOwner::AtomicWait)
    );
    assert!(!atomic.services.is_quiescent());
    let mut cleanup = CleanupQueue::<OBJECTS>::new();
    {
        let user = &mut atomic.user;
        let mut terminal = atomic.services.terminal_cleanup(
            None,
            |_| panic!("atomic terminal cleanup cannot own a userspace output"),
            |pin| user.release_atomic_u32(pin),
        );
        terminal.cleanup_terminal_wait(
            &mut atomic.registry,
            &mut atomic.tasks,
            &atomic.waits,
            &atomic.execution,
            atomic.thread,
            &mut cleanup,
        );
    }
    assert_empty_cleanup(cleanup);
    assert_eq!(atomic.user.atomic_pins, 0);
    assert_eq!(
        atomic.services.operation_owner(atomic.thread),
        Err(FServiceOwnerError::Missing)
    );
    assert!(atomic.services.is_quiescent());
    assert_eq!(
        atomic.execution.scheduler_state(atomic.thread),
        Some(SchedulerThreadState::Blocked)
    );
}

#[test]
fn terminal_cleanup_drains_two_atomic_waits_with_a_finite_deadline() {
    let mut registry = ObjectRegistry::<OBJECTS>::new();
    let mut tasks = Tasks::new();
    let (_root, root_owner) = tasks.create_root_group(&mut registry).unwrap();
    let (process, process_reference) = tasks.create_process(&mut registry, &root_owner).unwrap();
    let process_owner = registry
        .retain_internal_from_handle(&process_reference)
        .unwrap();
    let (first, first_reference) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    let (second, second_reference) = tasks.create_thread(&mut registry, &process_owner).unwrap();
    assert!(registry.release_handle(first_reference).unwrap().is_none());
    assert!(registry.release_handle(second_reference).unwrap().is_none());
    assert!(
        registry
            .release_handle(process_reference)
            .unwrap()
            .is_none()
    );
    assert!(registry.release_internal(process_owner).unwrap().is_none());
    assert!(registry.release_internal(root_owner).unwrap().is_none());

    let execution = ExecutionDomain::<EXECUTION>::new(test_stack_bounds()).unwrap();
    for (thread, seed) in [(first, 1_u64), (second, 2_u64)] {
        execution
            .start_thread(
                &mut tasks,
                thread,
                ThreadStartState::from_validated_user_state(
                    0x0000_0000_4000_0000 + seed * 0x1000,
                    0x0000_0000_5000_0000 + seed * 0x1000,
                    seed,
                    seed + 1,
                ),
            )
            .unwrap();
    }
    assert_eq!(execution.schedule_next().unwrap().current, Some(first));

    let mut services = Services::new();
    let mut user = FakeUserMemory::new();
    user.atomic_value = 0x77;
    let mut deadlines = TestWaitDeadlines::<2>::new();
    for (thread, address, deadline) in [
        (
            first,
            DwUserAddress(BASE + 0xc00),
            WaitDeadline::Finite(50_000),
        ),
        (second, DwUserAddress(BASE + 0xc04), WaitDeadline::Infinite),
    ] {
        let key = stable_atomic_key(&mut registry);
        let pin = user.pin_atomic_u32(address).unwrap();
        let suspended = begin_atomic_wait(
            pin,
            key,
            0x77,
            deadline,
            &services.atomic_waits,
            &mut tasks,
            &execution,
            &mut services.atomic_operations,
            Some(&mut deadlines),
            crate::cpu::CpuIndex::BOOTSTRAP,
            process,
            thread,
            |pin| user.load_atomic_u32_acquire(pin),
        )
        .unwrap_or_else(|failure| panic!("multi-atomic setup failed: {:?}", failure.error));
        let AtomicWaitBegin::Suspended { .. } = suspended else {
            panic!("matching atomic wait did not suspend")
        };
        if let Some(switched) = execution.suspended_claim_on(crate::cpu::CpuIndex::BOOTSTRAP) {
            assert_eq!(switched.thread(), thread);
            execution.complete_switch_on(switched).unwrap();
        }
    }
    assert_eq!(user.atomic_pins, 2);
    assert_eq!(
        services.operation_owner(first),
        Ok(FServiceOperationOwner::AtomicWait)
    );
    assert_eq!(
        services.operation_owner(second),
        Ok(FServiceOperationOwner::AtomicWait)
    );

    let waits = WaitRegistry::<WAITERS>::new();
    let mut cleanup = CleanupQueue::<OBJECTS>::new();
    {
        let mut terminal = services.terminal_cleanup(
            Some(&mut deadlines),
            |_| panic!("atomic terminal cleanup cannot own a userspace output"),
            |pin| user.release_atomic_u32(pin),
        );
        for thread in [first, second] {
            terminal.cleanup_terminal_wait(
                &mut registry,
                &mut tasks,
                &waits,
                &execution,
                thread,
                &mut cleanup,
            );
        }
    }
    assert_empty_cleanup(cleanup);
    assert_eq!(user.atomic_pins, 0);
    assert_eq!(deadlines.queue.earliest(), None);
    assert!(services.is_quiescent());
    assert!(!execution.blocked_operations().has_thread(first));
    assert!(!execution.blocked_operations().has_thread(second));
}

#[test]
fn prepared_dispatch_rejects_root_drift_before_usercopy_or_authority_borrow() {
    let fixture = Fixture::new();
    let prepared = fixture
        .services
        .prepare_dispatch(
            NativeSyscallRequest::ClockGet {
                clock_id: deepwyrm_abi::DW_CLOCK_BOOTTIME,
                out_nanoseconds: DwUserAddress(BASE),
            },
            fixture.thread,
            7,
        )
        .unwrap();
    assert!(matches!(
        prepared.begin(fixture.thread, 8),
        Err(FServiceDispatchPhaseError::IdentityDrift)
    ));
}
