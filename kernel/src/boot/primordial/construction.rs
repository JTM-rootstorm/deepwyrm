//! Single-owner DW0-G2 primordial construction coordinator.
//!
//! The backend is an authority adapter, not a second object model: production
//! adapters consume the existing prepared Task/AddressRegion, MemoryObject,
//! Channel/HandleTable, and execution tokens. Keeping those tokens behind one
//! mutable borrow prevents a partially built primordial process from escaping
//! while this module owns transaction order and rollback.

use deepwyrm_abi::{
    DW_OBJECT_TYPE_ADDRESS_REGION, DW_OBJECT_TYPE_MEMORY_OBJECT, DW_OBJECT_TYPE_TASK_GROUP,
    DW_RIGHT_DUPLICATE, DW_RIGHT_INSPECT, DW_RIGHT_MAP, DW_RIGHT_MODIFY, DW_RIGHT_READ,
    DW_RIGHT_TRANSFER, DW_RIGHT_WAIT, DW_RIGHT_WRITE, DwHandle, DwObjectType, DwRights,
};

use super::{PrimordialElfLoadPlan, PrimordialLoadSegment};

pub(crate) mod authority;

const PAGE_SIZE: u64 = 4096;
const USER_END_EXCLUSIVE: u64 = 0x0000_8000_0000_0000;
pub(crate) const STACK_BYTES: u64 = 128 * 1024;
const STARTUP_BLOCK_BYTES: usize = 4096;
const STARTUP_ABI_VERSION: u64 = 1;

const INIT_BYTES: [u8; 64] = [
    0x57, 0x52, 0x42, 0x50, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const RESOURCE_INIT_BYTES: [u8; 72] = [
    0x57, 0x52, 0x42, 0x50, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x48, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const READY_BYTES: [u8; 40] = [
    0x57, 0x52, 0x42, 0x50, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[cfg(any(
    test,
    deepwyrm_dw1d_evidence,
    deepwyrm_dw1e_evidence,
    deepwyrm_wyr1c_evidence,
    deepwyrm_wyr1d_evidence,
    deepwyrm_wyr1e_evidence,
    deepwyrm_r1_evidence,
))]
const RESOURCE_READY_BYTES: [u8; 40] = [
    0x57, 0x52, 0x42, 0x50, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

const CHILD_CHANNEL_RIGHTS: DwRights =
    DwRights(DW_RIGHT_READ.0 | DW_RIGHT_WRITE.0 | DW_RIGHT_WAIT.0 | DW_RIGHT_INSPECT.0);
const SELF_ROOT_RIGHTS: DwRights =
    DwRights(DW_RIGHT_MAP.0 | DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0);
const BOOTFS_RIGHTS: DwRights = DwRights(
    DW_RIGHT_READ.0
        | DW_RIGHT_MAP.0
        | DW_RIGHT_INSPECT.0
        | DW_RIGHT_DUPLICATE.0
        | DW_RIGHT_TRANSFER.0,
);
const LOADER_TASK_GROUP_RIGHTS: DwRights =
    DwRights(DW_RIGHT_MODIFY.0 | DW_RIGHT_INSPECT.0 | DW_RIGHT_DUPLICATE.0 | DW_RIGHT_TRANSFER.0);
const RESOURCE_DOMAIN_TASK_GROUP_RIGHTS: DwRights = DwRights(
    DW_RIGHT_MODIFY.0
        | DW_RIGHT_INSPECT.0
        | DW_RIGHT_DUPLICATE.0
        | DW_RIGHT_TRANSFER.0
        | deepwyrm_abi::DW_RIGHT_RESOURCE.0,
);

/// One exact capability descriptor transferred in `BOOTSTRAP_INIT_V1`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrimordialCapabilitySpec {
    pub(crate) role: u32,
    pub(crate) object_type: DwObjectType,
    pub(crate) rights: DwRights,
}

const INITIAL_CAPABILITIES: [PrimordialCapabilitySpec; 3] = [
    PrimordialCapabilitySpec {
        role: 1,
        object_type: DW_OBJECT_TYPE_ADDRESS_REGION,
        rights: SELF_ROOT_RIGHTS,
    },
    PrimordialCapabilitySpec {
        role: 2,
        object_type: DW_OBJECT_TYPE_MEMORY_OBJECT,
        rights: BOOTFS_RIGHTS,
    },
    PrimordialCapabilitySpec {
        role: 3,
        object_type: DW_OBJECT_TYPE_TASK_GROUP,
        rights: LOADER_TASK_GROUP_RIGHTS,
    },
];

const RESOURCE_INITIAL_CAPABILITIES: [PrimordialCapabilitySpec; 4] = [
    INITIAL_CAPABILITIES[0],
    INITIAL_CAPABILITIES[1],
    INITIAL_CAPABILITIES[2],
    PrimordialCapabilitySpec {
        role: 4,
        object_type: DW_OBJECT_TYPE_TASK_GROUP,
        rights: RESOURCE_DOMAIN_TASK_GROUP_RIGHTS,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrimordialInitProfile {
    Historical,
    ResourceDomain,
}

/// Deterministic guarded-stack placement and startup-block location.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrimordialStackLayout {
    pub(crate) guard_start: u64,
    pub(crate) mapped_start: u64,
    pub(crate) mapped_end_exclusive: u64,
    pub(crate) startup_block_start: u64,
}

/// Every fallible boundary inside the one G2 construction transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrimordialConstructionStage {
    ProcessRoot,
    SegmentObject(usize),
    SegmentMap(usize),
    StackObject,
    StackMap,
    StartupCopy,
    ChannelPair,
    ChildEndpointInstall,
    BootfsObject,
    CapabilityStaging,
    InitPublication,
    ThreadCreation,
    ThreadStartPreparation,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrimordialConstructionError<E> {
    BootstrapBytes,
    BootfsBytes,
    StackPlacement,
    InvalidBootstrapHandle,
    Injected(PrimordialConstructionStage),
    Backend {
        stage: PrimordialConstructionStage,
        error: E,
    },
}

/// Marker proving that the infallible publication boundary was crossed.
/// Linear monitor authority remains in the concrete backend until handoff.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PrimordialLaunch;

/// Existing-authority adapter consumed exclusively by the G2 coordinator.
pub(crate) trait PrimordialConstructionBackend {
    type Error;

    fn prepare_process_root(&mut self) -> Result<(), Self::Error>;
    fn create_segment_object(
        &mut self,
        index: usize,
        segment: PrimordialLoadSegment,
        initialized_offset: u64,
        initialized_bytes: &[u8],
    ) -> Result<(), Self::Error>;
    fn map_segment(
        &mut self,
        index: usize,
        segment: PrimordialLoadSegment,
    ) -> Result<(), Self::Error>;
    fn create_stack_object(&mut self, byte_len: u64) -> Result<(), Self::Error>;
    fn map_stack(&mut self, layout: PrimordialStackLayout) -> Result<(), Self::Error>;
    fn write_startup_block(
        &mut self,
        object_offset: u64,
        bytes: &[u8; STARTUP_BLOCK_BYTES],
    ) -> Result<(), Self::Error>;
    fn create_channel_pair(&mut self) -> Result<(), Self::Error>;
    fn install_child_channel(&mut self, rights: DwRights) -> Result<DwHandle, Self::Error>;
    fn create_bootfs_object(
        &mut self,
        logical_byte_len: u64,
        rounded_byte_len: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error>;
    fn stage_init_capabilities(
        &mut self,
        capabilities: &[PrimordialCapabilitySpec],
    ) -> Result<(), Self::Error>;
    fn publish_init(&mut self, bytes: &[u8]) -> Result<(), Self::Error>;
    fn create_initial_thread(
        &mut self,
        entry: u64,
        stack_pointer: u64,
        argument0: u64,
        argument1: u64,
    ) -> Result<(), Self::Error>;
    fn prepare_initial_thread_start(&mut self) -> Result<(), Self::Error>;

    /// Commits Process hierarchy and makes the prepared Thread runnable.
    /// Implementations consume only prior reservations and must not fail.
    fn commit_process_and_start(&mut self) -> PrimordialLaunch;

    /// Cancels every owned reservation/object in reverse dependency order.
    fn rollback(&mut self);
}

/// Builds the complete primordial process without crossing the externally
/// observable boundary until the final backend commit.
pub(crate) fn construct_primordial<B, I>(
    plan: &PrimordialElfLoadPlan,
    bootstrap: &[u8],
    bootfs: &[u8],
    backend: &mut B,
    inject: I,
) -> Result<PrimordialLaunch, PrimordialConstructionError<B::Error>>
where
    B: PrimordialConstructionBackend,
    I: FnMut(PrimordialConstructionStage) -> bool,
{
    construct_primordial_with_profile(
        plan,
        bootstrap,
        bootfs,
        PrimordialInitProfile::Historical,
        backend,
        inject,
    )
}

pub(crate) fn construct_primordial_with_profile<B, I>(
    plan: &PrimordialElfLoadPlan,
    bootstrap: &[u8],
    bootfs: &[u8],
    profile: PrimordialInitProfile,
    backend: &mut B,
    mut inject: I,
) -> Result<PrimordialLaunch, PrimordialConstructionError<B::Error>>
where
    B: PrimordialConstructionBackend,
    I: FnMut(PrimordialConstructionStage) -> bool,
{
    if bootstrap.is_empty() {
        return Err(PrimordialConstructionError::BootstrapBytes);
    }
    if bootfs.is_empty() {
        return Err(PrimordialConstructionError::BootfsBytes);
    }
    let layout = stack_layout(plan).ok_or(PrimordialConstructionError::StackPlacement)?;
    for index in 0..plan.segment_count() {
        let segment = plan
            .segment(index)
            .expect("validated plan segment count remains exact");
        if initialized_segment_bytes(segment, bootstrap).is_none() {
            return Err(PrimordialConstructionError::BootstrapBytes);
        }
    }
    let bootfs_len =
        u64::try_from(bootfs.len()).map_err(|_| PrimordialConstructionError::BootfsBytes)?;
    let rounded_bootfs =
        align_up(bootfs_len, PAGE_SIZE).ok_or(PrimordialConstructionError::BootfsBytes)?;

    step(
        backend,
        PrimordialConstructionStage::ProcessRoot,
        &mut inject,
        |backend| backend.prepare_process_root(),
    )?;
    for index in 0..plan.segment_count() {
        let segment = plan
            .segment(index)
            .expect("validated plan segment count remains exact");
        let initialized = initialized_segment_bytes(segment, bootstrap)
            .expect("construction inputs were preflighted before resource preparation");
        let initialized_offset = segment.virtual_start() - segment.page_start();
        step(
            backend,
            PrimordialConstructionStage::SegmentObject(index),
            &mut inject,
            |backend| {
                backend.create_segment_object(index, segment, initialized_offset, initialized)
            },
        )?;
    }
    for index in 0..plan.segment_count() {
        let segment = plan
            .segment(index)
            .expect("validated plan segment count remains exact");
        step(
            backend,
            PrimordialConstructionStage::SegmentMap(index),
            &mut inject,
            |backend| backend.map_segment(index, segment),
        )?;
    }
    step(
        backend,
        PrimordialConstructionStage::StackObject,
        &mut inject,
        |backend| backend.create_stack_object(STACK_BYTES),
    )?;
    step(
        backend,
        PrimordialConstructionStage::StackMap,
        &mut inject,
        |backend| backend.map_stack(layout),
    )?;
    let startup = startup_block(layout.startup_block_start);
    step(
        backend,
        PrimordialConstructionStage::StartupCopy,
        &mut inject,
        |backend| backend.write_startup_block(STACK_BYTES - STARTUP_BLOCK_BYTES as u64, &startup),
    )?;
    step(
        backend,
        PrimordialConstructionStage::ChannelPair,
        &mut inject,
        PrimordialConstructionBackend::create_channel_pair,
    )?;
    let bootstrap_handle = step_value(
        backend,
        PrimordialConstructionStage::ChildEndpointInstall,
        &mut inject,
        |backend| backend.install_child_channel(CHILD_CHANNEL_RIGHTS),
    )?;
    if bootstrap_handle.0 == 0 {
        backend.rollback();
        return Err(PrimordialConstructionError::InvalidBootstrapHandle);
    }
    step(
        backend,
        PrimordialConstructionStage::BootfsObject,
        &mut inject,
        |backend| backend.create_bootfs_object(bootfs_len, rounded_bootfs, bootfs),
    )?;
    step(
        backend,
        PrimordialConstructionStage::CapabilityStaging,
        &mut inject,
        |backend| match profile {
            PrimordialInitProfile::Historical => {
                backend.stage_init_capabilities(&INITIAL_CAPABILITIES)
            }
            PrimordialInitProfile::ResourceDomain => {
                backend.stage_init_capabilities(&RESOURCE_INITIAL_CAPABILITIES)
            }
        },
    )?;
    step(
        backend,
        PrimordialConstructionStage::InitPublication,
        &mut inject,
        |backend| match profile {
            PrimordialInitProfile::Historical => backend.publish_init(&INIT_BYTES),
            PrimordialInitProfile::ResourceDomain => backend.publish_init(&RESOURCE_INIT_BYTES),
        },
    )?;
    step(
        backend,
        PrimordialConstructionStage::ThreadCreation,
        &mut inject,
        |backend| {
            backend.create_initial_thread(
                plan.entry(),
                layout.startup_block_start,
                bootstrap_handle.0,
                STARTUP_ABI_VERSION,
            )
        },
    )?;
    step(
        backend,
        PrimordialConstructionStage::ThreadStartPreparation,
        &mut inject,
        PrimordialConstructionBackend::prepare_initial_thread_start,
    )?;
    Ok(backend.commit_process_and_start())
}

fn step<B, I, F>(
    backend: &mut B,
    stage: PrimordialConstructionStage,
    inject: &mut I,
    operation: F,
) -> Result<(), PrimordialConstructionError<B::Error>>
where
    B: PrimordialConstructionBackend,
    I: FnMut(PrimordialConstructionStage) -> bool,
    F: FnOnce(&mut B) -> Result<(), B::Error>,
{
    step_value(backend, stage, inject, operation)
}

fn step_value<B, I, F, T>(
    backend: &mut B,
    stage: PrimordialConstructionStage,
    inject: &mut I,
    operation: F,
) -> Result<T, PrimordialConstructionError<B::Error>>
where
    B: PrimordialConstructionBackend,
    I: FnMut(PrimordialConstructionStage) -> bool,
    F: FnOnce(&mut B) -> Result<T, B::Error>,
{
    let value = match operation(backend) {
        Ok(value) => value,
        Err(error) => {
            backend.rollback();
            return Err(PrimordialConstructionError::Backend { stage, error });
        }
    };
    if inject(stage) {
        backend.rollback();
        return Err(PrimordialConstructionError::Injected(stage));
    }
    Ok(value)
}

fn initialized_segment_bytes(segment: PrimordialLoadSegment, bootstrap: &[u8]) -> Option<&[u8]> {
    let file_start = usize::try_from(segment.file_offset()).ok()?;
    let file_len = usize::try_from(segment.file_byte_len()).ok()?;
    let file_end = file_start.checked_add(file_len)?;
    bootstrap.get(file_start..file_end)
}

fn stack_layout(plan: &PrimordialElfLoadPlan) -> Option<PrimordialStackLayout> {
    let mut mapped_end = USER_END_EXCLUSIVE;
    for _ in 0..=plan.segment_count() {
        let mapped_start = mapped_end.checked_sub(STACK_BYTES)?;
        let guard_start = mapped_start.checked_sub(PAGE_SIZE)?;
        if guard_start < PAGE_SIZE {
            return None;
        }
        let mut conflict_start: Option<u64> = None;
        for index in 0..plan.segment_count() {
            let segment = plan.segment(index)?;
            if guard_start < segment.page_end_exclusive() && segment.page_start() < mapped_end {
                conflict_start = Some(match conflict_start {
                    Some(current) => current.min(segment.page_start()),
                    None => segment.page_start(),
                });
            }
        }
        if let Some(conflict_start) = conflict_start {
            mapped_end = conflict_start;
            continue;
        }
        return Some(PrimordialStackLayout {
            guard_start,
            mapped_start,
            mapped_end_exclusive: mapped_end,
            startup_block_start: mapped_end - STARTUP_BLOCK_BYTES as u64,
        });
    }
    None
}

fn startup_block(start: u64) -> [u8; STARTUP_BLOCK_BYTES] {
    const STRING_OFFSET: usize = 48;
    const ARGUMENT: &[u8] = b"wyrmroot-bootstrap\0";
    let mut bytes = [0_u8; STARTUP_BLOCK_BYTES];
    for (index, value) in [1_u64, start + STRING_OFFSET as u64, 0, 0, 0, 0]
        .into_iter()
        .enumerate()
    {
        let offset = index * 8;
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }
    bytes[STRING_OFFSET..STRING_OFFSET + ARGUMENT.len()].copy_from_slice(ARGUMENT);
    bytes
}

const fn align_up(value: u64, alignment: u64) -> Option<u64> {
    match value.checked_add(alignment - 1) {
        Some(value) => Some(value & !(alignment - 1)),
        None => None,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrimordialExitDisposition {
    Normal(u32),
    UnhandledException,
    AuthorizedTermination,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrimordialCompletionError<E> {
    Receive(E),
    MalformedReady,
    ObserveExit(E),
    NonzeroExit(u32),
    UnhandledException,
    AuthorizedTermination,
    NotQuiescent(E),
}

/// Kernel-peer/structured-task adapter for the bounded G2 host gate.
pub(crate) trait PrimordialCompletionBackend {
    type Error;

    fn receive_ready(&mut self, output: &mut [u8; 40]) -> Result<usize, Self::Error>;
    fn observe_exit(&mut self) -> Result<PrimordialExitDisposition, Self::Error>;
    fn verify_quiescent(&mut self) -> Result<(), Self::Error>;
}

/// Consumes READY before structured exit disposition so a committed datagram
/// remains observable even when userspace immediately closes/exits.
pub(crate) fn complete_primordial_launch<B: PrimordialCompletionBackend>(
    backend: &mut B,
) -> Result<(), PrimordialCompletionError<B::Error>> {
    complete_primordial_launch_with_ready(backend, &READY_BYTES)
}

#[cfg(any(
    test,
    deepwyrm_dw1d_evidence,
    deepwyrm_dw1e_evidence,
    deepwyrm_wyr1c_evidence,
    deepwyrm_wyr1d_evidence,
    deepwyrm_wyr1e_evidence,
    deepwyrm_r1_evidence,
))]
pub(crate) fn complete_resource_primordial_launch<B: PrimordialCompletionBackend>(
    backend: &mut B,
) -> Result<(), PrimordialCompletionError<B::Error>> {
    complete_primordial_launch_with_ready(backend, &RESOURCE_READY_BYTES)
}

fn complete_primordial_launch_with_ready<B: PrimordialCompletionBackend>(
    backend: &mut B,
    expected_ready: &[u8; 40],
) -> Result<(), PrimordialCompletionError<B::Error>> {
    let mut bytes = [0_u8; 40];
    let ready = backend.receive_ready(&mut bytes);
    let exit = backend.observe_exit();
    let quiescent = backend.verify_quiescent();

    // Selector 34 reports quiescence last. Its permanent-supervisor product
    // failed run 4 on a quiescence invariant that erased the supervised child's
    // own terminal status, so for that selector alone the child-observable
    // facts are reported first and the kernel-side invariant afterwards. Every
    // other selector keeps the established quiescence-first precedence.
    #[cfg(not(deepwyrm_r1_evidence))]
    quiescent.map_err(PrimordialCompletionError::NotQuiescent)?;
    let actual = ready.map_err(PrimordialCompletionError::Receive)?;
    if actual != expected_ready.len() || bytes != *expected_ready {
        return Err(PrimordialCompletionError::MalformedReady);
    }
    let disposition = exit.map_err(PrimordialCompletionError::ObserveExit)?;
    match disposition {
        PrimordialExitDisposition::Normal(0) => {}
        PrimordialExitDisposition::Normal(code) => {
            return Err(PrimordialCompletionError::NonzeroExit(code));
        }
        PrimordialExitDisposition::UnhandledException => {
            return Err(PrimordialCompletionError::UnhandledException);
        }
        PrimordialExitDisposition::AuthorizedTermination => {
            return Err(PrimordialCompletionError::AuthorizedTermination);
        }
    }
    #[cfg(deepwyrm_r1_evidence)]
    quiescent.map_err(PrimordialCompletionError::NotQuiescent)?;
    Ok(())
}

/// Selector-local split of the primordial completion contract. This validates
/// the committed READY and structured zero exit without consuming the runtime
/// authority that a live permanent-supervisor descendant still requires.
#[cfg(any(
    test,
    deepwyrm_wyr1_evidence,
    deepwyrm_wyr1b_evidence,
    deepwyrm_wyr1c_evidence,
    deepwyrm_wyr1d_evidence,
    deepwyrm_wyr1e_evidence,
))]
pub(crate) fn validate_primordial_retirement_facts<B: PrimordialCompletionBackend>(
    backend: &mut B,
) -> Result<(), PrimordialCompletionError<B::Error>> {
    validate_primordial_retirement_facts_with_ready(backend, &READY_BYTES)
}

/// Selector-local retirement validation for the four-capability resource
/// primordial profile. This preserves the READY/exit split while requiring
/// the same profile-aware READY accepted by the initial construction path.
#[cfg(any(
    test,
    deepwyrm_wyr1c_evidence,
    deepwyrm_wyr1d_evidence,
    deepwyrm_wyr1e_evidence,
    deepwyrm_dw1e_evidence,
    deepwyrm_r1_evidence,
))]
pub(crate) fn validate_resource_primordial_retirement_facts<B: PrimordialCompletionBackend>(
    backend: &mut B,
) -> Result<(), PrimordialCompletionError<B::Error>> {
    validate_primordial_retirement_facts_with_ready(backend, &RESOURCE_READY_BYTES)
}

fn validate_primordial_retirement_facts_with_ready<B: PrimordialCompletionBackend>(
    backend: &mut B,
    expected_ready: &[u8; 40],
) -> Result<(), PrimordialCompletionError<B::Error>> {
    let mut bytes = [0_u8; 40];
    // Snapshot both facts before applying the established READY-first error
    // precedence. A failed receive must not erase the concurrent structured
    // Process disposition needed by selector-local failure diagnostics.
    let ready = backend.receive_ready(&mut bytes);
    let exit = backend.observe_exit();

    let actual = ready.map_err(PrimordialCompletionError::Receive)?;
    if actual != expected_ready.len() || bytes != *expected_ready {
        return Err(PrimordialCompletionError::MalformedReady);
    }
    match exit.map_err(PrimordialCompletionError::ObserveExit)? {
        PrimordialExitDisposition::Normal(0) => Ok(()),
        PrimordialExitDisposition::Normal(code) => {
            Err(PrimordialCompletionError::NonzeroExit(code))
        }
        PrimordialExitDisposition::UnhandledException => {
            Err(PrimordialCompletionError::UnhandledException)
        }
        PrimordialExitDisposition::AuthorizedTermination => {
            Err(PrimordialCompletionError::AuthorizedTermination)
        }
    }
}

#[cfg(test)]
mod tests;
