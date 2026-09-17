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

/// What `observe_exit` reported, carried beside a failure that is not itself
/// about the exit.
///
/// F3A.6t. Both completion paths compute the structured exit disposition
/// *before* applying READY-first error precedence, and then drop it when the
/// receive, the READY shape, or the quiescence invariant is what fails.
/// `validate_primordial_retirement_facts_with_ready` even carried a comment
/// saying it must not -- "a failed receive must not erase the concurrent
/// structured Process disposition" -- above code whose `?` erased it anyway.
/// The intent was documented and never implemented.
///
/// It matters because `WouldBlock` (F3A.6s, production) says only that
/// nothing was queued. Whether the bootstrap application never sent READY,
/// exited first, or faulted is the *next* question, and the answer was already
/// in a local three lines above the discard.
///
/// A failed `observe_exit` collapses to `Unobserved` rather than carrying its
/// own error. The primary cause already owns the detail field, and "no
/// disposition exists to report" is the whole of what a reader needs from a
/// secondary fact; `ObserveExit` carries the instance when the exit
/// observation is itself the failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrimordialExitObservation {
    /// `observe_exit` failed, so no disposition exists to report.
    Unobserved,
    /// The application exited with this status.
    Exited(u32),
    UnhandledException,
    AuthorizedTermination,
}

impl PrimordialExitObservation {
    fn observe<E>(exit: &Result<PrimordialExitDisposition, E>) -> Self {
        match exit {
            Err(_) => Self::Unobserved,
            Ok(PrimordialExitDisposition::Normal(code)) => Self::Exited(*code),
            Ok(PrimordialExitDisposition::UnhandledException) => Self::UnhandledException,
            Ok(PrimordialExitDisposition::AuthorizedTermination) => Self::AuthorizedTermination,
        }
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Unobserved => "unobserved",
            Self::Exited(_) => "exited",
            Self::UnhandledException => "unhandled-exception",
            Self::AuthorizedTermination => "authorized-termination",
        }
    }

    /// The exit status where one exists, and zero where the disposition is not
    /// a status. Read it only together with `name`.
    pub(crate) const fn code(self) -> u32 {
        match self {
            Self::Exited(code) => code,
            Self::Unobserved | Self::UnhandledException | Self::AuthorizedTermination => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrimordialCompletionError<E> {
    Receive(E, PrimordialExitObservation),
    MalformedReady(PrimordialExitObservation),
    ObserveExit(E),
    NonzeroExit(u32),
    UnhandledException,
    AuthorizedTermination,
    NotQuiescent(E, PrimordialExitObservation),
}

/// How a backend error renders as the one number a boot transcript carries.
///
/// F3A.6s. `completion_record` reports a single `u32` detail beside its cause
/// name, so every `PrimordialCompletionBackend::Error` used with it must say
/// what that number is. The only non-test backend's error *is* a `u32` of
/// structured cause codes (`primordial_channel_receive_error`), so that impl
/// is the identity; the trait exists so a richer error type has to answer the
/// question rather than defaulting to zero.
pub(crate) trait PrimordialCompletionDetail {
    fn completion_detail(&self) -> u32;
}

impl PrimordialCompletionDetail for u32 {
    fn completion_detail(&self) -> u32 {
        *self
    }
}

/// One completion, as the reader's channel receives it.
///
/// F3A.6t widened this from a tuple. `exit` is `Some` exactly when the
/// reported cause is *not* itself the exit -- a receive failure, a malformed
/// READY, or a quiescence failure -- and carries the disposition those paths
/// used to discard. It is `None` when the cause already *is* the exit
/// (`ObserveExit`, `NonzeroExit`, `UnhandledException`,
/// `AuthorizedTermination`) or when there is no failure, because a second
/// rendering of the same fact would be noise rather than carriage.
pub(crate) struct BootstrapCompletionRecord {
    pub(crate) level: crate::debug::DiagnosticLevel,
    pub(crate) cause: &'static str,
    pub(crate) detail: u32,
    pub(crate) exit: Option<PrimordialExitObservation>,
}

/// One completion, as a diagnostic level, a cause name and a number.
///
/// F3A.6q. The production arm of the x86_64 primordial completion handler read
/// `Err(_)` over this enum and emitted one sentence for six of its seven
/// variants, at the last diagnostic boundary in the boot -- that arm emits and
/// then halts in `sti; hlt`, so nothing downstream can recover what it drops.
/// `DIAGNOSTIC_CAUSE_CARRIAGE_CONTRACT.md` §3.3 requires a diagnostic boundary
/// to preserve the instance, and an instrumented build already did: the same
/// value reached `G5PrimordialProbe::failure_detail`, which is exhaustive and
/// returns the exit code. A production build got prose. That asymmetry is why
/// the F3A campaign diagnosed the instrumented sibling for nine revisions
/// while the production product's own failure stayed one sentence.
///
/// It lives beside the error rather than beside the emitter deliberately. The
/// mapping is a property of this enum, not of an architecture, and
/// `arch::x86_64::mm::activation::primordial` is compiled only for an
/// integrated target build -- so a mapping placed there could not be tested at
/// all, and dropping the exit code would have turned no test red. Here it is
/// exercised by `completion_records_name_every_variant_and_keep_the_exit_code`.
///
/// The match is exhaustive rather than defaulting, so a new variant fails to
/// compile instead of inheriting a name it has not earned. The numbers match
/// `failure_detail`'s so an instrumented and a production transcript agree.
///
/// The three variants carrying a backend error render that payload through
/// `PrimordialCompletionDetail`, so `ready-not-received` names *why* the
/// receive failed rather than reporting a zero.
///
/// F3A.6s corrects F3A.6q on this point. That revision left the payload
/// unrendered on the stated grounds that its type "varies with the build --
/// `u32` on the resource path, `LiveUserAccessError` on the live one". That
/// was wrong, and wrong in a way worth recording: `LiveUserAccessError` is
/// `PrimordialPlatform::Error`, a *different* trait describing userspace
/// memory access. The payload here is `PrimordialCompletionBackend::Error`,
/// and that trait has exactly one non-test implementation -- `type Error =
/// u32` on `PrimordialRuntimeCarrier`. There was never a second type to write
/// a mapping for. The claim came from reading two `type Error` lines in one
/// file without checking which trait each belonged to.
///
/// The zero also made the neighbouring claim that these numbers match
/// `failure_detail`'s false for precisely these three variants: that mapping
/// is declared over `PrimordialCompletionError<u32>` and returns `*detail`
/// for each. This restores the agreement the doc comment already asserted.
///
/// The bound is a trait rather than a `u32` field because it keeps the
/// obligation on the enum: a future backend carrying a richer error cannot be
/// used here until it says how it renders as one number, instead of silently
/// inheriting a zero.
pub(crate) fn completion_record<E: PrimordialCompletionDetail>(
    completion: &Result<(), PrimordialCompletionError<E>>,
) -> BootstrapCompletionRecord {
    use crate::debug::DiagnosticLevel;

    match completion {
        Ok(()) => BootstrapCompletionRecord {
            level: DiagnosticLevel::Info,
            cause: "completed normally",
            detail: 0,
            exit: None,
        },
        Err(PrimordialCompletionError::Receive(error, exit)) => BootstrapCompletionRecord {
            level: DiagnosticLevel::Error,
            cause: "ready-not-received",
            detail: error.completion_detail(),
            exit: Some(*exit),
        },
        Err(PrimordialCompletionError::MalformedReady(exit)) => BootstrapCompletionRecord {
            level: DiagnosticLevel::Error,
            cause: "ready-malformed",
            detail: 3,
            exit: Some(*exit),
        },
        Err(PrimordialCompletionError::ObserveExit(error)) => BootstrapCompletionRecord {
            level: DiagnosticLevel::Error,
            cause: "exit-not-observed",
            detail: error.completion_detail(),
            exit: None,
        },
        // The one variant whose payload is unconditionally numeric, and the
        // one worth the most: this is the userspace application status, which
        // for a WYR1 product is the whole `0xAF..` failure encoding the F3A
        // campaign spent nine revisions building.
        Err(PrimordialCompletionError::NonzeroExit(code)) => BootstrapCompletionRecord {
            level: DiagnosticLevel::Error,
            cause: "nonzero-exit",
            detail: *code,
            exit: None,
        },
        Err(PrimordialCompletionError::UnhandledException) => BootstrapCompletionRecord {
            level: DiagnosticLevel::Error,
            cause: "unhandled-exception",
            detail: 5,
            exit: None,
        },
        Err(PrimordialCompletionError::AuthorizedTermination) => BootstrapCompletionRecord {
            level: DiagnosticLevel::Error,
            cause: "authorized-termination",
            detail: 6,
            exit: None,
        },
        Err(PrimordialCompletionError::NotQuiescent(error, exit)) => BootstrapCompletionRecord {
            level: DiagnosticLevel::Error,
            cause: "not-quiescent",
            detail: error.completion_detail(),
            exit: Some(*exit),
        },
    }
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
    // F3A.6t. Snapshot the disposition before precedence consumes `exit`, so
    // a receive, READY-shape or quiescence failure reports what the
    // application did instead of erasing it.
    let observation = PrimordialExitObservation::observe(&exit);

    // Selector 34 reports quiescence last. Its permanent-supervisor product
    // failed run 4 on a quiescence invariant that erased the supervised child's
    // own terminal status, so for that selector alone the child-observable
    // facts are reported first and the kernel-side invariant afterwards. Every
    // other selector keeps the established quiescence-first precedence.
    #[cfg(not(deepwyrm_r1_evidence))]
    quiescent.map_err(|error| PrimordialCompletionError::NotQuiescent(error, observation))?;
    let actual = ready.map_err(|error| PrimordialCompletionError::Receive(error, observation))?;
    if actual != expected_ready.len() || bytes != *expected_ready {
        return Err(PrimordialCompletionError::MalformedReady(observation));
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
    quiescent.map_err(|error| PrimordialCompletionError::NotQuiescent(error, observation))?;
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
    // F3A.6t makes the comment above true. It claimed a failed receive must
    // not erase the concurrent disposition; until this revision the `?` below
    // erased it regardless.
    let observation = PrimordialExitObservation::observe(&exit);

    let actual = ready.map_err(|error| PrimordialCompletionError::Receive(error, observation))?;
    if actual != expected_ready.len() || bytes != *expected_ready {
        return Err(PrimordialCompletionError::MalformedReady(observation));
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
