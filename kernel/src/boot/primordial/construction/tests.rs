extern crate std;

use std::vec;
use std::vec::Vec;

use super::*;
use crate::boot::primordial::PrimordialSegmentPermissions;
use crate::boot::primordial::parse_primordial_elf;

const ELF_HEADER_SIZE: usize = 64;
const PROGRAM_HEADER_SIZE: usize = 56;

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn program_header(
    bytes: &mut [u8],
    index: usize,
    flags: u32,
    file_offset: u64,
    virtual_start: u64,
    file_byte_len: u64,
    memory_byte_len: u64,
) {
    let offset = ELF_HEADER_SIZE + index * PROGRAM_HEADER_SIZE;
    put_u32(bytes, offset, 1);
    put_u32(bytes, offset + 4, flags);
    put_u64(bytes, offset + 8, file_offset);
    put_u64(bytes, offset + 16, virtual_start);
    put_u64(bytes, offset + 32, file_byte_len);
    put_u64(bytes, offset + 40, memory_byte_len);
    put_u64(bytes, offset + 48, PAGE_SIZE);
}

pub(super) fn elf_fixture() -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x3000];
    bytes[..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    put_u16(&mut bytes, 16, 2);
    put_u16(&mut bytes, 18, 62);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 24, 0x401000);
    put_u64(&mut bytes, 32, ELF_HEADER_SIZE as u64);
    put_u16(&mut bytes, 52, ELF_HEADER_SIZE as u16);
    put_u16(&mut bytes, 54, PROGRAM_HEADER_SIZE as u16);
    put_u16(&mut bytes, 56, 2);
    program_header(&mut bytes, 0, 5, 0x1000, 0x401000, 4, 0x1000);
    program_header(&mut bytes, 1, 6, 0x2000, 0x402000, 8, 0x1000);
    bytes[0x1000..0x1004].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);
    bytes[0x2000..0x2008].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    bytes
}

#[derive(Debug)]
struct HostBackend {
    live_resources: usize,
    completed: Vec<PrimordialConstructionStage>,
    fail_at: Option<PrimordialConstructionStage>,
    rolled_back: bool,
    committed: bool,
    handle: DwHandle,
    stack_object_bytes: Option<u64>,
    stack_layout: Option<PrimordialStackLayout>,
    startup_object_offset: Option<u64>,
    startup: Option<[u8; STARTUP_BLOCK_BYTES]>,
    capabilities: Option<Vec<PrimordialCapabilitySpec>>,
    init: Option<Vec<u8>>,
    start: Option<[u64; 4]>,
}

impl HostBackend {
    fn new(handle: u64) -> Self {
        Self {
            live_resources: 0,
            completed: Vec::new(),
            fail_at: None,
            rolled_back: false,
            committed: false,
            handle: DwHandle(handle),
            stack_object_bytes: None,
            stack_layout: None,
            startup_object_offset: None,
            startup: None,
            capabilities: None,
            init: None,
            start: None,
        }
    }

    fn boundary(&mut self, stage: PrimordialConstructionStage) -> Result<(), &'static str> {
        if self.fail_at == Some(stage) {
            return Err("injected backend failure");
        }
        self.completed.push(stage);
        self.live_resources += 1;
        Ok(())
    }
}

impl PrimordialConstructionBackend for HostBackend {
    type Error = &'static str;

    fn prepare_process_root(&mut self) -> Result<(), Self::Error> {
        self.boundary(PrimordialConstructionStage::ProcessRoot)
    }

    fn create_segment_object(
        &mut self,
        index: usize,
        segment: PrimordialLoadSegment,
        initialized_offset: u64,
        initialized_bytes: &[u8],
    ) -> Result<(), Self::Error> {
        assert_eq!(
            initialized_offset,
            segment.virtual_start() - segment.page_start()
        );
        assert_eq!(initialized_bytes.len() as u64, segment.file_byte_len());
        assert!(segment.mapped_byte_len() >= segment.memory_byte_len());
        self.boundary(PrimordialConstructionStage::SegmentObject(index))
    }

    fn map_segment(
        &mut self,
        index: usize,
        segment: PrimordialLoadSegment,
    ) -> Result<(), Self::Error> {
        let permissions: PrimordialSegmentPermissions = segment.permissions();
        assert!(!(permissions.writable() && permissions.executable()));
        self.boundary(PrimordialConstructionStage::SegmentMap(index))
    }

    fn create_stack_object(&mut self, byte_len: u64) -> Result<(), Self::Error> {
        assert_eq!(byte_len, STACK_BYTES);
        self.stack_object_bytes = Some(byte_len);
        self.boundary(PrimordialConstructionStage::StackObject)
    }

    fn map_stack(&mut self, layout: PrimordialStackLayout) -> Result<(), Self::Error> {
        assert_eq!(layout.mapped_start - layout.guard_start, PAGE_SIZE);
        assert_eq!(
            layout.mapped_end_exclusive - layout.mapped_start,
            STACK_BYTES
        );
        self.stack_layout = Some(layout);
        self.boundary(PrimordialConstructionStage::StackMap)
    }

    fn write_startup_block(
        &mut self,
        object_offset: u64,
        bytes: &[u8; STARTUP_BLOCK_BYTES],
    ) -> Result<(), Self::Error> {
        assert_eq!(object_offset, STACK_BYTES - STARTUP_BLOCK_BYTES as u64);
        self.startup_object_offset = Some(object_offset);
        self.startup = Some(*bytes);
        self.boundary(PrimordialConstructionStage::StartupCopy)
    }

    fn create_channel_pair(&mut self) -> Result<(), Self::Error> {
        self.boundary(PrimordialConstructionStage::ChannelPair)
    }

    fn install_child_channel(&mut self, rights: DwRights) -> Result<DwHandle, Self::Error> {
        assert_eq!(rights, CHILD_CHANNEL_RIGHTS);
        self.boundary(PrimordialConstructionStage::ChildEndpointInstall)?;
        Ok(self.handle)
    }

    fn create_bootfs_object(
        &mut self,
        logical_byte_len: u64,
        rounded_byte_len: u64,
        bytes: &[u8],
    ) -> Result<(), Self::Error> {
        assert_eq!(logical_byte_len, bytes.len() as u64);
        assert!(rounded_byte_len >= logical_byte_len);
        assert!(rounded_byte_len.is_multiple_of(PAGE_SIZE));
        self.boundary(PrimordialConstructionStage::BootfsObject)
    }

    fn stage_init_capabilities(
        &mut self,
        capabilities: &[PrimordialCapabilitySpec],
    ) -> Result<(), Self::Error> {
        self.capabilities = Some(capabilities.to_vec());
        self.boundary(PrimordialConstructionStage::CapabilityStaging)
    }

    fn publish_init(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.init = Some(bytes.to_vec());
        self.boundary(PrimordialConstructionStage::InitPublication)
    }

    fn create_initial_thread(
        &mut self,
        entry: u64,
        stack_pointer: u64,
        argument0: u64,
        argument1: u64,
    ) -> Result<(), Self::Error> {
        self.start = Some([entry, stack_pointer, argument0, argument1]);
        self.boundary(PrimordialConstructionStage::ThreadCreation)
    }

    fn prepare_initial_thread_start(&mut self) -> Result<(), Self::Error> {
        self.boundary(PrimordialConstructionStage::ThreadStartPreparation)
    }

    fn commit_process_and_start(&mut self) -> PrimordialLaunch {
        self.committed = true;
        PrimordialLaunch
    }

    fn rollback(&mut self) {
        self.rolled_back = true;
        self.live_resources = 0;
        self.stack_object_bytes = None;
        self.stack_layout = None;
        self.startup_object_offset = None;
        self.startup = None;
        self.capabilities = None;
        self.init = None;
        self.start = None;
    }
}

pub(super) fn stages() -> Vec<PrimordialConstructionStage> {
    vec![
        PrimordialConstructionStage::ProcessRoot,
        PrimordialConstructionStage::SegmentObject(0),
        PrimordialConstructionStage::SegmentObject(1),
        PrimordialConstructionStage::SegmentMap(0),
        PrimordialConstructionStage::SegmentMap(1),
        PrimordialConstructionStage::StackObject,
        PrimordialConstructionStage::StackMap,
        PrimordialConstructionStage::StartupCopy,
        PrimordialConstructionStage::ChannelPair,
        PrimordialConstructionStage::ChildEndpointInstall,
        PrimordialConstructionStage::BootfsObject,
        PrimordialConstructionStage::CapabilityStaging,
        PrimordialConstructionStage::InitPublication,
        PrimordialConstructionStage::ThreadCreation,
        PrimordialConstructionStage::ThreadStartPreparation,
    ]
}

#[test]
fn locked_protocol_vectors_are_exact() {
    let expected_init = [
        0x57, 0x52, 0x42, 0x50, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x40, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    let expected_ready = [
        0x57, 0x52, 0x42, 0x50, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    let expected_resource_ready = [
        0x57, 0x52, 0x42, 0x50, 0x01, 0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(INIT_BYTES, expected_init);
    assert_eq!(READY_BYTES, expected_ready);
    assert_eq!(RESOURCE_READY_BYTES, expected_resource_ready);
}

#[test]
fn constructs_exact_startup_init_and_capability_contract_before_commit() {
    let elf = elf_fixture();
    let plan = parse_primordial_elf(&elf).unwrap();
    let mut backend = HostBackend::new(0x1_0000_0001);
    let launch = construct_primordial(&plan, &elf, b"bootfs", &mut backend, |_| false).unwrap();

    assert_eq!(backend.completed, stages());
    assert!(backend.committed);
    assert!(!backend.rolled_back);
    assert_eq!(launch, PrimordialLaunch);
    assert_eq!(backend.init, Some(INIT_BYTES.to_vec()));
    assert_eq!(backend.capabilities, Some(INITIAL_CAPABILITIES.to_vec()));
    assert_eq!(
        INITIAL_CAPABILITIES,
        [
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
        ]
    );
    let start = backend.start.unwrap();
    assert_eq!(start[0], plan.entry());
    assert_eq!(start[2], backend.handle.0);
    assert_eq!(start[3], STARTUP_ABI_VERSION);
    assert!(start[1].is_multiple_of(16));

    assert_eq!(STACK_BYTES, 128 * 1024);
    assert_eq!(backend.stack_object_bytes, Some(128 * 1024));
    let stack_layout = backend.stack_layout.unwrap();
    assert_eq!(
        stack_layout,
        PrimordialStackLayout {
            guard_start: 0x0000_7fff_fffd_f000,
            mapped_start: 0x0000_7fff_fffe_0000,
            mapped_end_exclusive: 0x0000_8000_0000_0000,
            startup_block_start: 0x0000_7fff_ffff_f000,
        }
    );
    assert_eq!(stack_layout.mapped_start - stack_layout.guard_start, 4096);
    assert_eq!(
        stack_layout.mapped_end_exclusive - stack_layout.mapped_start,
        128 * 1024
    );
    assert_eq!(backend.startup_object_offset, Some(124 * 1024));
    assert_eq!(start[1], stack_layout.startup_block_start);

    let startup = backend.startup.unwrap();
    assert_eq!(u64::from_le_bytes(startup[0..8].try_into().unwrap()), 1);
    assert_eq!(
        u64::from_le_bytes(startup[8..16].try_into().unwrap()),
        start[1] + 48
    );
    assert_eq!(&startup[48..67], b"wyrmroot-bootstrap\0");
    assert!(startup[67..].iter().all(|byte| *byte == 0));
}

#[test]
fn resource_domain_profile_adds_one_exact_role_without_changing_historical_init() {
    let elf = elf_fixture();
    let plan = parse_primordial_elf(&elf).unwrap();
    let mut backend = HostBackend::new(0x1_0000_0011);
    construct_primordial_with_profile(
        &plan,
        &elf,
        b"bootfs",
        PrimordialInitProfile::ResourceDomain,
        &mut backend,
        |_| false,
    )
    .unwrap();

    assert_eq!(backend.init, Some(RESOURCE_INIT_BYTES.to_vec()));
    assert_eq!(
        backend.capabilities,
        Some(RESOURCE_INITIAL_CAPABILITIES.to_vec())
    );
    assert_eq!(RESOURCE_INIT_BYTES.len(), 72);
    assert_eq!(&RESOURCE_INIT_BYTES[..4], b"WRBP");
    assert_eq!(&RESOURCE_INIT_BYTES[4..8], &[1, 0, 2, 0]);
    assert_eq!(&RESOURCE_INIT_BYTES[16..20], &72_u32.to_le_bytes());
    assert_eq!(&RESOURCE_INIT_BYTES[20..24], &4_u32.to_le_bytes());
    assert_eq!(&RESOURCE_INIT_BYTES[64..68], &4_u32.to_le_bytes());
    assert_eq!(
        RESOURCE_INITIAL_CAPABILITIES[3],
        PrimordialCapabilitySpec {
            role: 4,
            object_type: DW_OBJECT_TYPE_TASK_GROUP,
            rights: RESOURCE_DOMAIN_TASK_GROUP_RIGHTS,
        }
    );
    assert_eq!(INIT_BYTES.len(), 64);
    assert_eq!(INITIAL_CAPABILITIES.len(), 3);
}

#[test]
fn mismatched_bootstrap_bytes_fail_before_resource_preparation() {
    let elf = elf_fixture();
    let plan = parse_primordial_elf(&elf).unwrap();
    let first = plan.segment(0).unwrap();
    let truncated_len = usize::try_from(first.file_offset()).unwrap();
    let mut backend = HostBackend::new(7);

    assert_eq!(
        construct_primordial(
            &plan,
            &elf[..truncated_len],
            b"bootfs",
            &mut backend,
            |_| false,
        ),
        Err(PrimordialConstructionError::BootstrapBytes)
    );
    assert!(backend.completed.is_empty());
    assert_eq!(backend.live_resources, 0);
    assert!(!backend.committed);
    assert!(!backend.rolled_back);
}

#[test]
fn every_post_boundary_injection_rolls_back_to_zero_resources() {
    let elf = elf_fixture();
    let plan = parse_primordial_elf(&elf).unwrap();
    for stage in stages() {
        let mut backend = HostBackend::new(7);
        let error = construct_primordial(&plan, &elf, b"bootfs", &mut backend, |candidate| {
            candidate == stage
        })
        .unwrap_err();
        assert_eq!(error, PrimordialConstructionError::Injected(stage));
        assert!(backend.rolled_back, "stage {stage:?} skipped rollback");
        assert_eq!(backend.live_resources, 0, "stage {stage:?} leaked capacity");
        assert!(!backend.committed, "stage {stage:?} crossed commit");
    }
}

#[test]
fn every_backend_failure_rolls_back_without_crossing_commit() {
    let elf = elf_fixture();
    let plan = parse_primordial_elf(&elf).unwrap();
    for stage in stages() {
        let mut backend = HostBackend::new(9);
        backend.fail_at = Some(stage);
        let error =
            construct_primordial(&plan, &elf, b"bootfs", &mut backend, |_| false).unwrap_err();
        assert_eq!(
            error,
            PrimordialConstructionError::Backend {
                stage,
                error: "injected backend failure",
            }
        );
        assert!(backend.rolled_back);
        assert_eq!(backend.live_resources, 0);
        assert!(!backend.committed);
    }
}

#[test]
fn child_bootstrap_handles_are_opaque_and_need_not_repeat() {
    let elf = elf_fixture();
    let plan = parse_primordial_elf(&elf).unwrap();
    let mut first = HostBackend::new(0x1_0000_0001);
    let mut second = HostBackend::new(0x2_0000_0001);
    construct_primordial(&plan, &elf, b"bootfs", &mut first, |_| false).unwrap();
    construct_primordial(&plan, &elf, b"bootfs", &mut second, |_| false).unwrap();
    assert_ne!(first.start.unwrap()[2], second.start.unwrap()[2]);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionFailure {
    Receive,
    Exit,
    Quiescence,
}

struct CompletionHost {
    ready: Result<Vec<u8>, CompletionFailure>,
    exit: Result<PrimordialExitDisposition, CompletionFailure>,
    quiescent: Result<(), CompletionFailure>,
    observed_exit: bool,
    verified_quiescence: bool,
}

impl PrimordialCompletionBackend for CompletionHost {
    type Error = CompletionFailure;

    fn receive_ready(&mut self, output: &mut [u8; 40]) -> Result<usize, Self::Error> {
        let bytes = self.ready.as_ref().map_err(|error| *error)?;
        let copied = bytes.len().min(output.len());
        output[..copied].copy_from_slice(&bytes[..copied]);
        Ok(bytes.len())
    }

    fn observe_exit(&mut self) -> Result<PrimordialExitDisposition, Self::Error> {
        self.observed_exit = true;
        self.exit
    }

    fn verify_quiescent(&mut self) -> Result<(), Self::Error> {
        self.verified_quiescence = true;
        self.quiescent
    }
}

fn completion_host(exit: PrimordialExitDisposition) -> CompletionHost {
    CompletionHost {
        ready: Ok(READY_BYTES.to_vec()),
        exit: Ok(exit),
        quiescent: Ok(()),
        observed_exit: false,
        verified_quiescence: false,
    }
}

#[test]
fn committed_ready_is_consumed_before_normal_exit_and_quiescence() {
    let mut host = completion_host(PrimordialExitDisposition::Normal(0));
    complete_primordial_launch(&mut host).unwrap();
    assert!(host.observed_exit);
    assert!(host.verified_quiescence);

    let mut malformed = completion_host(PrimordialExitDisposition::Normal(0));
    malformed.ready = Ok(vec![0; 40]);
    assert_eq!(
        complete_primordial_launch(&mut malformed),
        Err(PrimordialCompletionError::MalformedReady)
    );
    assert!(malformed.observed_exit);
    assert!(malformed.verified_quiescence);
}

#[test]
fn resource_completion_requires_v3_ready_without_widening_v2() {
    let mut resource = completion_host(PrimordialExitDisposition::Normal(0));
    resource.ready = Ok(RESOURCE_READY_BYTES.to_vec());
    complete_resource_primordial_launch(&mut resource).unwrap();

    let mut historical = completion_host(PrimordialExitDisposition::Normal(0));
    assert_eq!(
        complete_resource_primordial_launch(&mut historical),
        Err(PrimordialCompletionError::MalformedReady)
    );

    let mut resource_on_historical = completion_host(PrimordialExitDisposition::Normal(0));
    resource_on_historical.ready = Ok(RESOURCE_READY_BYTES.to_vec());
    assert_eq!(
        complete_primordial_launch(&mut resource_on_historical),
        Err(PrimordialCompletionError::MalformedReady)
    );
}

#[test]
fn completion_rejects_peer_failure_exception_nonzero_exit_and_residue() {
    let mut peer_closed = completion_host(PrimordialExitDisposition::Normal(0));
    peer_closed.ready = Err(CompletionFailure::Receive);
    assert_eq!(
        complete_primordial_launch(&mut peer_closed),
        Err(PrimordialCompletionError::Receive(
            CompletionFailure::Receive
        ))
    );
    assert!(peer_closed.observed_exit);
    assert!(peer_closed.verified_quiescence);

    for (exit, expected) in [
        (
            PrimordialExitDisposition::Normal(7),
            PrimordialCompletionError::NonzeroExit(7),
        ),
        (
            PrimordialExitDisposition::UnhandledException,
            PrimordialCompletionError::UnhandledException,
        ),
        (
            PrimordialExitDisposition::AuthorizedTermination,
            PrimordialCompletionError::AuthorizedTermination,
        ),
    ] {
        let mut host = completion_host(exit);
        assert_eq!(complete_primordial_launch(&mut host), Err(expected));
        assert!(host.verified_quiescence);
    }

    let mut exit_error = completion_host(PrimordialExitDisposition::Normal(0));
    exit_error.exit = Err(CompletionFailure::Exit);
    assert_eq!(
        complete_primordial_launch(&mut exit_error),
        Err(PrimordialCompletionError::ObserveExit(
            CompletionFailure::Exit
        ))
    );

    let mut residue = completion_host(PrimordialExitDisposition::Normal(0));
    residue.quiescent = Err(CompletionFailure::Quiescence);
    assert_eq!(
        complete_primordial_launch(&mut residue),
        Err(PrimordialCompletionError::NotQuiescent(
            CompletionFailure::Quiescence
        ))
    );

    // Both facts fail at once, which is the only case where the precedence is
    // observable -- and selector 34 deliberately inverts it.
    //
    // `complete_primordial_launch_with_ready` reports the kernel-side quiescence
    // invariant first for every selector except `deepwyrm_r1_evidence`, where the
    // child-observable facts come first because run 4 failed on a quiescence
    // invariant that erased the supervised child's own terminal status. This
    // assertion predates that split and asserted only the majority order, so it
    // failed under selector 34's own cfg while the implementation was behaving
    // exactly as its comment says it should.
    let mut peer_failure_with_residue = completion_host(PrimordialExitDisposition::Normal(0));
    peer_failure_with_residue.ready = Err(CompletionFailure::Receive);
    peer_failure_with_residue.quiescent = Err(CompletionFailure::Quiescence);
    #[cfg(not(deepwyrm_r1_evidence))]
    assert_eq!(
        complete_primordial_launch(&mut peer_failure_with_residue),
        Err(PrimordialCompletionError::NotQuiescent(
            CompletionFailure::Quiescence
        ))
    );
    #[cfg(deepwyrm_r1_evidence)]
    assert_eq!(
        complete_primordial_launch(&mut peer_failure_with_residue),
        Err(PrimordialCompletionError::Receive(
            CompletionFailure::Receive
        )),
        "selector 34 reports the child's own failure ahead of the kernel-side \
         residue invariant; see complete_primordial_launch_with_ready"
    );
}

#[test]
fn retirement_fact_split_samples_exit_without_consuming_quiescence() {
    let mut receive_failure = completion_host(PrimordialExitDisposition::Normal(0xaf01_0002));
    receive_failure.ready = Err(CompletionFailure::Receive);
    assert_eq!(
        validate_primordial_retirement_facts(&mut receive_failure),
        Err(PrimordialCompletionError::Receive(
            CompletionFailure::Receive
        ))
    );
    assert!(receive_failure.observed_exit);
    assert!(!receive_failure.verified_quiescence);

    let mut malformed = completion_host(PrimordialExitDisposition::Normal(0));
    malformed.ready = Ok(vec![0; 40]);
    malformed.exit = Err(CompletionFailure::Exit);
    assert_eq!(
        validate_primordial_retirement_facts(&mut malformed),
        Err(PrimordialCompletionError::MalformedReady)
    );
    assert!(malformed.observed_exit);
    assert!(!malformed.verified_quiescence);

    let mut exit_failure = completion_host(PrimordialExitDisposition::Normal(0));
    exit_failure.exit = Err(CompletionFailure::Exit);
    assert_eq!(
        validate_primordial_retirement_facts(&mut exit_failure),
        Err(PrimordialCompletionError::ObserveExit(
            CompletionFailure::Exit
        ))
    );
    assert!(exit_failure.observed_exit);
    assert!(!exit_failure.verified_quiescence);

    let mut resource = completion_host(PrimordialExitDisposition::Normal(0));
    resource.ready = Ok(RESOURCE_READY_BYTES.to_vec());
    validate_resource_primordial_retirement_facts(&mut resource).unwrap();
    assert!(resource.observed_exit);
    assert!(!resource.verified_quiescence);

    let mut resource_on_historical = completion_host(PrimordialExitDisposition::Normal(0));
    assert_eq!(
        validate_resource_primordial_retirement_facts(&mut resource_on_historical),
        Err(PrimordialCompletionError::MalformedReady)
    );
}

/// F3A.6q. Seven variants, seven answers. The production arm used to emit one
/// sentence for six of them at the last boundary in the boot, and the exit
/// code -- a WYR1 product's whole `0xAF..` failure encoding -- sat inside the
/// variant that got discarded.
#[test]
fn completion_records_name_every_variant_and_keep_the_exit_code() {
    /// One expected answer: the completion, its cause name, its detail.
    type Expectation = (
        Result<(), PrimordialCompletionError<u32>>,
        &'static str,
        u32,
    );

    let cases: Vec<Expectation> = vec![
        (Ok(()), "completed normally", 0),
        (
            Err(PrimordialCompletionError::Receive(0x7100_0017)),
            "ready-not-received",
            0x7100_0017,
        ),
        (
            Err(PrimordialCompletionError::MalformedReady),
            "ready-malformed",
            3,
        ),
        (
            Err(PrimordialCompletionError::ObserveExit(0x7100_0016)),
            "exit-not-observed",
            0x7100_0016,
        ),
        (
            Err(PrimordialCompletionError::NonzeroExit(0xAF21_0B41)),
            "nonzero-exit",
            0xAF21_0B41,
        ),
        (
            Err(PrimordialCompletionError::UnhandledException),
            "unhandled-exception",
            5,
        ),
        (
            Err(PrimordialCompletionError::AuthorizedTermination),
            "authorized-termination",
            6,
        ),
        (
            Err(PrimordialCompletionError::NotQuiescent(0x7100_0015)),
            "not-quiescent",
            0x7100_0015,
        ),
    ];

    let mut names = Vec::new();
    for (index, (completion, cause, detail)) in cases.into_iter().enumerate() {
        let (level, observed_cause, observed_detail) = completion_record(&completion);
        assert_eq!(observed_cause, cause);
        assert_eq!(observed_detail, detail, "{cause} lost its detail");
        // Only success is informational; every failure is an error.
        let expected = if index == 0 {
            crate::debug::DiagnosticLevel::Info
        } else {
            crate::debug::DiagnosticLevel::Error
        };
        assert_eq!(level, expected, "{cause} has the wrong level");
        names.push(observed_cause);
    }

    // F3A.6s. The three payload-bearing variants are given distinct codes
    // above precisely so this test fails if `completion_record` ever renders a
    // constant -- a zero, or one payload for all three -- instead of each
    // variant's own carried value. The codes are real
    // `primordial_channel_receive_error` encodings: BufferTooSmall,
    // PeerClosed, WouldBlock.

    // No two causes share a name, or a transcript still could not tell them
    // apart -- which is the entire defect this replaced.
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total, "two completion causes share a name");
}
