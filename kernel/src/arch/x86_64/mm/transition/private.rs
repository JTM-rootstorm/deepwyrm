
use super::*;

const ENTRY_COUNT: usize = 512;
const MAX_TABLE_FRAMES: usize = DW_BOOT_X86_64_PAGING_HANDOFF_MAX_TABLE_FRAME_COUNT as usize;
const LOW_CANONICAL_LIMIT: u64 = 1_u64 << 47;
const ADDRESS_OFFSET_MASK: u64 = PAGE_SIZE - 1;
const DISALLOWED_TABLE_FLAGS: u64 =
    USER | WRITE_THROUGH | CACHE_DISABLE | HUGE | GLOBAL | SOFTWARE_LOW | SOFTWARE_HIGH;
const DISALLOWED_LEAF_FLAGS: u64 =
    USER | WRITE_THROUGH | CACHE_DISABLE | HUGE | GLOBAL | SOFTWARE_LOW | SOFTWARE_HIGH;

/// CPU facts captured at the non-reentrant BSP transition boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TransitionCpuState {
    pub(super) processor_id: u8,
    pub(super) physical_address_width: u8,
    pub(super) cr3: u64,
    pub(super) cpl: u8,
    pub(super) paging_enabled: bool,
    pub(super) long_mode_active: bool,
    pub(super) four_level_paging: bool,
    pub(super) no_execute_enabled: bool,
    pub(super) write_protect_enabled: bool,
    pub(super) interrupts_enabled: bool,
    pub(super) pcid_enabled: bool,
    pub(super) global_pages_enabled: bool,
    pub(super) smap_enabled: bool,
    pub(super) access_flag_set: bool,
    pub(super) pat_supported: bool,
    pub(super) pat_entry_zero: u8,
}

/// A fixed snapshot extracted from already-validated boot intake.
pub(super) struct TransitionHandoff<'a> {
    physical_address_width: u8,
    cr3_root_physical: u64,
    temporary_virtual_address: u64,
    temporary_indices: [usize; 4],
    temporary_child_frames: [u64; 3],
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    table_frames: &'a [u64],
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    table_frames: [u64; MAX_TABLE_FRAMES],
    table_frame_count: usize,
    _lifetime: PhantomData<&'a [u64]>,
}

impl<'a> TransitionHandoff<'a> {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    pub(super) fn from_validated(
        handoff: &'a ValidatedPagingHandoff,
    ) -> Result<Self, TransitionAttestationError<core::convert::Infallible>> {
        let header = handoff.header();
        let physical_address_width = u8::try_from(header.physical_address_width)
            .map_err(|_| TransitionAttestationError::InvalidCarrier)?;
        let table_frame_count = handoff.table_frame_count();
        if table_frame_count == 0 || table_frame_count > MAX_TABLE_FRAMES {
            return Err(TransitionAttestationError::InvalidCarrier);
        }
        Ok(Self {
            physical_address_width,
            cr3_root_physical: header.cr3_root_physical,
            temporary_virtual_address: header.temporary_virtual_address,
            temporary_indices: [
                usize::from(header.pml4_index),
                usize::from(header.pdpt_index),
                usize::from(header.pd_index),
                usize::from(header.pt_index),
            ],
            temporary_child_frames: [
                header.temporary_pdpt_frame_physical,
                header.temporary_pd_frame_physical,
                header.temporary_pt_frame_physical,
            ],
            table_frames: handoff.table_frames(),
            table_frame_count,
            _lifetime: PhantomData,
        })
    }

    fn table_frames(&self) -> &[u64] {
        &self.table_frames[..self.table_frame_count]
    }

    fn contains_table_frame(&self, frame: u64) -> bool {
        self.table_frames().binary_search(&frame).is_ok()
    }
}

/// Narrow physical-table reader used only while the declared loader root is
/// still current. Its production implementation is supplied by the linear
/// DW0-C1 transition mapper boundary.
pub(super) trait TransitionTableReader {
    type Error;

    fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransitionAttestationError<E> {
    Access(E),
    #[allow(
        dead_code,
        reason = "constructed by the target-only validated-handoff adapter"
    )]
    InvalidCarrier,
    WrongProcessorState,
    WrongControlState,
    WrongRoot,
    InvalidEntry,
    UnlistedTable,
    AliasedOrCyclicTable,
    IncompleteTableGraph,
    InvalidTemporaryPath,
    TemporaryLeafPresent,
    InvalidIdentityAlias,
}

/// Linear proof that the copied carrier describes the exact live root.
///
/// This value deliberately is neither `Copy` nor `Clone`. Later DW0-C1 work
/// consumes it to construct the temporary mapper; it is not itself permission
/// to write CR3.
#[derive(Debug)]
pub(super) struct AttestedTransition<'a> {
    processor_id: u8,
    capabilities: PagingCapabilities,
    root: FrameAddress,
    temporary_virtual_address: u64,
    temporary_indices: [usize; 4],
    temporary_child_frames: [FrameAddress; 3],
    temporary_pt_frame: FrameAddress,
    temporary_leaf_index: usize,
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    table_frames: &'a [u64],
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    table_frames: [u64; MAX_TABLE_FRAMES],
    table_frame_count: usize,
    _lifetime: PhantomData<&'a [u64]>,
}

impl AttestedTransition<'_> {
    pub(super) const fn processor_id(&self) -> u8 {
        self.processor_id
    }

    pub(super) const fn capabilities(&self) -> PagingCapabilities {
        self.capabilities
    }

    pub(super) const fn root(&self) -> FrameAddress {
        self.root
    }

    pub(super) const fn temporary_virtual_address(&self) -> u64 {
        self.temporary_virtual_address
    }

    pub(super) const fn temporary_pt_frame(&self) -> FrameAddress {
        self.temporary_pt_frame
    }

    fn table_frames(&self) -> &[u64] {
        &self.table_frames[..self.table_frame_count]
    }

    fn contains_transition_table(&self, frame: FrameAddress) -> bool {
        self.table_frames().contains(&frame.address())
    }
}

#[derive(Clone, Copy)]
struct TableNode {
    frame: FrameAddress,
    level: u8,
    virtual_prefix: u64,
    writable_path: bool,
}

const EMPTY_NODE: TableNode = TableNode {
    frame: FrameAddress(0),
    level: 0,
    virtual_prefix: 0,
    writable_path: false,
};

pub(super) fn attest_transition<'a, R: TransitionTableReader>(
    cpu: TransitionCpuState,
    handoff: &TransitionHandoff<'a>,
    reader: &mut R,
) -> Result<AttestedTransition<'a>, TransitionAttestationError<R::Error>> {
    if cpu.cpl != 0 {
        return Err(TransitionAttestationError::WrongProcessorState);
    }
    if cpu.interrupts_enabled
        || cpu.pcid_enabled
        || cpu.global_pages_enabled
        || cpu.smap_enabled
        || cpu.access_flag_set
        || !cpu.paging_enabled
        || !cpu.long_mode_active
        || !cpu.four_level_paging
        || !cpu.no_execute_enabled
        || !cpu.write_protect_enabled
        || !cpu.pat_supported
        || cpu.pat_entry_zero != 6
        || cpu.physical_address_width != handoff.physical_address_width
    {
        return Err(TransitionAttestationError::WrongControlState);
    }
    if cpu.cr3 & ADDRESS_OFFSET_MASK != 0 || cpu.cr3 != handoff.cr3_root_physical {
        return Err(TransitionAttestationError::WrongRoot);
    }

    let capabilities = PagingCapabilities::validate(
        cpu.physical_address_width,
        cpu.four_level_paging,
        cpu.no_execute_enabled,
        cpu.write_protect_enabled,
    )
    .map_err(|_| TransitionAttestationError::WrongControlState)?;
    let root = FrameAddress::new(cpu.cr3, capabilities.physical_limit())
        .map_err(|_| TransitionAttestationError::WrongRoot)?;
    if handoff
        .table_frames()
        .iter()
        .any(|frame| *frame >= LOW_CANONICAL_LIMIT)
    {
        return Err(TransitionAttestationError::InvalidIdentityAlias);
    }
    if !handoff.contains_table_frame(root.address()) {
        return Err(TransitionAttestationError::UnlistedTable);
    }

    attest_complete_graph(handoff, capabilities, root, reader)?;
    attest_temporary_path(handoff, capabilities, root, reader)?;

    let temporary_pt_frame = FrameAddress::new(
        handoff.temporary_child_frames[2],
        capabilities.physical_limit(),
    )
    .map_err(|_| TransitionAttestationError::InvalidTemporaryPath)?;
    let temporary_child_frames = [
        FrameAddress::new(
            handoff.temporary_child_frames[0],
            capabilities.physical_limit(),
        )
        .map_err(|_| TransitionAttestationError::InvalidTemporaryPath)?,
        FrameAddress::new(
            handoff.temporary_child_frames[1],
            capabilities.physical_limit(),
        )
        .map_err(|_| TransitionAttestationError::InvalidTemporaryPath)?,
        temporary_pt_frame,
    ];
    Ok(AttestedTransition {
        processor_id: cpu.processor_id,
        capabilities,
        root,
        temporary_virtual_address: handoff.temporary_virtual_address,
        temporary_indices: handoff.temporary_indices,
        temporary_child_frames,
        temporary_pt_frame,
        temporary_leaf_index: handoff.temporary_indices[3],
        table_frames: handoff.table_frames,
        table_frame_count: handoff.table_frame_count,
        _lifetime: PhantomData,
    })
}

/// Raw operations beneath the single-page transition window.
///
/// # Safety
///
/// An implementation must address the exact still-active transition root used
/// by [`attest_transition`]. Leaf access must use aligned atomics; invalidation
/// and window writes must be infallible, ordered architecture operations.
/// Window accesses must address only the frame currently installed in that
/// leaf and must not retain references.
#[allow(
    unsafe_code,
    reason = "volatile scratch-leaf and mapped-window behavior is an architecture safety contract"
)]
pub(super) unsafe trait TransitionScratchBackend: TransitionTableReader {
    fn load_temporary_leaf(&mut self, table: FrameAddress, index: usize) -> u64;
    fn compare_exchange_temporary_leaf(
        &mut self,
        table: FrameAddress,
        index: usize,
        current: u64,
        new: u64,
    ) -> Result<(), u64>;
    fn invalidate_temporary_page(&mut self, virtual_address: u64);
    fn read_window_u64(&mut self, index: usize) -> u64;
    fn write_window_u64(&mut self, index: usize, value: u64);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransitionScratchError<E> {
    Access(E),
    Busy,
    TransitionTableAlias,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransitionZeroError<E> {
    InvalidAllocation,
    Scratch(TransitionScratchError<E>),
    FrameRole(FrameRoleError),
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct TransitionZeroFailure<E> {
    error: TransitionZeroError<E>,
    grant: AllocationGrant,
}

impl<E> TransitionZeroFailure<E> {
    pub(super) const fn error(&self) -> &TransitionZeroError<E> {
        &self.error
    }

    pub(super) fn into_grant(self) -> AllocationGrant {
        self.grant
    }
}

/// Exclusive mapper for the one loader-provided transition page.
///
/// Every operation begins and ends with the temporary leaf exactly zero. The
/// API exposes values rather than mapped references, so no alias can outlive a
/// remap. This value is intentionally linear and has no `Clone`/`Copy` impl.
struct TransitionScratchMapper<'a, B> {
    attested: AttestedTransition<'a>,
    backend: B,
    poisoned: bool,
    _not_send_sync: PhantomData<*mut ()>,
}

impl<'a, B: TransitionScratchBackend> TransitionScratchMapper<'a, B> {
    pub(super) fn from_attested(
        attested: AttestedTransition<'a>,
        mut backend: B,
    ) -> Result<Self, TransitionScratchError<B::Error>> {
        let leaf =
            backend.load_temporary_leaf(attested.temporary_pt_frame, attested.temporary_leaf_index);
        if leaf != 0 {
            return Err(TransitionScratchError::Busy);
        }
        Ok(Self {
            attested,
            backend,
            poisoned: false,
            _not_send_sync: PhantomData,
        })
    }

    pub(super) const fn capabilities(&self) -> PagingCapabilities {
        self.attested.capabilities
    }

    pub(super) fn read_frame_entry(
        &mut self,
        frame: FrameAddress,
        index: usize,
    ) -> Result<u64, TransitionScratchError<B::Error>> {
        assert!(index < ENTRY_COUNT, "page-table entry index is bounded");
        self.with_frame(frame, |backend| backend.read_window_u64(index))
    }

    fn write_frame_entry(
        &mut self,
        frame: FrameAddress,
        index: usize,
        value: u64,
    ) -> Result<(), TransitionScratchError<B::Error>> {
        assert!(index < ENTRY_COUNT, "page-table entry index is bounded");
        self.with_frame(frame, |backend| backend.write_window_u64(index, value))
    }

    pub(super) fn temporary_leaf_is_zero(&mut self) -> bool {
        self.backend.load_temporary_leaf(
            self.attested.temporary_pt_frame,
            self.attested.temporary_leaf_index,
        ) == 0
    }

    fn zero_frame_unchecked(
        &mut self,
        frame: FrameAddress,
    ) -> Result<(), TransitionScratchError<B::Error>> {
        self.with_frame(frame, |backend| {
            for index in 0..ENTRY_COUNT {
                backend.write_window_u64(index, 0);
            }
        })
    }

    /// Zeroes a complete allocator grant and consumes it into the manager's
    /// typed zeroed state. All frame addresses are validated before the first
    /// byte changes; a failure returns the still-owned allocation grant.
    #[allow(
        unsafe_code,
        reason = "exclusive physical zeroing is immediately consumed into the typed frame-role transition"
    )]
    pub(super) fn zero_allocation<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
        &mut self,
        roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        grant: AllocationGrant,
    ) -> Result<ZeroedGrant, TransitionZeroFailure<B::Error>> {
        if let Err(error) = roles.validate_allocation(&grant) {
            return Err(TransitionZeroFailure {
                error: TransitionZeroError::FrameRole(error),
                grant,
            });
        }
        let start = grant.physical_start();
        let byte_len = grant.byte_len();
        if byte_len == 0 || !byte_len.is_multiple_of(PAGE_SIZE) {
            return Err(TransitionZeroFailure {
                error: TransitionZeroError::InvalidAllocation,
                grant,
            });
        }
        let mut offset = 0_u64;
        while offset < byte_len {
            if FrameAddress::new(start + offset, self.capabilities().physical_limit()).is_err() {
                return Err(TransitionZeroFailure {
                    error: TransitionZeroError::InvalidAllocation,
                    grant,
                });
            }
            offset += PAGE_SIZE;
        }

        offset = 0;
        while offset < byte_len {
            let frame = FrameAddress::new(start + offset, self.capabilities().physical_limit())
                .expect("complete allocation range was prevalidated");
            if let Err(error) = self.zero_frame_unchecked(frame) {
                return Err(TransitionZeroFailure {
                    error: TransitionZeroError::Scratch(error),
                    grant,
                });
            }
            offset += PAGE_SIZE;
        }

        // SAFETY: the exclusive scratch mapper wrote zero to every u64 in
        // every page of the grant and completed each unmap/invalidation before
        // this role transition. The non-Copy grant remained exclusively owned.
        match unsafe { roles.assume_zeroed(grant) } {
            Ok(zeroed) => Ok(zeroed),
            Err(error) => Err(TransitionZeroFailure {
                error: TransitionZeroError::FrameRole(error.error()),
                grant: error.into_grant(),
            }),
        }
    }

    fn with_frame<T>(
        &mut self,
        frame: FrameAddress,
        operation: impl FnOnce(&mut B) -> T,
    ) -> Result<T, TransitionScratchError<B::Error>> {
        assert!(!self.poisoned, "transition scratch mapper is poisoned");
        if self.attested.contains_transition_table(frame) {
            return Err(TransitionScratchError::TransitionTableAlias);
        }
        let installed = frame.address() | PRESENT | WRITABLE | NO_EXECUTE;
        if self
            .backend
            .compare_exchange_temporary_leaf(
                self.attested.temporary_pt_frame,
                self.attested.temporary_leaf_index,
                0,
                installed,
            )
            .is_err()
        {
            return Err(TransitionScratchError::Busy);
        }
        self.backend
            .invalidate_temporary_page(self.attested.temporary_virtual_address);
        let result = operation(&mut self.backend);

        let mut expected = installed;
        for _ in 0..3 {
            match self.backend.compare_exchange_temporary_leaf(
                self.attested.temporary_pt_frame,
                self.attested.temporary_leaf_index,
                expected,
                0,
            ) {
                Ok(()) => {
                    self.backend
                        .invalidate_temporary_page(self.attested.temporary_virtual_address);
                    return Ok(result);
                }
                Err(observed) if observed & !(ACCESSED | DIRTY) == installed => {
                    expected = observed;
                }
                Err(observed) => {
                    self.poisoned = true;
                    panic!("hostile transition scratch leaf drift: observed {observed:#018x}");
                }
            }
        }
        self.poisoned = true;
        panic!("transition scratch leaf did not converge after A/D drift");
    }
}

fn attest_complete_graph<R: TransitionTableReader>(
    handoff: &TransitionHandoff,
    capabilities: PagingCapabilities,
    root: FrameAddress,
    reader: &mut R,
) -> Result<(), TransitionAttestationError<R::Error>> {
    let mut pending = [EMPTY_NODE; MAX_TABLE_FRAMES];
    let mut visited = [0_u64; MAX_TABLE_FRAMES];
    pending[0] = TableNode {
        frame: root,
        level: 3,
        virtual_prefix: 0,
        writable_path: true,
    };
    let mut identity_alias_counts = [0_u8; MAX_TABLE_FRAMES];
    let mut pending_count = 1;
    let mut cursor = 0;
    let mut visited_count = 0;

    while cursor < pending_count {
        let node = pending[cursor];
        cursor += 1;
        if visited[..visited_count].contains(&node.frame.address()) {
            return Err(TransitionAttestationError::AliasedOrCyclicTable);
        }
        if visited_count == MAX_TABLE_FRAMES {
            return Err(TransitionAttestationError::IncompleteTableGraph);
        }
        visited[visited_count] = node.frame.address();
        visited_count += 1;

        for index in 0..ENTRY_COUNT {
            let entry = reader
                .read_entry(node.frame, index)
                .map_err(TransitionAttestationError::Access)?;
            if entry & PRESENT == 0 {
                if entry != 0 {
                    return Err(TransitionAttestationError::InvalidEntry);
                }
                continue;
            }
            validate_entry_bits(entry, capabilities, node.level == 0)?;
            if node.level == 0 {
                let mapped_frame = entry & physical_address_mask(capabilities);
                if let Ok(table_index) = handoff.table_frames().binary_search(&mapped_frame) {
                    let virtual_address =
                        entry_virtual_address(node.virtual_prefix, index, node.level);
                    let required = PRESENT | WRITABLE | NO_EXECUTE;
                    if virtual_address != mapped_frame
                        || !node.writable_path
                        || entry & !(ACCESSED | DIRTY) != mapped_frame | required
                        || identity_alias_counts[table_index] != 0
                    {
                        return Err(TransitionAttestationError::InvalidIdentityAlias);
                    }
                    identity_alias_counts[table_index] = 1;
                }
                continue;
            }
            let child_address = entry & physical_address_mask(capabilities);
            if !handoff.contains_table_frame(child_address) {
                return Err(TransitionAttestationError::UnlistedTable);
            }
            let child = FrameAddress::new(child_address, capabilities.physical_limit())
                .map_err(|_| TransitionAttestationError::InvalidEntry)?;
            if pending_count == MAX_TABLE_FRAMES {
                return Err(TransitionAttestationError::IncompleteTableGraph);
            }
            pending[pending_count] = TableNode {
                frame: child,
                level: node.level - 1,
                virtual_prefix: entry_virtual_address(node.virtual_prefix, index, node.level),
                writable_path: node.writable_path && entry & WRITABLE != 0,
            };
            pending_count += 1;
        }
    }

    if visited_count != handoff.table_frames().len()
        || handoff
            .table_frames()
            .iter()
            .any(|frame| !visited[..visited_count].contains(frame))
        || identity_alias_counts[..handoff.table_frames().len()]
            .iter()
            .any(|count| *count != 1)
    {
        return Err(TransitionAttestationError::IncompleteTableGraph);
    }
    Ok(())
}

fn attest_temporary_path<R: TransitionTableReader>(
    handoff: &TransitionHandoff,
    capabilities: PagingCapabilities,
    root: FrameAddress,
    reader: &mut R,
) -> Result<(), TransitionAttestationError<R::Error>> {
    let mut table = root;
    for depth in 0..3 {
        let entry = reader
            .read_entry(table, handoff.temporary_indices[depth])
            .map_err(TransitionAttestationError::Access)?;
        validate_entry_bits(entry, capabilities, false)?;
        if entry & WRITABLE == 0
            || entry & DISALLOWED_TABLE_FLAGS != 0
            || entry & physical_address_mask(capabilities) != handoff.temporary_child_frames[depth]
        {
            return Err(TransitionAttestationError::InvalidTemporaryPath);
        }
        table = FrameAddress::new(
            handoff.temporary_child_frames[depth],
            capabilities.physical_limit(),
        )
        .map_err(|_| TransitionAttestationError::InvalidTemporaryPath)?;
    }
    let leaf = reader
        .read_entry(table, handoff.temporary_indices[3])
        .map_err(TransitionAttestationError::Access)?;
    if leaf != 0 {
        return Err(TransitionAttestationError::TemporaryLeafPresent);
    }
    Ok(())
}

fn validate_entry_bits<E>(
    entry: u64,
    capabilities: PagingCapabilities,
    leaf: bool,
) -> Result<(), TransitionAttestationError<E>> {
    let address_mask = physical_address_mask(capabilities);
    if entry & !(address_mask | PERMITTED_ENTRY_FLAGS) != 0
        || entry & PRESENT == 0
        || entry
            & if leaf {
                DISALLOWED_LEAF_FLAGS
            } else {
                DISALLOWED_TABLE_FLAGS
            }
            != 0
    {
        return Err(TransitionAttestationError::InvalidEntry);
    }
    let address = entry & address_mask;
    if address == 0
        || address & ADDRESS_OFFSET_MASK != 0
        || address >= capabilities.physical_limit().exclusive()
        || (leaf && entry & WRITABLE != 0 && entry & NO_EXECUTE == 0)
    {
        return Err(TransitionAttestationError::InvalidEntry);
    }
    let _hardware_mutable = entry & (ACCESSED | DIRTY);
    Ok(())
}

fn physical_address_mask(capabilities: PagingCapabilities) -> u64 {
    (capabilities.physical_limit().exclusive() - 1) & !ADDRESS_OFFSET_MASK
}

fn entry_virtual_address(prefix: u64, index: usize, level: u8) -> u64 {
    let shift = 12 + u32::from(level) * 9;
    let address = prefix | ((index as u64) << shift);
    if address & (1_u64 << 47) != 0 {
        address | 0xffff_0000_0000_0000
    } else {
        address
    }
}

const LIVE_TRANSITION_UNCLAIMED: u8 = 0;
const LIVE_TRANSITION_ATTESTING: u8 = 1;
const LIVE_TRANSITION_OWNED: u8 = 2;
const LIVE_TRANSITION_POISONED: u8 = 3;
const LIVE_TRANSITION_RETIRED: u8 = 4;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
static LIVE_TRANSITION_STATE: AtomicU8 = AtomicU8::new(LIVE_TRANSITION_UNCLAIMED);

fn claim_transition_state(state: &AtomicU8) -> Result<(), ()> {
    state
        .compare_exchange(
            LIVE_TRANSITION_UNCLAIMED,
            LIVE_TRANSITION_ATTESTING,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .map(|_| ())
        .map_err(|_| ())
}

/// Production failure before the linear temporary mapper becomes available.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiveTransitionError {
    AlreadyClaimed,
    InvalidCarrier,
    Attestation(TransitionAttestationError<Infallible>),
    Scratch(TransitionScratchError<Infallible>),
    FrameRole(FrameRoleError),
    #[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
    TargetUnavailable,
}

/// The sole live DW0-C1 transition mapper.
pub(crate) struct LiveTransitionMapper<'a> {
    mapper: TransitionScratchMapper<'a, LiveTransitionBackend>,
    _transition_roles: TransitionTableRoleSet<MAX_TABLE_FRAMES>,
}

/// Terminal C1 handoff consumed by the later C2 activation operation.
///
/// It deliberately exposes no mapper methods: after conversion, scratch
/// authority cannot be used independently of the future consuming CR3 switch.
pub(crate) struct TransitionActivationHandoff<'a>(LiveTransitionMapper<'a>);

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TransitionActivationAccessError {
    WrongRoot,
    InvalidTemporaryPath,
    TemporaryLeafPresent,
    UnattestedTransitionFrame,
    Scratch(TransitionScratchError<Infallible>),
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl TransitionActivationHandoff<'_> {
    pub(super) fn capabilities(&self) -> PagingCapabilities {
        self.0.mapper.capabilities()
    }

    pub(super) fn processor_id(&self) -> u8 {
        self.0.mapper.attested.processor_id()
    }

    pub(super) fn transition_root(&self) -> FrameAddress {
        self.0.mapper.attested.root()
    }

    pub(super) fn temporary_virtual_address(&self) -> u64 {
        self.0.mapper.attested.temporary_virtual_address()
    }

    pub(super) fn read_transition_entry(
        &mut self,
        table: FrameAddress,
        index: usize,
    ) -> Result<u64, TransitionActivationAccessError> {
        if !self.0.mapper.attested.contains_transition_table(table) {
            return Err(TransitionActivationAccessError::UnattestedTransitionFrame);
        }
        match self.0.mapper.backend.read_entry(table, index) {
            Ok(value) => Ok(value),
            Err(never) => match never {},
        }
    }

    pub(super) fn revalidate_temporary_path(
        &mut self,
        current_root: FrameAddress,
    ) -> Result<(), TransitionActivationAccessError> {
        if current_root != self.transition_root() {
            return Err(TransitionActivationAccessError::WrongRoot);
        }
        let capabilities = self.capabilities();
        let mut table = current_root;
        for depth in 0..3 {
            let index = self.0.mapper.attested.temporary_indices[depth];
            let entry = self.read_transition_entry(table, index)?;
            validate_entry_bits::<Infallible>(entry, capabilities, false)
                .map_err(|_| TransitionActivationAccessError::InvalidTemporaryPath)?;
            let expected = self.0.mapper.attested.temporary_child_frames[depth];
            if entry & WRITABLE == 0
                || entry & DISALLOWED_TABLE_FLAGS != 0
                || entry & physical_address_mask(capabilities) != expected.address()
                || !self.0.mapper.attested.contains_transition_table(expected)
            {
                return Err(TransitionActivationAccessError::InvalidTemporaryPath);
            }
            table = expected;
        }
        let leaf_index = self.0.mapper.attested.temporary_indices[3];
        let leaf = self.read_transition_entry(table, leaf_index)?;
        if leaf != 0 || !self.0.mapper.temporary_leaf_is_zero() {
            return Err(TransitionActivationAccessError::TemporaryLeafPresent);
        }
        Ok(())
    }

    pub(super) fn read_inactive_entry(
        &mut self,
        frame: FrameAddress,
        index: usize,
    ) -> Result<u64, TransitionScratchError<Infallible>> {
        self.0.mapper.read_frame_entry(frame, index)
    }

    pub(super) fn retire_before_activation(self) {
        assert!(
            LIVE_TRANSITION_STATE
                .compare_exchange(
                    LIVE_TRANSITION_OWNED,
                    LIVE_TRANSITION_RETIRED,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok(),
            "transition authority was not uniquely owned before CR3 activation"
        );
        // Transition-table frames are intentionally not reclaimed in DW0.
        // Forgetting this terminal authority also guarantees no destructor
        // can touch the old mapping after the CR3 write.
        core::mem::forget(self);
    }
}

impl<'a> LiveTransitionMapper<'a> {
    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    pub(super) fn capabilities(&self) -> PagingCapabilities {
        self.mapper.capabilities()
    }

    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    pub(super) fn transition_root(&self) -> FrameAddress {
        self.mapper.attested.root()
    }

    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    pub(super) fn temporary_virtual_address(&self) -> u64 {
        self.mapper.attested.temporary_virtual_address()
    }

    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    pub(super) fn resolve_transition_leaf(
        &mut self,
        page: u64,
    ) -> Result<u64, TransitionActivationAccessError> {
        let capabilities = self.capabilities();
        let mut table = self.transition_root();
        for level in (0..=3).rev() {
            let index = ((page >> (12 + level * 9)) & 0x1ff) as usize;
            if !self.mapper.attested.contains_transition_table(table) {
                return Err(TransitionActivationAccessError::UnattestedTransitionFrame);
            }
            let entry = match self.mapper.backend.read_entry(table, index) {
                Ok(entry) => entry,
                Err(never) => match never {},
            };
            validate_entry_bits::<Infallible>(entry, capabilities, level == 0)
                .map_err(|_| TransitionActivationAccessError::InvalidTemporaryPath)?;
            if level == 0 {
                return Ok(entry);
            }
            let child = FrameAddress::new(
                entry & physical_address_mask(capabilities),
                capabilities.physical_limit(),
            )
            .map_err(|_| TransitionActivationAccessError::InvalidTemporaryPath)?;
            if !self.mapper.attested.contains_transition_table(child) {
                return Err(TransitionActivationAccessError::UnattestedTransitionFrame);
            }
            table = child;
        }
        unreachable!("four-level transition walk always reaches a leaf")
    }

    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    pub(super) fn read_owned_table_entry<
        const RANGE_CAPACITY: usize,
        const ROLE_CAPACITY: usize,
    >(
        &mut self,
        roles: &FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        table: TableIdentity,
        index: usize,
    ) -> Result<u64, TransitionActivationAccessError> {
        roles
            .validate_table_identity(table)
            .map_err(|_| TransitionActivationAccessError::InvalidTemporaryPath)?;
        let frame = FrameAddress::new(table.physical_start(), self.capabilities().physical_limit())
            .map_err(|_| TransitionActivationAccessError::InvalidTemporaryPath)?;
        self.mapper
            .read_frame_entry(frame, index)
            .map_err(TransitionActivationAccessError::Scratch)
    }

    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    pub(super) fn write_owned_table_entry<
        const RANGE_CAPACITY: usize,
        const ROLE_CAPACITY: usize,
    >(
        &mut self,
        roles: &FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        table: TableIdentity,
        index: usize,
        value: u64,
    ) -> Result<(), TransitionActivationAccessError> {
        roles
            .validate_table_identity(table)
            .map_err(|_| TransitionActivationAccessError::InvalidTemporaryPath)?;
        let frame = FrameAddress::new(table.physical_start(), self.capabilities().physical_limit())
            .map_err(|_| TransitionActivationAccessError::InvalidTemporaryPath)?;
        self.mapper
            .write_frame_entry(frame, index, value)
            .map_err(TransitionActivationAccessError::Scratch)
    }

    #[cfg(all(target_os = "none", target_arch = "x86_64"))]
    pub(crate) fn zero_allocation<const RANGE_CAPACITY: usize, const ROLE_CAPACITY: usize>(
        &mut self,
        roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
        grant: AllocationGrant,
    ) -> Result<ZeroedGrant, TransitionZeroFailure<Infallible>> {
        self.mapper.zero_allocation(roles, grant)
    }

    pub(crate) fn into_activation_handoff(self) -> TransitionActivationHandoff<'a> {
        TransitionActivationHandoff(self)
    }

    fn from_private_parts(
        mapper: TransitionScratchMapper<'a, LiveTransitionBackend>,
        transition_roles: TransitionTableRoleSet<MAX_TABLE_FRAMES>,
    ) -> Self {
        Self {
            mapper,
            _transition_roles: transition_roles,
        }
    }
}

/// Claims and attests the loader transition root, atomically imports its exact
/// table set into the authoritative role registry, and returns the only mapper
/// allowed to mutate its fixed temporary leaf.
///
/// # Safety
///
/// Calling this function is the explicit unsafe assertion of exclusive
/// early-transition ownership. The caller must be the BSP on the one-shot
/// early boot path, before any AP startup, at CPL0 with IF clear, and must
/// own the sole boot-memory role manager. The atomic claim makes that
/// assertion linear within Deepwyrm; it cannot observe BSP/AP ownership
/// independently. This boundary trusts the accepted loader's integrity and
/// self-consistency contract for the exact CR3 root and retained identity
/// aliases; the live walk does not independently or cryptographically prove
/// physical authenticity against a malicious loader, firmware/unsafe memory
/// corruption, or DMA. Failure poisons this transition opportunity; callers
/// must not continue boot or try to reconstruct a mapper.
#[allow(
    unsafe_code,
    reason = "one-shot live CPU observation and transition-table identity access"
)]
pub(crate) unsafe fn claim_live_transition_mapper<
    'a,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    handoff: &'a ValidatedPagingHandoff,
    roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
) -> Result<LiveTransitionMapper<'a>, LiveTransitionError> {
    claim_live_transition_mapper_impl(handoff, roles)
}

#[cfg(not(all(target_os = "none", target_arch = "x86_64")))]
fn claim_live_transition_mapper_impl<
    'a,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    handoff: &'a ValidatedPagingHandoff,
    roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
) -> Result<LiveTransitionMapper<'a>, LiveTransitionError> {
    let _ = (handoff, roles);
    Err(LiveTransitionError::TargetUnavailable)
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "the unsafe one-shot facade delegates live register observation and attested external-role import here"
)]
fn claim_live_transition_mapper_impl<
    'a,
    const RANGE_CAPACITY: usize,
    const ROLE_CAPACITY: usize,
>(
    handoff: &'a ValidatedPagingHandoff,
    roles: &mut FrameRoleManager<RANGE_CAPACITY, ROLE_CAPACITY>,
) -> Result<LiveTransitionMapper<'a>, LiveTransitionError> {
    let handoff = TransitionHandoff::from_validated(handoff)
        .map_err(|_| LiveTransitionError::InvalidCarrier)?;
    claim_transition_state(&LIVE_TRANSITION_STATE)
        .map_err(|_| LiveTransitionError::AlreadyClaimed)?;

    // SAFETY: this function's caller establishes the documented bootstrap CPU
    // state and transition mapping lifetime.
    let cpu = unsafe { observe_live_transition_cpu() };
    let mut backend = LiveTransitionBackend {
        temporary_virtual_address: handoff.temporary_virtual_address,
    };
    let attested = match attest_transition(cpu, &handoff, &mut backend) {
        Ok(attested) => attested,
        Err(error) => {
            LIVE_TRANSITION_STATE.store(LIVE_TRANSITION_POISONED, Ordering::Release);
            return Err(LiveTransitionError::Attestation(error));
        }
    };
    let mapper = match TransitionScratchMapper::from_attested(attested, backend) {
        Ok(mapper) => mapper,
        Err(error) => {
            LIVE_TRANSITION_STATE.store(LIVE_TRANSITION_POISONED, Ordering::Release);
            return Err(LiveTransitionError::Scratch(error));
        }
    };
    // SAFETY: the consumed live attestation retained in `mapper` proves this
    // exact sorted set is the current transition graph; the unsafe entry
    // contract supplies the accepted loader provenance and sole role manager.
    let transition_roles = match unsafe {
        roles.import_transition_tables::<MAX_TABLE_FRAMES>(mapper.attested.table_frames())
    } {
        Ok(roles) => roles,
        Err(error) => {
            LIVE_TRANSITION_STATE.store(LIVE_TRANSITION_POISONED, Ordering::Release);
            return Err(LiveTransitionError::FrameRole(error));
        }
    };
    LIVE_TRANSITION_STATE.store(LIVE_TRANSITION_OWNED, Ordering::Release);
    Ok(LiveTransitionMapper::from_private_parts(
        mapper,
        transition_roles,
    ))
}

struct LiveTransitionBackend {
    temporary_virtual_address: u64,
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
const _: () = assert!(
    core::mem::size_of::<LiveTransitionMapper<'static>>() <= 256,
    "the linear transition mapper must remain a compact borrowed carrier"
);

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
impl TransitionTableReader for LiveTransitionBackend {
    type Error = Infallible;

    #[allow(
        unsafe_code,
        reason = "the attested carrier guarantees identity aliases for every transition table"
    )]
    fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        debug_assert!(index < ENTRY_COUNT);
        let address = table.address() + (index as u64) * 8;
        // SAFETY: construction is confined to the loader transition lifetime;
        // the carrier enumerates this complete reserved table frame and the
        // loader contract supplies its supervisor identity alias.
        Ok(unsafe { core::ptr::read_volatile(address as *const u64) })
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "volatile transition PTE/window access and invlpg are the audited DW0-C1 boundary"
)]
unsafe impl TransitionScratchBackend for LiveTransitionBackend {
    fn load_temporary_leaf(&mut self, table: FrameAddress, index: usize) -> u64 {
        debug_assert!(index < ENTRY_COUNT);
        let address = table.address() + (index as u64) * 8;
        // SAFETY: each x86_64 PTE is naturally aligned and the accepted loader
        // contract retains this exact identity alias through transition. All
        // Deepwyrm access to the scratch leaf uses this atomic protocol.
        unsafe { (&*(address as *const core::sync::atomic::AtomicU64)).load(Ordering::SeqCst) }
    }

    fn compare_exchange_temporary_leaf(
        &mut self,
        table: FrameAddress,
        index: usize,
        current: u64,
        new: u64,
    ) -> Result<(), u64> {
        debug_assert!(index < ENTRY_COUNT);
        let address = table.address() + (index as u64) * 8;
        // SAFETY: see `load_temporary_leaf`; compare-exchange is the sole
        // mutation protocol for this retained, aligned transition PTE.
        unsafe { &*(address as *const core::sync::atomic::AtomicU64) }
            .compare_exchange(current, new, Ordering::SeqCst, Ordering::SeqCst)
            .map(|_| ())
    }

    fn invalidate_temporary_page(&mut self, virtual_address: u64) {
        debug_assert_eq!(virtual_address, self.temporary_virtual_address);
        // SAFETY: `invlpg` is executed at CPL0 for the canonical fixed window
        // while the attested transition CR3 remains current.
        unsafe {
            core::arch::asm!(
                "invlpg [{}]",
                in(reg) virtual_address,
                options(nostack, preserves_flags),
            );
        }
    }

    fn read_window_u64(&mut self, index: usize) -> u64 {
        debug_assert!(index < ENTRY_COUNT);
        let address = self.temporary_virtual_address + (index as u64) * 8;
        // SAFETY: the mapper installed exactly one exclusive physical page
        // for this bounded read and no reference escapes the operation.
        unsafe { core::ptr::read_volatile(address as *const u64) }
    }

    fn write_window_u64(&mut self, index: usize, value: u64) {
        debug_assert!(index < ENTRY_COUNT);
        let address = self.temporary_virtual_address + (index as u64) * 8;
        // SAFETY: the mapper has installed exactly one exclusive page for this
        // bounded operation and no reference escapes the write.
        unsafe { core::ptr::write_volatile(address as *mut u64, value) };
    }
}

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unsafe_code,
    reason = "privileged register observation is confined to the documented one-shot BSP boundary"
)]
unsafe fn observe_live_transition_cpu() -> TransitionCpuState {
    use core::arch::asm;
    use core::arch::x86_64::__cpuid;

    // SAFETY: the surrounding unsafe contract guarantees CPL0 early boot.
    let maximum_leaf = __cpuid(0x8000_0000).eax;
    // SAFETY: CPUID leaf zero is architecturally available on x86_64.
    let maximum_basic_leaf = __cpuid(0).eax;
    let pat_supported = maximum_basic_leaf >= 1
        // SAFETY: the basic maximum reports leaf one as available.
        && __cpuid(1).edx & (1 << 16) != 0;
    let physical_address_width = if maximum_leaf >= 0x8000_0008 {
        // SAFETY: the extended CPUID leaf was reported present.
        (__cpuid(0x8000_0008).eax & 0xff) as u8
    } else {
        0
    };
    let cr0: u64;
    let cr3: u64;
    let cr4: u64;
    let rflags: u64;
    let cs: u16;
    let efer_low: u32;
    let efer_high: u32;
    // SAFETY: these are read-only observations at the CPL0 BSP boundary.
    unsafe {
        asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
        asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        asm!("pushfq", "pop {}", out(reg) rflags, options(nomem, preserves_flags));
        asm!("mov {:x}, cs", out(reg) cs, options(nomem, nostack, preserves_flags));
        asm!(
            "rdmsr",
            in("ecx") 0xc000_0080_u32,
            out("eax") efer_low,
            out("edx") efer_high,
            options(nomem, nostack, preserves_flags),
        );
    }
    let efer = u64::from(efer_low) | (u64::from(efer_high) << 32);
    let pat = if pat_supported {
        let pat_low: u32;
        let pat_high: u32;
        // SAFETY: CPUID.01H:EDX.PAT proved that IA32_PAT is implemented.
        unsafe {
            asm!(
                "rdmsr",
                in("ecx") 0x277_u32,
                out("eax") pat_low,
                out("edx") pat_high,
                options(nomem, nostack, preserves_flags),
            );
        }
        u64::from(pat_low) | (u64::from(pat_high) << 32)
    } else {
        0
    };
    // SAFETY: CPUID leaf one is architecturally available on x86_64.
    let processor_id = (__cpuid(1).ebx >> 24) as u8;
    TransitionCpuState {
        processor_id,
        physical_address_width,
        cr3,
        cpl: (cs & 3) as u8,
        paging_enabled: cr0 & (1 << 31) != 0,
        long_mode_active: efer & (1 << 10) != 0,
        four_level_paging: cr4 & (1 << 12) == 0,
        no_execute_enabled: efer & (1 << 11) != 0,
        write_protect_enabled: cr0 & (1 << 16) != 0,
        interrupts_enabled: rflags & (1 << 9) != 0,
        pcid_enabled: cr4 & (1 << 17) != 0,
        global_pages_enabled: cr4 & (1 << 7) != 0,
        smap_enabled: cr4 & (1 << 21) != 0,
        access_flag_set: rflags & (1 << 18) != 0,
        pat_supported,
        pat_entry_zero: pat as u8,
    }
}

#[cfg(test)]
mod tests;
