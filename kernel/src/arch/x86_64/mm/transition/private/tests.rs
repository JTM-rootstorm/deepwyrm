
extern crate std;

use super::*;
use crate::memory::frame_roles::synthetic_frame_role_manager;
use std::collections::BTreeMap;
use std::vec::Vec;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ScratchEvent {
    LeafLoad(u64),
    LeafCas {
        current: u64,
        new: u64,
        observed: u64,
    },
    Invalidate(u64),
    WindowWrite(usize, u64),
}

#[derive(Default)]
struct FakeReader {
    entries: BTreeMap<(u64, usize), u64>,
    mapped_frame: Option<u64>,
    events: Vec<ScratchEvent>,
    next_clear_drift: Option<u64>,
}

impl TransitionTableReader for FakeReader {
    type Error = ();

    fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        Ok(*self.entries.get(&(table.address(), index)).unwrap_or(&0))
    }
}

#[allow(
    unsafe_code,
    reason = "the host fake models the exact leaf/window relationship in ordinary memory"
)]
unsafe impl TransitionScratchBackend for FakeReader {
    fn load_temporary_leaf(&mut self, table: FrameAddress, index: usize) -> u64 {
        let value = *self.entries.get(&(table.address(), index)).unwrap_or(&0);
        self.events.push(ScratchEvent::LeafLoad(value));
        value
    }

    fn compare_exchange_temporary_leaf(
        &mut self,
        table: FrameAddress,
        index: usize,
        current: u64,
        new: u64,
    ) -> Result<(), u64> {
        let entry = self.entries.entry((table.address(), index)).or_insert(0);
        if current != 0
            && new == 0
            && let Some(drift) = self.next_clear_drift.take()
        {
            *entry |= drift;
        }
        let observed = *entry;
        self.events.push(ScratchEvent::LeafCas {
            current,
            new,
            observed,
        });
        if observed != current {
            self.mapped_frame =
                (observed & PRESENT != 0).then_some(observed & 0x000f_ffff_ffff_f000);
            return Err(observed);
        }
        *entry = new;
        self.mapped_frame = (new & PRESENT != 0).then_some(new & 0x000f_ffff_ffff_f000);
        Ok(())
    }

    fn invalidate_temporary_page(&mut self, virtual_address: u64) {
        self.events.push(ScratchEvent::Invalidate(virtual_address));
    }

    fn read_window_u64(&mut self, index: usize) -> u64 {
        let frame = self.mapped_frame.expect("window is mapped");
        *self.entries.get(&(frame, index)).unwrap_or(&0)
    }

    fn write_window_u64(&mut self, index: usize, value: u64) {
        self.events.push(ScratchEvent::WindowWrite(index, value));
        let frame = self.mapped_frame.expect("window is mapped");
        self.entries.insert((frame, index), value);
    }
}

fn handoff() -> TransitionHandoff<'static> {
    let mut table_frames = [0_u64; MAX_TABLE_FRAMES];
    table_frames[..7].copy_from_slice(&[0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000]);
    TransitionHandoff {
        physical_address_width: 40,
        cr3_root_physical: 0x1000,
        temporary_virtual_address: 0xffff_ff00_0000_0000,
        temporary_indices: [510, 0, 0, 0],
        temporary_child_frames: [0x2000, 0x3000, 0x4000],
        table_frames,
        table_frame_count: 7,
        _lifetime: PhantomData,
    }
}

fn cpu() -> TransitionCpuState {
    TransitionCpuState {
        processor_id: 0,
        physical_address_width: 40,
        cr3: 0x1000,
        cpl: 0,
        paging_enabled: true,
        long_mode_active: true,
        four_level_paging: true,
        no_execute_enabled: true,
        write_protect_enabled: true,
        interrupts_enabled: false,
        pcid_enabled: false,
        global_pages_enabled: false,
        smap_enabled: false,
        access_flag_set: false,
        pat_supported: true,
        pat_entry_zero: 6,
    }
}

fn graph() -> FakeReader {
    let mut reader = FakeReader::default();
    reader
        .entries
        .insert((0x1000, 510), 0x2000 | PRESENT | WRITABLE);
    reader
        .entries
        .insert((0x2000, 0), 0x3000 | PRESENT | WRITABLE);
    reader
        .entries
        .insert((0x3000, 0), 0x4000 | PRESENT | WRITABLE);
    reader
        .entries
        .insert((0x1000, 0), 0x5000 | PRESENT | WRITABLE);
    reader
        .entries
        .insert((0x5000, 0), 0x6000 | PRESENT | WRITABLE);
    reader
        .entries
        .insert((0x6000, 0), 0x7000 | PRESENT | WRITABLE);
    for frame in (0x1000..=0x7000).step_by(PAGE_SIZE as usize) {
        reader.entries.insert(
            (0x7000, (frame / PAGE_SIZE) as usize),
            frame | PRESENT | WRITABLE | NO_EXECUTE,
        );
    }
    reader
}

#[test]
fn attests_exact_live_graph_and_empty_temporary_leaf() {
    let mut reader = graph();
    let attested = attest_transition(cpu(), &handoff(), &mut reader).unwrap();

    assert_eq!(attested.root().address(), 0x1000);
    assert_eq!(attested.temporary_pt_frame().address(), 0x4000);
    assert_eq!(attested.temporary_virtual_address(), 0xffff_ff00_0000_0000);
    assert_eq!(
        attested.capabilities().physical_limit().exclusive(),
        1_u64 << 40
    );
}

#[test]
fn rejects_cpu_drift_unlisted_tables_and_nonzero_temporary_leaf() {
    let mut wrong_cpu = cpu();
    wrong_cpu.cr3 = 0x2000;
    assert!(matches!(
        attest_transition(wrong_cpu, &handoff(), &mut graph()),
        Err(TransitionAttestationError::WrongRoot)
    ));

    let mut unlisted = graph();
    unlisted
        .entries
        .insert((0x3000, 1), 0x8000 | PRESENT | WRITABLE);
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut unlisted),
        Err(TransitionAttestationError::UnlistedTable)
    ));

    let mut occupied = graph();
    occupied
        .entries
        .insert((0x4000, 0), 0x8000 | PRESENT | NO_EXECUTE);
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut occupied),
        Err(TransitionAttestationError::TemporaryLeafPresent)
    ));
}

#[test]
fn linear_mapper_uses_exact_cas_invalidation_and_window_order() {
    let mut backend = graph();
    let attested = attest_transition(cpu(), &handoff(), &mut backend).unwrap();
    let mut mapper = TransitionScratchMapper::from_attested(attested, backend).unwrap();
    mapper.backend.events.clear();
    let mut roles = synthetic_frame_role_manager::<1, 8>(0x8000, 1);
    let allocation = roles.allocate(1).unwrap();
    mapper.backend.entries.insert((0x8000, 7), 0xfeed_beef);
    let zeroed = mapper.zero_allocation(&mut roles, allocation).unwrap();
    let _backing = roles.assign_object_backing(zeroed).unwrap();

    assert_eq!(mapper.backend.entries.get(&(0x4000, 0)), Some(&0));
    assert_eq!(mapper.backend.mapped_frame, None);
    let installed = 0x8000 | PRESENT | WRITABLE | NO_EXECUTE;
    assert_eq!(
        mapper.backend.events.first(),
        Some(&ScratchEvent::LeafCas {
            current: 0,
            new: installed,
            observed: 0,
        })
    );
    assert_eq!(
        mapper.backend.events.get(1),
        Some(&ScratchEvent::Invalidate(0xffff_ff00_0000_0000))
    );
    assert_eq!(mapper.backend.events.len(), ENTRY_COUNT + 4);
    for (index, event) in mapper.backend.events[2..2 + ENTRY_COUNT].iter().enumerate() {
        assert_eq!(event, &ScratchEvent::WindowWrite(index, 0));
    }
    assert_eq!(
        mapper.backend.events.get(ENTRY_COUNT + 2),
        Some(&ScratchEvent::LeafCas {
            current: installed,
            new: 0,
            observed: installed,
        })
    );
    assert_eq!(
        mapper.backend.events.last(),
        Some(&ScratchEvent::Invalidate(0xffff_ff00_0000_0000))
    );
    assert_eq!(mapper.backend.entries.get(&(0x8000, 7)), Some(&0));
}

#[test]
fn mapper_rejects_typed_allocation_of_transition_alias_before_leaf_cas() {
    let mut backend = graph();
    let attested = attest_transition(cpu(), &handoff(), &mut backend).unwrap();
    let mut mapper = TransitionScratchMapper::from_attested(attested, backend).unwrap();
    mapper.backend.events.clear();
    let mut roles = synthetic_frame_role_manager::<1, 8>(0x1000, 1);
    let allocation = roles.allocate(1).unwrap();

    let failure = mapper
        .zero_allocation(&mut roles, allocation)
        .expect_err("transition table aliases are never scratch targets");
    assert_eq!(
        failure.error(),
        &TransitionZeroError::Scratch(TransitionScratchError::TransitionTableAlias)
    );
    roles.cancel_allocation(failure.into_grant()).unwrap();
    assert!(mapper.backend.events.is_empty());
}

#[test]
fn rejects_every_required_bootstrap_cpu_control_fact() {
    let mut cases = [cpu(); 12];
    cases[0].cpl = 3;
    cases[1].interrupts_enabled = true;
    cases[2].pcid_enabled = true;
    cases[3].global_pages_enabled = true;
    cases[4].paging_enabled = false;
    cases[5].long_mode_active = false;
    cases[6].four_level_paging = false;
    cases[7].write_protect_enabled = false;
    cases[8].pat_supported = false;
    cases[9].pat_entry_zero = 0;
    cases[10].smap_enabled = true;
    cases[11].access_flag_set = true;

    for (index, state) in cases.into_iter().enumerate() {
        let error = attest_transition(state, &handoff(), &mut graph()).unwrap_err();
        if index == 0 {
            assert_eq!(error, TransitionAttestationError::WrongProcessorState);
        } else {
            assert_eq!(error, TransitionAttestationError::WrongControlState);
        }
    }

    let mut wrong_nx = cpu();
    wrong_nx.no_execute_enabled = false;
    assert_eq!(
        attest_transition(wrong_nx, &handoff(), &mut graph()).unwrap_err(),
        TransitionAttestationError::WrongControlState
    );
    let mut wrong_width = cpu();
    wrong_width.physical_address_width = 39;
    assert_eq!(
        attest_transition(wrong_width, &handoff(), &mut graph()).unwrap_err(),
        TransitionAttestationError::WrongControlState
    );
}

#[test]
fn rejects_cycles_incomplete_graphs_and_hostile_entry_bits() {
    let mut cyclic = graph();
    cyclic
        .entries
        .insert((0x1000, 509), 0x1000 | PRESENT | WRITABLE);
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut cyclic),
        Err(TransitionAttestationError::AliasedOrCyclicTable)
    ));

    let mut incomplete_handoff = handoff();
    incomplete_handoff.table_frames[7] = 0x8000;
    incomplete_handoff.table_frame_count = 8;
    assert!(matches!(
        attest_transition(cpu(), &incomplete_handoff, &mut graph()),
        Err(TransitionAttestationError::IncompleteTableGraph)
    ));

    let mut nonzero_nonpresent = graph();
    nonzero_nonpresent.entries.insert((0x1000, 1), ACCESSED);
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut nonzero_nonpresent),
        Err(TransitionAttestationError::InvalidEntry)
    ));

    let mut writable_executable = graph();
    writable_executable
        .entries
        .insert((0x4000, 1), 0x8000 | PRESENT | WRITABLE);
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut writable_executable),
        Err(TransitionAttestationError::InvalidEntry)
    ));

    let mut user_path = graph();
    user_path
        .entries
        .insert((0x1000, 510), 0x2000 | PRESENT | WRITABLE | USER);
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut user_path),
        Err(TransitionAttestationError::InvalidEntry)
    ));

    let mut multiparent = graph();
    multiparent
        .entries
        .insert((0x1000, 1), 0x2000 | PRESENT | WRITABLE);
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut multiparent),
        Err(TransitionAttestationError::AliasedOrCyclicTable)
    ));

    let mut huge = graph();
    huge.entries.insert(
        (0x6000, 1),
        0x20_0000 | PRESENT | WRITABLE | NO_EXECUTE | HUGE,
    );
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut huge),
        Err(TransitionAttestationError::InvalidEntry)
    ));

    let mut above_width = graph();
    above_width
        .entries
        .insert((0x4000, 1), (1_u64 << 40) | PRESENT | NO_EXECUTE);
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut above_width),
        Err(TransitionAttestationError::InvalidEntry)
    ));

    let mut reserved_bit = graph();
    reserved_bit
        .entries
        .insert((0x4000, 1), (1_u64 << 51) | PRESENT | NO_EXECUTE);
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut reserved_bit),
        Err(TransitionAttestationError::InvalidEntry)
    ));
}

#[test]
fn identity_aliases_are_exact_unique_base_page_mappings() {
    let mut ad_drift = graph();
    for frame in (0x1000..=0x7000).step_by(PAGE_SIZE as usize) {
        *ad_drift
            .entries
            .get_mut(&(0x7000, (frame / PAGE_SIZE) as usize))
            .unwrap() |= ACCESSED | DIRTY;
    }
    assert!(attest_transition(cpu(), &handoff(), &mut ad_drift).is_ok());

    let mut missing = graph();
    missing.entries.remove(&(0x7000, 1));
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut missing),
        Err(TransitionAttestationError::IncompleteTableGraph)
    ));

    let mut table_as_data = graph();
    table_as_data
        .entries
        .insert((0x7000, 8), 0x1000 | PRESENT | WRITABLE | NO_EXECUTE);
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut table_as_data),
        Err(TransitionAttestationError::InvalidIdentityAlias)
    ));

    let mut cache_marked = graph();
    *cache_marked.entries.get_mut(&(0x7000, 1)).unwrap() |= WRITE_THROUGH;
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut cache_marked),
        Err(TransitionAttestationError::InvalidEntry)
    ));

    let mut read_only = graph();
    *read_only.entries.get_mut(&(0x7000, 1)).unwrap() &= !WRITABLE;
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut read_only),
        Err(TransitionAttestationError::InvalidIdentityAlias)
    ));

    let mut executable = graph();
    *executable.entries.get_mut(&(0x7000, 1)).unwrap() &= !NO_EXECUTE;
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut executable),
        Err(TransitionAttestationError::InvalidEntry)
    ));

    let mut global = graph();
    *global.entries.get_mut(&(0x7000, 1)).unwrap() |= GLOBAL;
    assert!(matches!(
        attest_transition(cpu(), &handoff(), &mut global),
        Err(TransitionAttestationError::InvalidEntry)
    ));

    for ancestor in [(0x1000, 0), (0x5000, 0), (0x6000, 0)] {
        let mut read_only_path = graph();
        *read_only_path.entries.get_mut(&ancestor).unwrap() &= !WRITABLE;
        assert!(matches!(
            attest_transition(cpu(), &handoff(), &mut read_only_path),
            Err(TransitionAttestationError::InvalidIdentityAlias)
        ));
    }
}

#[test]
fn rejects_non_low_canonical_table_identity_before_first_read() {
    struct NoRead;

    impl TransitionTableReader for NoRead {
        type Error = ();

        fn read_entry(&mut self, _table: FrameAddress, _index: usize) -> Result<u64, Self::Error> {
            panic!("non-canonical table identity reached the reader")
        }
    }

    let mut invalid = handoff();
    invalid.table_frames[6] = LOW_CANONICAL_LIMIT;
    assert_eq!(
        attest_transition(cpu(), &invalid, &mut NoRead).unwrap_err(),
        TransitionAttestationError::InvalidIdentityAlias
    );
}

#[test]
fn scratch_clear_recovers_only_accessed_dirty_drift() {
    let mut backend = graph();
    let attested = attest_transition(cpu(), &handoff(), &mut backend).unwrap();
    let mut mapper = TransitionScratchMapper::from_attested(attested, backend).unwrap();
    mapper.backend.events.clear();
    mapper.backend.next_clear_drift = Some(ACCESSED | DIRTY);
    let mut roles = synthetic_frame_role_manager::<1, 4>(0x8000, 1);
    let allocation = roles.allocate(1).unwrap();
    let zeroed = mapper.zero_allocation(&mut roles, allocation).unwrap();
    roles.cancel_zeroed(zeroed).unwrap();

    let installed = 0x8000 | PRESENT | WRITABLE | NO_EXECUTE;
    assert!(mapper.backend.events.contains(&ScratchEvent::LeafCas {
        current: installed,
        new: 0,
        observed: installed | ACCESSED | DIRTY,
    }));
    assert!(mapper.backend.events.contains(&ScratchEvent::LeafCas {
        current: installed | ACCESSED | DIRTY,
        new: 0,
        observed: installed | ACCESSED | DIRTY,
    }));
    assert_eq!(mapper.backend.entries.get(&(0x4000, 0)), Some(&0));
    assert_eq!(mapper.backend.mapped_frame, None);
}

#[test]
fn hostile_scratch_restore_drift_panics_fail_stop() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    let mut backend = graph();
    let attested = attest_transition(cpu(), &handoff(), &mut backend).unwrap();
    let mut mapper = TransitionScratchMapper::from_attested(attested, backend).unwrap();
    mapper.backend.next_clear_drift = Some(0x1000);
    let mut roles = synthetic_frame_role_manager::<1, 4>(0x8000, 1);
    let allocation = roles.allocate(1).unwrap();

    let result = catch_unwind(AssertUnwindSafe(|| {
        let _ = mapper.zero_allocation(&mut roles, allocation);
    }));
    assert!(result.is_err());
    assert!(mapper.poisoned);
    assert_ne!(mapper.backend.entries.get(&(0x4000, 0)), Some(&0));
    let frame = FrameAddress::new(0xa000, mapper.capabilities().physical_limit()).unwrap();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let _ = mapper.zero_frame_unchecked(frame);
        }))
        .is_err()
    );
}

#[test]
fn foreign_allocation_role_rejection_has_zero_physical_effect() {
    let mut backend = graph();
    let attested = attest_transition(cpu(), &handoff(), &mut backend).unwrap();
    let mut mapper = TransitionScratchMapper::from_attested(attested, backend).unwrap();
    mapper.backend.events.clear();
    mapper.backend.entries.insert((0x8000, 23), u64::MAX);
    let mut owner = synthetic_frame_role_manager::<1, 4>(0x8000, 1);
    let mut foreign = synthetic_frame_role_manager::<1, 4>(0xa000, 1);
    let allocation = owner.allocate(1).unwrap();

    let failure = mapper
        .zero_allocation(&mut foreign, allocation)
        .expect_err("a foreign role manager must reject before mapping");
    assert_eq!(
        failure.error(),
        &TransitionZeroError::FrameRole(FrameRoleError::ForeignManager)
    );
    assert_eq!(mapper.backend.entries.get(&(0x8000, 23)), Some(&u64::MAX));
    assert!(mapper.backend.events.is_empty());
    owner.cancel_allocation(failure.into_grant()).unwrap();
}

#[test]
fn busy_mapper_construction_and_one_shot_claim_do_not_restore_authority() {
    let mut backend = graph();
    let attested = attest_transition(cpu(), &handoff(), &mut backend).unwrap();
    backend
        .entries
        .insert((0x4000, 0), 0x5000 | PRESENT | WRITABLE | NO_EXECUTE);
    assert!(matches!(
        TransitionScratchMapper::from_attested(attested, backend),
        Err(TransitionScratchError::Busy)
    ));

    let state = AtomicU8::new(LIVE_TRANSITION_UNCLAIMED);
    assert_eq!(claim_transition_state(&state), Ok(()));
    assert_eq!(state.load(Ordering::Acquire), LIVE_TRANSITION_ATTESTING);
    state.store(LIVE_TRANSITION_POISONED, Ordering::Release);
    assert_eq!(claim_transition_state(&state), Err(()));
    assert_eq!(state.load(Ordering::Acquire), LIVE_TRANSITION_POISONED);
    state.store(LIVE_TRANSITION_OWNED, Ordering::Release);
    assert_eq!(claim_transition_state(&state), Err(()));
    assert_eq!(state.load(Ordering::Acquire), LIVE_TRANSITION_OWNED);
}

#[test]
#[allow(
    unsafe_code,
    reason = "the synthetic manager helper creates the host-only allocator namespace"
)]
fn mapper_zeroes_complete_grant_before_typed_role_transition() {
    let mut backend = graph();
    let attested = attest_transition(cpu(), &handoff(), &mut backend).unwrap();
    let mut mapper = TransitionScratchMapper::from_attested(attested, backend).unwrap();
    let mut roles = synthetic_frame_role_manager::<1, 8>(0x8000, 2);
    let allocation = roles.allocate(2).unwrap();
    mapper.backend.entries.insert((0x8000, 17), u64::MAX);
    mapper.backend.entries.insert((0x9000, 511), u64::MAX);

    let zeroed = mapper
        .zero_allocation(&mut roles, allocation)
        .expect("the full grant is physically zeroed");
    let _backing = roles.assign_object_backing(zeroed).unwrap();

    for frame in [0x8000, 0x9000] {
        for index in 0..ENTRY_COUNT {
            assert_eq!(mapper.backend.entries.get(&(frame, index)), Some(&0));
        }
    }
    assert_eq!(roles.check_invariants(), Ok(()));
}

#[test]
fn zeroing_failure_returns_live_allocation_grant_for_cancellation() {
    let mut backend = graph();
    let attested = attest_transition(cpu(), &handoff(), &mut backend).unwrap();
    let mut mapper = TransitionScratchMapper::from_attested(attested, backend).unwrap();
    let mut roles = synthetic_frame_role_manager::<1, 4>(0x8000, 1);
    let allocation = roles.allocate(1).unwrap();
    mapper.backend.events.clear();
    mapper.backend.entries.insert((0x8000, 31), u64::MAX);
    let conflict = 0xa000 | PRESENT | WRITABLE | NO_EXECUTE;
    mapper.backend.entries.insert((0x4000, 0), conflict);

    let failure = mapper
        .zero_allocation(&mut roles, allocation)
        .expect_err("an occupied scratch leaf rejects before zeroing");
    assert_eq!(
        failure.error(),
        &TransitionZeroError::Scratch(TransitionScratchError::Busy)
    );
    let installed = 0x8000 | PRESENT | WRITABLE | NO_EXECUTE;
    assert_eq!(
        mapper.backend.events,
        [ScratchEvent::LeafCas {
            current: 0,
            new: installed,
            observed: conflict,
        }]
    );
    assert_eq!(mapper.backend.entries.get(&(0x8000, 31)), Some(&u64::MAX));
    mapper.backend.entries.insert((0x4000, 0), 0);
    roles.cancel_allocation(failure.into_grant()).unwrap();
    assert_eq!(roles.available_frames(), 1);
    assert_eq!(roles.check_invariants(), Ok(()));
}
