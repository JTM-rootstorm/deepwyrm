//! Host tests of a retiring root's table teardown (DW2 §10.14 revision 2
//! items 0 to 5 and the progress rule).

extern crate std;

use std::collections::{BTreeMap, BTreeSet};
use std::vec::Vec;

use super::super::super::super::{PRESENT, PagingCapabilities, USER, WRITABLE};
use super::*;
use crate::arch::x86_64::mm::VirtualPage;
use crate::arch::x86_64::mm::journal::target_seal;
use crate::cpu::CpuIndex;
use crate::memory::address_region::AddressSpaceAuthority;
use crate::memory::frame_roles::{TableOwnerKey, synthetic_frame_role_manager};
use crate::object::ObjectRegistry;
use crate::task::TaskAuthority;

type Roles = FrameRoleManager<128, 256>;
type Bindings = AddressSpaceRootBindings<2, 2>;

/// A flat page-table model that records every entry read, by table frame.
#[derive(Default)]
struct CountingTarget {
    entries: BTreeMap<(u64, usize), u64>,
    reads: Vec<u64>,
}

impl CountingTarget {
    fn link(&mut self, parent: TableIdentity, index: usize, child: TableIdentity) {
        self.entries.insert(
            (parent.physical_start(), index),
            child.physical_start() | PRESENT | WRITABLE | USER,
        );
    }

    fn reads_of(&self, table: TableIdentity) -> usize {
        self.reads
            .iter()
            .filter(|frame| **frame == table.physical_start())
            .count()
    }
}

impl target_seal::Sealed for CountingTarget {}

#[allow(
    unsafe_code,
    reason = "the host-only flat table target applies an in-memory write batch at once"
)]
// SAFETY: a host model with no CPU: each batch is applied whole, at once.
unsafe impl AtomicPageTableTarget for CountingTarget {
    type Error = ();

    fn read_entry(&mut self, table: FrameAddress, index: usize) -> Result<u64, Self::Error> {
        self.reads.push(table.address());
        Ok(*self.entries.get(&(table.address(), index)).unwrap_or(&0))
    }

    fn zero_table_frame(&mut self, frame: FrameAddress) -> Result<(), Self::Error> {
        self.entries
            .retain(|(table, _), _| *table != frame.address());
        Ok(())
    }

    fn apply(
        &mut self,
        writes: &[JournalWrite],
        _invalidations: &[VirtualPage],
    ) -> Result<(), Self::Error> {
        for write in writes {
            self.entries
                .insert((write.table().address(), write.index()), write.value());
        }
        Ok(())
    }
}

#[allow(
    unsafe_code,
    reason = "synthetic host tables model completed physical zeroing"
)]
fn commit_table(
    roles: &mut Roles,
    owner: TableOwnerKey,
    level: TableLevel,
    parent: Option<TableIdentity>,
) -> TableIdentity {
    let allocation = roles.allocate(1).unwrap();
    // SAFETY: the host model never dereferences synthetic frames.
    let zeroed = unsafe { roles.assume_zeroed(allocation) }.unwrap();
    let candidate = roles.prepare_table(zeroed, owner, level).unwrap();
    roles.commit_table(candidate, parent).unwrap()
}

/// A primordial root A and an exited child B, bound, with B's quiescence
/// proof and the registry charging B.
struct Fixture {
    roles: Roles,
    bindings: Bindings,
    target: CountingTarget,
    pins: UserPinTracker<1>,
    primordial: ProcessKey,
    child: ProcessKey,
    primordial_space: AddressSpaceKey,
    space: AddressSpaceKey,
    root: TableIdentity,
    proof: ProcessQuiescenceProof,
    registry: ObjectRegistry<16>,
    _tasks: TaskAuthority<1, 2, 1, 4>,
}

impl Fixture {
    #[allow(
        unsafe_code,
        reason = "synthetic roots and authority keys model the host-only root-binding contract"
    )]
    fn new() -> Self {
        let mut roles = synthetic_frame_role_manager::<128, 256>(0x100_000, 200);
        let owner_a = roles.create_table_owner().unwrap();
        let owner_b = roles.create_table_owner().unwrap();
        let identity_a = commit_table(&mut roles, owner_a, TableLevel::Pml4, None);
        let root = commit_table(&mut roles, owner_b, TableLevel::Pml4, None);
        let capabilities = PagingCapabilities::validate(40, true, true, true).unwrap();
        // SAFETY: the synthetic role manager authenticated these exact roots.
        let root_a =
            unsafe { PageTableRoot::from_owned_root(identity_a.physical_start(), capabilities) }
                .unwrap();
        // SAFETY: as above.
        let root_b =
            unsafe { PageTableRoot::from_owned_root(root.physical_start(), capabilities) }.unwrap();
        let mut registry = ObjectRegistry::<16>::new();
        let mut tasks = TaskAuthority::<1, 2, 1, 4>::new();
        let (_group, owner) = tasks.create_root_group(&mut registry).unwrap();
        let (primordial, _primordial_owner) = tasks.create_process(&mut registry, &owner).unwrap();
        let (child, _child_owner) = tasks.create_process(&mut registry, &owner).unwrap();
        drop(tasks.terminate_process_authorized(child, 0).unwrap());
        let proof = tasks.process_quiescence_proof(child).unwrap();
        // SAFETY: this test-local authority is the only registry for its two
        // synthetic roots and outlives every key it issues.
        let mut authority = unsafe { AddressSpaceAuthority::<2, 2>::new() };
        let primordial_space = authority.create_address_space().unwrap();
        let space = authority.create_address_space().unwrap();
        let mut bindings = Bindings::new();
        bindings
            .bind_primordial(&roles, primordial_space, primordial, &root_a, identity_a)
            .unwrap();
        bindings
            .bind_owned(&roles, space, child, root_b, root)
            .unwrap_or_else(|_| panic!("the child root binds"));
        Self {
            roles,
            bindings,
            target: CountingTarget::default(),
            pins: UserPinTracker::<1>::new(),
            primordial,
            child,
            primordial_space,
            space,
            root,
            proof,
            registry,
            _tasks: tasks,
        }
    }

    fn owner(&self) -> TableOwnerKey {
        self.root.owner()
    }

    fn table(&mut self, level: TableLevel, parent: TableIdentity, index: usize) -> TableIdentity {
        let owner = self.owner();
        let table = commit_table(&mut self.roles, owner, level, Some(parent));
        self.target.link(parent, index, table);
        table
    }

    /// A page table with a present leaf in every slot named.
    fn page_table(
        &mut self,
        parent: TableIdentity,
        index: usize,
        leaves: &[usize],
    ) -> TableIdentity {
        let table = self.table(TableLevel::Pt, parent, index);
        for &leaf in leaves {
            self.target.entries.insert(
                (table.physical_start(), leaf),
                0x9000_0000 | (leaf as u64) << 12 | PRESENT | USER,
            );
        }
        table
    }

    fn step(&mut self) -> Result<TableTeardownStep, RootBindingError> {
        let reservation = self.pins.reserve_teardown(self.space).unwrap();
        self.bindings.teardown_tables_step(
            &mut self.roles,
            &mut self.target,
            self.child,
            self.space,
            &self.pins,
            reservation,
        )
    }

    fn table_count(&self) -> u32 {
        self.roles.hierarchy_table_count(self.root).unwrap()
    }

    /// Steps until no table remains, checking each step against the
    /// bounds and the progress rule; the steps taken.
    fn steps_to_empty(&mut self) -> Vec<TableTeardownStep> {
        let mut steps = Vec::new();
        while self.table_count() != 0 {
            let before = self.table_count();
            let step = self.step().unwrap();
            assert!(step.freed() >= 1, "a step freed nothing: {step:?}");
            assert!(step.freed() <= TEARDOWN_STEP_TABLES);
            assert!(step.read() <= TEARDOWN_FIRST_FREE_ENTRIES);
            assert_eq!(before - self.table_count(), step.freed());
            assert_eq!(step.remaining(), self.table_count() != 0);
            assert_eq!(self.roles.check_invariants(), Ok(()));
            steps.push(step);
            assert!(steps.len() <= 64, "teardown did not converge");
        }
        steps
    }

    fn teardown_root(&mut self) -> Result<(), RootBindingError> {
        let reservation = self.pins.reserve_teardown(self.space).unwrap();
        self.bindings.teardown_empty_owned(
            &mut self.roles,
            &mut self.target,
            self.child,
            self.space,
            &self.pins,
            reservation,
        )
    }
}

/// Item 2: page tables are freed without a read of their entries, whatever
/// leaves they hold, and a step stops at 64 frees or, once it has freed one,
/// at 512 entries read. The root's proof afterwards reads only the PML4's
/// user entries (item 3), and every frame comes back.
#[test]
fn page_tables_are_freed_unread_and_each_step_is_bounded() {
    let mut fixture = Fixture::new();
    let initial = fixture.roles.available_frames();
    let pdpt = fixture.table(TableLevel::Pdpt, fixture.root, 0);
    let pd = fixture.table(TableLevel::Pd, pdpt, 0);
    let page_tables: Vec<_> = (0..100)
        .map(|index| fixture.page_table(pd, index, &[0, 7, 511]))
        .collect();
    assert_eq!(fixture.table_count(), 102);
    fixture
        .bindings
        .begin_retiring(fixture.child, fixture.space)
        .unwrap();

    let steps = fixture.steps_to_empty();
    // 64 page tables after three reads down; then the other 36 and the PD
    // read up to the 512-entry bound; then the PD, freed once its last
    // entry is read (past the bound, which ends a step only after a free);
    // then the PDPT. At 2 MiB a step, the 200 MiB they mapped took 100.
    let freed: Vec<_> = steps.iter().map(|step| step.freed()).collect();
    let read: Vec<_> = steps.iter().map(|step| step.read()).collect();
    assert_eq!(freed, [TEARDOWN_STEP_TABLES, 36, 1, 1]);
    assert_eq!(read, [3 + 63, TEARDOWN_STEP_ENTRIES, 2 + 512, 1 + 512]);
    for table in &page_tables {
        assert_eq!(fixture.target.reads_of(*table), 0, "a page table was read");
        assert!(fixture.roles.validate_table_identity(*table).is_err());
    }
    assert!(fixture.target.reads_of(pd) > 0);

    fixture.target.reads.clear();
    fixture.teardown_root().unwrap();
    assert!(
        fixture
            .target
            .reads
            .iter()
            .all(|frame| *frame == fixture.root.physical_start()),
        "the root's proof read below the root"
    );
    assert_eq!(fixture.target.reads.len(), 256);
    assert_eq!(fixture.roles.available_frames(), initial + 1);
    assert_eq!(fixture.roles.check_invariants(), Ok(()));
    assert_eq!(
        fixture.bindings.is_retiring(fixture.child, fixture.space),
        Err(RootBindingError::Missing)
    );
}

/// The progress rule: a root whose only mapping sits at the last PML4 user
/// entry, the last PDPT entry and the last PD entry is torn down in three
/// steps, each freeing a table and none reading more than 256 + 512 + 512
/// entries, though each must descend past 1,280 entries first.
#[test]
fn the_highest_mapping_is_torn_down_one_table_per_step_within_the_bound() {
    let mut fixture = Fixture::new();
    let pdpt = fixture.table(TableLevel::Pdpt, fixture.root, 255);
    let pd = fixture.table(TableLevel::Pd, pdpt, 511);
    let pt = fixture.page_table(pd, 511, &[511]);
    fixture
        .bindings
        .begin_retiring(fixture.child, fixture.space)
        .unwrap();

    let steps = fixture.steps_to_empty();
    assert_eq!(steps.len(), 3);
    assert!(steps.iter().all(|step| step.freed() == 1));
    assert_eq!(steps[0].read(), TEARDOWN_FIRST_FREE_ENTRIES);
    assert_eq!(steps[2].read(), 256 + 512);
    assert_eq!(fixture.target.reads_of(pt), 0);
    assert_eq!(
        fixture
            .target
            .entries
            .get(&(fixture.root.physical_start(), 255)),
        Some(&0)
    );
    fixture.teardown_root().unwrap();
}

/// Item 2: a large leaf in a PD or a PDPT is refused, not read as a table,
/// and nothing is freed.
#[test]
fn a_large_leaf_is_refused() {
    for level in [TableLevel::Pd, TableLevel::Pdpt] {
        let mut fixture = Fixture::new();
        let pdpt = fixture.table(TableLevel::Pdpt, fixture.root, 3);
        let holder = match level {
            TableLevel::Pd => fixture.table(TableLevel::Pd, pdpt, 9),
            TableLevel::Pdpt => pdpt,
            TableLevel::Pml4 | TableLevel::Pt => {
                unreachable!("only PDs and PDPTs hold large leaves")
            }
        };
        fixture.target.entries.insert(
            (holder.physical_start(), 17),
            0x4000_0000 | HUGE | PRESENT | WRITABLE | USER,
        );
        fixture
            .bindings
            .begin_retiring(fixture.child, fixture.space)
            .unwrap();
        let free = fixture.roles.available_frames();
        let tables = fixture.table_count();
        assert_eq!(fixture.step(), Err(RootBindingError::LargeLeaf));
        assert_eq!(fixture.roles.available_frames(), free);
        assert_eq!(fixture.table_count(), tables);
    }
}

/// Items 0, 1 and 4: the teardown publisher exists only for an owned,
/// retiring root with no CPU resident and the Process's own proof; a root
/// with a resident cannot begin retiring; once retiring, no CPU may enter
/// it, no session may select it, and a table step refuses a root that is
/// not retiring.
#[test]
fn only_a_retiring_owned_root_without_residents_gets_a_teardown_publisher() {
    let mut fixture = Fixture::new();
    let bindings = &fixture.bindings;
    let (child, space) = (fixture.child, fixture.space);
    assert_eq!(
        bindings
            .retiring_teardown_publisher(
                fixture.primordial,
                fixture.primordial_space,
                &fixture.proof
            )
            .err(),
        Some(RootBindingError::ProcessMismatch)
    );
    assert_eq!(
        bindings
            .begin_retiring(fixture.primordial, fixture.primordial_space)
            .err(),
        Some(RootBindingError::RootMismatch)
    );
    assert_eq!(
        bindings
            .retiring_teardown_publisher(child, space, &fixture.proof)
            .err(),
        Some(RootBindingError::NotRetiring)
    );

    let resident = bindings
        .prepare_selection(CpuIndex::BOOTSTRAP, child, space)
        .unwrap();
    assert_eq!(
        bindings.begin_retiring(child, space).err(),
        Some(RootBindingError::Resident)
    );
    assert_eq!(bindings.is_retiring(child, space), Ok(false));
    bindings.abandon_selection(resident).unwrap();

    bindings.begin_retiring(child, space).unwrap();
    bindings.begin_retiring(child, space).unwrap();
    assert_eq!(bindings.is_retiring(child, space), Ok(true));
    assert_eq!(
        bindings
            .prepare_selection(CpuIndex::BOOTSTRAP, child, space)
            .err(),
        Some(RootBindingError::Retiring)
    );
    let cpu1 = CpuIndex::new(1).unwrap();
    assert_eq!(
        bindings.prepare_selection(cpu1, child, space).err(),
        Some(RootBindingError::Retiring)
    );
    assert_eq!(bindings.resident_count(child, space), Ok(0));
    let placeholder = bindings
        .root_for_process(
            // Any root stands in for the primordial; the child's is refused
            // before it is looked at.
            match &bindings.binding(child, space).unwrap().storage {
                RootStorage::Owned(root) => root,
                RootStorage::Primordial => unreachable!("the child's root is owned"),
            },
            child,
        )
        .err();
    assert_eq!(placeholder, Some(RootBindingError::Retiring));
    let publisher = bindings
        .retiring_teardown_publisher(child, space, &fixture.proof)
        .unwrap();
    assert_eq!(publisher.address_space_key(), space);

    // A table step needs a retiring root.
    let mut other = Fixture::new();
    assert_eq!(other.step(), Err(RootBindingError::NotRetiring));
    fixture.teardown_root().unwrap();
}

/// Item 4: a synchronous teardown of a retiring root whose tables remain
/// fails closed, reading no table below the root and changing nothing.
#[test]
fn a_synchronous_teardown_of_a_retiring_root_fails_closed() {
    let mut fixture = Fixture::new();
    let pdpt = fixture.table(TableLevel::Pdpt, fixture.root, 1);
    let pd = fixture.table(TableLevel::Pd, pdpt, 2);
    fixture.page_table(pd, 3, &[4]);
    fixture
        .bindings
        .begin_retiring(fixture.child, fixture.space)
        .unwrap();
    let free = fixture.roles.available_frames();
    let entries = fixture.target.entries.clone();
    assert_eq!(fixture.teardown_root(), Err(RootBindingError::Retiring));
    let below: BTreeSet<u64> = fixture.target.reads.iter().copied().collect();
    assert_eq!(
        below.into_iter().collect::<Vec<_>>(),
        [fixture.root.physical_start()]
    );
    assert_eq!(fixture.roles.available_frames(), free);
    assert_eq!(fixture.target.entries, entries);
    assert_eq!(fixture.table_count(), 3);
    assert_eq!(
        fixture.bindings.is_retiring(fixture.child, fixture.space),
        Ok(true)
    );

    fixture.steps_to_empty();
    fixture.teardown_root().unwrap();
}

/// Item 2: tables are freed without touching any charge: the Process's
/// weight, which holds its fault-built tables, is the same before and after
/// (it falls at Process finalization).
#[test]
fn the_processs_weight_is_unchanged_by_the_table_steps() {
    let mut fixture = Fixture::new();
    let pdpt = fixture.table(TableLevel::Pdpt, fixture.root, 0);
    let pd = fixture.table(TableLevel::Pd, pdpt, 0);
    for index in 0..8 {
        fixture.page_table(pd, index, &[index]);
    }
    let process = fixture.child.object_id();
    fixture.registry.set_charge_pages(process, 10).unwrap();
    let before = fixture.registry.charge(process).unwrap();
    fixture
        .bindings
        .begin_retiring(fixture.child, fixture.space)
        .unwrap();
    fixture.steps_to_empty();
    fixture.teardown_root().unwrap();
    assert_eq!(fixture.registry.charge(process).unwrap(), before);
    assert_eq!(before.1, 10);
}
