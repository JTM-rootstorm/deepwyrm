//! The in-place writers of DW2 §12.6 item 3 against their definition:
//! `occupy` and `vacate` must leave the table, both lists, the free-slot
//! count and the start index exactly as `store` would. Two managers built
//! alike are driven through one long generated sequence, one through
//! `occupy` and `vacate`, the other through `store` with the start index
//! set and cleared by hand, and compared after every operation.

extern crate std;

use super::super::physical::PhysicalAddressLimit;
use super::*;
use std::vec::Vec;

const PAGE: u64 = BASE_PAGE_SIZE;
/// Free ranges for every hole the live runs can leave at boot.
type Manager = FrameRoleManager<64, 64>;

/// Index memory whose every entry reads as empty: roots with no pages.
struct EmptyIndex;

impl IndexMemory for EmptyIndex {
    fn read(&self, _node: u64, _entry: usize) -> u64 {
        0
    }

    #[allow(
        unsafe_code,
        reason = "the model implements the trait's unsafe methods"
    )]
    unsafe fn write(&self, _node: u64, _entry: usize, _value: u64) {
        panic!("the writer test links no index entry");
    }

    #[allow(
        unsafe_code,
        reason = "the model implements the trait's unsafe methods"
    )]
    unsafe fn zero(&self, _page: u64) -> bool {
        true
    }
}

static EMPTY_INDEX: EmptyIndex = EmptyIndex;

/// A manager over `page_count` pages at 1 MiB, in `domain` if given.
fn manager(page_count: u64, domain: Option<u64>) -> Manager {
    let limit = PhysicalAddressLimit::new(1_u64 << 52).unwrap();
    let candidate = PageRange::from_page_count(0x10_0000, page_count, limit).unwrap();
    let allocator = PhysicalFrameAllocator::from_candidates(&[candidate], limit, []).unwrap();
    let mut roles = Manager::new(allocator).unwrap();
    if let Some(domain) = domain {
        roles.domain = domain;
    }
    roles.set_index_memory(&EMPTY_INDEX);
    roles
}

/// Grows from three staged runs.
fn grow(roles: &mut Manager) {
    test_support::grow_in_leaked_runs(roles, 3);
}

/// A fixed-seed xorshift generator.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// Roles of every kind; `KINDS` of them, the first `DYNAMIC` dynamic.
const KINDS: u64 = 18;
const DYNAMIC: u64 = 14;
/// Bays for external runs, outside the allocator, each wide enough for the
/// longest run a slot stores.
const BAYS: usize = 64;
const BAY_BASE: u64 = 1 << 46;
const BAY_SPAN: u64 = 1 << 45;

/// Whether `role` is a PML4 candidate or a committed PML4.
fn is_pml4(role: FrameRole) -> bool {
    matches!(
        role,
        FrameRole::TableCandidate {
            level: TableLevel::Pml4,
            ..
        } | FrameRole::PageTable {
            level: TableLevel::Pml4,
            ..
        }
    )
}

/// The reference: the slot written by `store`, the start index by hand.
fn store_occupy(roles: &mut Manager, slot: usize, generation: u32, record: RoleRecord) {
    roles.store(slot, generation, Some(record));
    if record.role.is_dynamic()
        && let Some(position) = roles.allocator.page_position(record.range.start)
        && let Some(starts) = roles.starts.as_deref_mut()
    {
        starts[position] = slot as u32 + 1;
    }
    roles.version = roles.version.wrapping_add(1);
}

fn store_vacate(roles: &mut Manager, slot: usize) {
    let generation = roles.live_generation(slot).unwrap();
    let record = roles.record_at(slot).unwrap();
    roles.store(slot, generation, None);
    if record.role.is_dynamic()
        && let Some(position) = roles.allocator.page_position(record.range.start)
        && let Some(starts) = roles.starts.as_deref_mut()
    {
        starts[position] = 0;
    }
    roles.version = roles.version.wrapping_add(1);
}

/// Both managers, slot for slot and list for list.
fn assert_same(fast: &Manager, reference: &Manager, step: usize) {
    assert!(
        fast.slot_views().eq(reference.slot_views()),
        "slots differ after step {step}"
    );
    assert_eq!(fast.first_free, reference.first_free, "step {step}");
    assert_eq!(fast.first_root, reference.first_root, "step {step}");
    assert_eq!(
        fast.free_slot_count, reference.free_slot_count,
        "step {step}"
    );
    for depth in 0..3 {
        assert_eq!(
            fast.free_slot(depth),
            reference.free_slot(depth),
            "step {step}"
        );
    }
    assert_eq!(
        fast.starts.as_deref(),
        reference.starts.as_deref(),
        "step {step}"
    );
    assert_eq!(fast.version, reference.version, "step {step}");
}

/// One live slot as the driver knows it.
#[derive(Clone, Copy)]
struct Live {
    slot: usize,
    identity: FrameRoleIdentity,
    range: PageRange,
    /// The bay of an external run.
    bay: Option<usize>,
}

/// The driver: what is live, and the counters roles draw from.
struct Driver {
    rng: Rng,
    domain: u64,
    live: Vec<Live>,
    bays: [bool; BAYS],
    next_owner: u64,
    cap: usize,
    occupied: u64,
    spent: u64,
    /// Slots occupied with each kind of role.
    kinds: [u64; KINDS as usize],
    /// Slots of PML4 level vacated, and slots retired.
    vacated_roots: u64,
    retired: u64,
}

impl Driver {
    fn owner(&mut self) -> TableOwnerKey {
        self.next_owner += 1;
        TableOwnerKey {
            domain: self.domain,
            raw: self.next_owner,
        }
    }

    /// A role of `kind` for the run `identity` names. A PML4 takes a fresh
    /// owner, so no owner has two slots on the root list.
    fn role(&mut self, kind: u64, identity: FrameRoleIdentity) -> FrameRole {
        let lower = [TableLevel::Pdpt, TableLevel::Pd, TableLevel::Pt];
        let level = lower[self.rng.below(3) as usize];
        let entry = IndexEntryLink {
            owner: self.rng.next(),
            place: self.rng.next(),
        };
        let own_chain = ChainLink {
            head: identity.raw,
            object_page: 0,
            next: 0,
        };
        match kind {
            0 => FrameRole::AllocatedUninitialized,
            1 => FrameRole::Zeroed,
            2 => FrameRole::BackingAllocated(own_chain),
            3 => FrameRole::ObjectBacking(own_chain),
            4 => FrameRole::ArchitectureBootstrap(ArchitectureBootstrapKind::X86ApTrampoline),
            5 => FrameRole::ArchitectureBootstrap(ArchitectureBootstrapKind::X86VtdTable),
            6 => FrameRole::TableCandidate {
                owner: self.owner(),
                level: TableLevel::Pml4,
            },
            7 => FrameRole::TableCandidate {
                owner: self.owner(),
                level,
            },
            8 => FrameRole::PageTable {
                owner: self.owner(),
                level: TableLevel::Pml4,
                parent: None,
            },
            9 => FrameRole::PageTable {
                owner: self.owner(),
                level,
                parent: Some(FrameRoleIdentity {
                    domain: self.domain,
                    raw: self.rng.next(),
                }),
            },
            10 => FrameRole::RoleTableStorage,
            11 => FrameRole::IndexRoot(IndexRootLink {
                pages: 1 + self.rng.below(512),
                levels: 1,
                state: IndexRootState::OnDemand,
            }),
            12 => FrameRole::IndexNode(entry),
            13 => FrameRole::ObjectPage(entry),
            14 => FrameRole::External(ExternalFrameRole::TransitionTable {
                table_index: self.rng.next() as u32,
            }),
            15 => FrameRole::External(ExternalFrameRole::KernelImage {
                segment: KernelImageSegment::ReadOnlyData,
            }),
            16 => FrameRole::ExternalImmutableModule {
                module_index: self.rng.next() as u32,
            },
            _ => FrameRole::ExternalDeviceMmio,
        }
    }

    /// Occupies the next free slot in both managers with a role of a
    /// random kind; the run comes from both allocators alike, or from a
    /// free bay for an external role.
    fn occupy(&mut self, fast: &mut Manager, reference: &mut Manager) {
        if self.live.len() >= self.cap {
            return;
        }
        let Ok((slot, generation)) = fast.next_slot() else {
            assert_eq!(reference.next_slot(), Err(FrameRoleError::Capacity));
            return;
        };
        assert_eq!(reference.next_slot(), Ok((slot, generation)));
        let identity = fast.identity(slot, generation).unwrap();
        let kind = self.rng.below(KINDS);
        let (range, bay) = if kind < DYNAMIC {
            let pages = 1 + self.rng.below(3);
            let Ok(range) = fast.allocator.allocate_run(pages) else {
                return;
            };
            assert_eq!(reference.allocator.allocate_run(pages), Ok(range));
            (range, None)
        } else {
            let Some(bay) = self.bays.iter().position(|used| !used) else {
                return;
            };
            self.bays[bay] = true;
            // One page, a few, or the most a slot stores.
            let pages = match self.rng.below(4) {
                0 => u64::from(u32::MAX),
                count => count,
            };
            let start = BAY_BASE + bay as u64 * BAY_SPAN;
            (
                PageRange {
                    start,
                    end: start + pages * PAGE,
                },
                Some(bay),
            )
        };
        let record = RoleRecord {
            range,
            role: self.role(kind, identity),
        };
        fast.occupy(slot, generation, record);
        store_occupy(reference, slot, generation, record);
        self.live.push(Live {
            slot,
            identity,
            range,
            bay,
        });
        self.occupied += 1;
        self.kinds[kind as usize] += 1;
        if generation == u32::MAX {
            self.spent += 1;
        }
    }

    fn vacate(&mut self, fast: &mut Manager, reference: &mut Manager, index: usize) {
        let live = self.live.swap_remove(index);
        match live.bay {
            Some(bay) => self.bays[bay] = false,
            None => {
                fast.allocator.free_run(live.range).unwrap();
                reference.allocator.free_run(live.range).unwrap();
            }
        }
        if fast.live_generation(live.slot) == Some(u32::MAX) {
            self.retired += 1;
        }
        if fast
            .record_at(live.slot)
            .is_some_and(|record| is_pml4(record.role))
        {
            self.vacated_roots += 1;
        }
        fast.vacate(live.slot);
        store_vacate(reference, live.slot);
    }

    /// Replaces a live record with another role of its class (dynamic or
    /// external), through `replace_record` in both: it stays on `store`.
    /// A PML4 kept at PML4 level keeps its owner, so a candidate can become
    /// a root.
    fn replace(&mut self, fast: &mut Manager, reference: &mut Manager, index: usize) {
        let live = self.live[index];
        let kind = if live.bay.is_some() {
            DYNAMIC + self.rng.below(KINDS - DYNAMIC)
        } else {
            self.rng.below(DYNAMIC)
        };
        let mut role = self.role(kind, live.identity);
        let old = fast.record_at(live.slot).unwrap().role;
        let old_owner = match old {
            FrameRole::TableCandidate {
                owner,
                level: TableLevel::Pml4,
            }
            | FrameRole::PageTable {
                owner,
                level: TableLevel::Pml4,
                ..
            } => Some(owner),
            FrameRole::AllocatedUninitialized
            | FrameRole::Zeroed
            | FrameRole::BackingAllocated(_)
            | FrameRole::ObjectBacking(_)
            | FrameRole::ArchitectureBootstrap(_)
            | FrameRole::TableCandidate { .. }
            | FrameRole::PageTable { .. }
            | FrameRole::External(_)
            | FrameRole::ExternalImmutableModule { .. }
            | FrameRole::ExternalDeviceMmio
            | FrameRole::RoleTableStorage
            | FrameRole::IndexRoot(_)
            | FrameRole::IndexNode(_)
            | FrameRole::ObjectPage(_) => None,
        };
        if let Some(kept) = old_owner {
            match &mut role {
                FrameRole::TableCandidate {
                    owner,
                    level: TableLevel::Pml4,
                }
                | FrameRole::PageTable {
                    owner,
                    level: TableLevel::Pml4,
                    ..
                } => *owner = kept,
                FrameRole::AllocatedUninitialized
                | FrameRole::Zeroed
                | FrameRole::BackingAllocated(_)
                | FrameRole::ObjectBacking(_)
                | FrameRole::ArchitectureBootstrap(_)
                | FrameRole::TableCandidate { .. }
                | FrameRole::PageTable { .. }
                | FrameRole::External(_)
                | FrameRole::ExternalImmutableModule { .. }
                | FrameRole::ExternalDeviceMmio
                | FrameRole::RoleTableStorage
                | FrameRole::IndexRoot(_)
                | FrameRole::IndexNode(_)
                | FrameRole::ObjectPage(_) => {}
            }
        }
        let record = RoleRecord {
            range: live.range,
            role,
        };
        fast.replace_record(live.slot, record);
        reference.replace_record(live.slot, record);
    }

    /// Gives a live committed table a mark and a count, in both.
    fn mark(&mut self, fast: &mut Manager, reference: &mut Manager, index: usize) {
        let slot = self.live[index].slot;
        if fast.table_at(slot).is_none() {
            return;
        }
        let (epoch, count) = (self.rng.next(), self.rng.next() as u32);
        for roles in [&mut *fast, &mut *reference] {
            roles.set_mark(slot, epoch);
            roles.set_tables(slot, count);
        }
    }

    /// Drives the head of the free list to its last generation in both, so
    /// its next use retires it.
    fn spend(fast: &mut Manager, reference: &mut Manager) {
        if let Ok((slot, _)) = fast.next_slot() {
            fast.test_set_generation(slot, u32::MAX - 1);
            reference.test_set_generation(slot, u32::MAX - 1);
        }
    }

    fn step(&mut self, fast: &mut Manager, reference: &mut Manager, step: usize) {
        if step % 400 == 200 {
            Self::spend(fast, reference);
        }
        let choice = self.rng.below(10);
        if self.live.is_empty() || choice < 4 {
            self.occupy(fast, reference);
        } else {
            let index = self.rng.below(self.live.len() as u64) as usize;
            match choice {
                4..=6 => self.vacate(fast, reference, index),
                7 | 8 => self.replace(fast, reference, index),
                _ => self.mark(fast, reference, index),
            }
        }
    }
}

/// Drives `fast` and `reference`, built alike, through `steps` generated
/// operations, comparing them after each, and checks both at the end.
fn drive(mut fast: Manager, mut reference: Manager, seed: u64, steps: usize, cap: usize) {
    assert_same(&fast, &reference, 0);
    let mut driver = Driver {
        rng: Rng(seed),
        domain: fast.domain,
        live: Vec::new(),
        bays: [false; BAYS],
        next_owner: 0,
        cap,
        occupied: 0,
        spent: 0,
        kinds: [0; KINDS as usize],
        vacated_roots: 0,
        retired: 0,
    };
    for step in 1..=steps {
        driver.step(&mut fast, &mut reference, step);
        assert_same(&fast, &reference, step);
    }
    assert!(driver.occupied > steps as u64 / 4, "the sequence occupies");
    assert!(driver.spent >= 1, "the sequence spends a generation");
    assert!(
        driver.kinds.iter().all(|count| *count > 0),
        "every kind is occupied: {:?}",
        driver.kinds
    );
    assert!(driver.vacated_roots > 0, "a slot of PML4 level is vacated");
    assert!(driver.retired > 0, "a spent slot is retired");
    // Index nodes and pages no root reaches would fail the index check, and
    // table storage that is not the grown table's would fail the storage
    // check: vacate them, then check both managers whole.
    while let Some(index) = driver.live.iter().position(|live| {
        matches!(
            fast.record_at(live.slot).map(|record| record.role),
            Some(FrameRole::IndexNode(_) | FrameRole::ObjectPage(_) | FrameRole::RoleTableStorage)
        )
    }) {
        driver.vacate(&mut fast, &mut reference, index);
        assert_same(&fast, &reference, steps);
    }
    assert_eq!(fast.check_invariants(), Ok(()));
    assert_eq!(reference.check_invariants(), Ok(()));
}

/// Every role kind's slot is occupied, replaced, marked and vacated on a
/// manager with only its boot table, and the fast writers leave exactly
/// what `store` leaves.
#[test]
fn occupy_and_vacate_leave_what_store_leaves_on_a_boot_sized_manager() {
    let fast = manager(1024, None);
    let reference = manager(1024, Some(fast.domain));
    drive(fast, reference, 0x9e37_79b9_7f4a_7c15, 6000, 48);
}

/// The same on a grown manager, where the start index is kept.
#[test]
fn occupy_and_vacate_leave_what_store_leaves_on_a_grown_manager() {
    let mut fast = manager(1024, None);
    let mut reference = manager(1024, Some(fast.domain));
    grow(&mut fast);
    grow(&mut reference);
    assert!(fast.starts.is_some());
    drive(fast, reference, 0xd1b5_4a32_d192_ed03, 6000, 200);
}
