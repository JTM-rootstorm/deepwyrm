extern crate std;

use super::*;
use crate::memory::address_region::{
    AddressSpaceKey, FaultWindows, Protection, WindowCharges, WindowOpening, test_mapping,
};
use crate::object::{ObjectId, ObjectRegistry};
use deepwyrm_abi::DW_OBJECT_TYPE_EVENT;
use std::vec::Vec;

const PAGE: u64 = 4096;
const START: u64 = 0x40_0000;
const CPUS: usize = 2;
const WRITE_FAULT: u64 = 1 << 2 | 1 << 1;
const READ_FAULT: u64 = 1 << 2;
const FETCH_FAULT: u64 = 1 << 2 | 1 << 4;

fn ids(count: usize) -> Vec<ObjectId> {
    let mut registry = ObjectRegistry::<32>::new();
    (0..count)
        .map(|_| registry.create(DW_OBJECT_TYPE_EVENT).unwrap().id())
        .collect()
}

/// The registry in miniature: each object's weight, and a room limit for
/// admission.
struct Weights {
    objects: Vec<(ObjectId, u64)>,
    room: u64,
}

impl Weights {
    fn weight(&self, object: ObjectId) -> u64 {
        self.objects
            .iter()
            .find(|entry| entry.0 == object)
            .unwrap()
            .1
    }

    fn entry(&mut self, object: ObjectId) -> &mut u64 {
        &mut self
            .objects
            .iter_mut()
            .find(|entry| entry.0 == object)
            .unwrap()
            .1
    }
}

impl WindowCharges for Weights {
    fn admit(&self, _object: ObjectId, frames: u64) -> bool {
        self.objects.iter().map(|entry| entry.1).sum::<u64>() + frames <= self.room
    }

    fn add(&mut self, object: ObjectId, frames: u64) {
        let weight = self.entry(object);
        *weight = weight.checked_add(frames).unwrap();
    }

    fn subtract(&mut self, object: ObjectId, frames: u64) {
        let weight = self.entry(object);
        *weight = weight.checked_sub(frames).unwrap();
    }
}

/// One mapped object: its mapping, the pages committed for it, and the
/// frames those took (a page and any index nodes).
struct Object {
    id: ObjectId,
    mapping: Mapping,
    committed: Vec<u64>,
    frames: u64,
}

/// The paging a fast serve sees, as a model: this CPU's window table, the
/// committed pages and present leaves, and a knob for every refusal.
struct Model {
    cpu: usize,
    windows: FaultWindows<u32, CPUS>,
    weights: Weights,
    objects: Vec<Object>,
    leaves: Vec<u64>,
    executing: (Option<ThreadKey>, u64),
    root: u32,
    session_refused: bool,
    scheduler_refuses: bool,
    publisher_refused: bool,
    tables_missing: bool,
    /// Index nodes a commit of an absent page takes besides the page.
    nodes: u64,
    /// The commit's cost cannot be asked.
    cost_unaskable: bool,
    commit_refused: bool,
    write_fails: bool,
    return_refused: bool,
    /// The paging is a shared hold's (DW2 §15.2): a commit takes no frame,
    /// an uncommitted page is `NotCommitted`, and nothing may be spent.
    shared: bool,
    /// What the serve asked, in order.
    calls: Vec<&'static str>,
    stamps: Vec<FastStamp>,
}

struct ModelLeaf<'a> {
    model: &'a mut Model,
}

impl Model {
    fn object_of(&mut self, mapping: &Mapping) -> &mut Object {
        self.objects
            .iter_mut()
            .find(|object| object.mapping == *mapping)
            .expect("a mapped object")
    }

    fn committed_frames(&self, object: ObjectId) -> u64 {
        self.objects
            .iter()
            .filter(|entry| entry.id == object)
            .map(|entry| entry.frames)
            .sum()
    }

    /// The invariant of the charge: every object's weight is its committed
    /// frames plus the credit of every window that names it.
    fn assert_charge_invariant(&self) {
        for object in &self.objects {
            let credit = self
                .windows
                .credit_toward(|candidate| candidate == object.id);
            assert_eq!(
                self.weights.weight(object.id),
                self.committed_frames(object.id) + credit,
                "an object's weight is its committed frames plus its windows' credit"
            );
        }
    }

    fn page_of(mapping: &Mapping, address: u64) -> u64 {
        (address - mapping.virtual_start()) / PAGE
    }
}

impl FastLeaf for ModelLeaf<'_> {
    /// The mapping and the page's address.
    type Place = (Mapping, u64);

    fn find(&mut self, mapping: &Mapping, address: u64) -> Option<(Mapping, u64)> {
        self.model.calls.push("find");
        (!self.model.tables_missing).then_some((*mapping, address))
    }

    /// As the role manager's commit within a limit: a committed page takes
    /// nothing whatever the limit; a commit over the limit takes nothing;
    /// a refused one takes nothing. "commit" is called only when frames
    /// are taken.
    fn commit_within(&mut self, place: &mut (Mapping, u64), limit: u64) -> FastCommit {
        self.model.calls.push("commit_within");
        if self.model.cost_unaskable {
            return FastCommit::Unaskable;
        }
        let nodes = self.model.nodes;
        let (mapping, address) = *place;
        let page = Model::page_of(&mapping, address);
        if self.model.object_of(&mapping).committed.contains(&page) {
            return FastCommit::Done(0);
        }
        if self.model.shared {
            return FastCommit::NotCommitted;
        }
        if 1 + nodes > limit {
            return FastCommit::Over;
        }
        if self.model.commit_refused {
            return FastCommit::Refused;
        }
        self.model.calls.push("commit");
        let object = self.model.object_of(&mapping);
        object.committed.push(page);
        object.frames += 1 + nodes;
        FastCommit::Done(1 + nodes)
    }

    fn write(&mut self, place: (Mapping, u64)) -> Option<bool> {
        self.model.calls.push("write");
        if self.model.write_fails {
            return None;
        }
        let address = place.1;
        if self.model.leaves.contains(&address) {
            return Some(false);
        }
        self.model.leaves.push(address);
        Some(true)
    }

    fn stamp(&mut self, stamp: FastStamp) {
        self.model.stamps.push(stamp);
    }
}

impl FastServePaging<u32> for Model {
    type Leaf<'a> = ModelLeaf<'a>;

    fn window(&self) -> Option<FaultWindow<u32>> {
        self.windows.window(self.cpu).copied()
    }

    fn executing(&self) -> (Option<ThreadKey>, u64) {
        self.executing
    }

    fn open_session(&mut self, root: u32, _process: ProcessKey) -> bool {
        self.calls.push("session");
        !self.session_refused && root == self.root
    }

    fn scheduler_allows(&mut self, _thread: ThreadKey) -> bool {
        self.calls.push("scheduler");
        !self.scheduler_refuses
    }

    fn leaf(&mut self, _mapping: &Mapping) -> Option<ModelLeaf<'_>> {
        self.calls.push("leaf");
        if self.publisher_refused {
            return None;
        }
        Some(ModelLeaf { model: self })
    }

    fn spend(&mut self, frames: u64) {
        assert!(!self.shared, "a shared serve takes no frame to spend");
        self.calls.push("spend");
        self.windows.spend(self.cpu, frames);
    }

    fn validate_return(&mut self) -> bool {
        self.calls.push("return");
        !self.return_refused
    }

    fn stamp(&mut self, stamp: FastStamp) {
        self.stamps.push(stamp);
    }
}

struct Fixture {
    model: Model,
    thread: ThreadKey,
    process: ProcessKey,
}

fn space(raw: u64) -> AddressSpaceKey {
    AddressSpaceKey::for_test(3, raw)
}

/// One object mapped writable, 200 pages from `START`, with a window
/// opened on CPU 0 by a touch of its first page.
fn fixture() -> Fixture {
    let id = ids(3);
    let (thread, process, object) = (
        ThreadKey::from_object_id(id[0]),
        ProcessKey::from_object_id(id[1]),
        id[2],
    );
    let mapping = test_mapping(space(1), START, 200, Protection::READ_WRITE);
    let mut model = Model {
        cpu: 0,
        windows: FaultWindows::new(),
        weights: Weights {
            objects: std::vec![(object, 0)],
            room: 10_000,
        },
        objects: std::vec![Object {
            id: object,
            mapping,
            committed: Vec::new(),
            frames: 0,
        }],
        leaves: Vec::new(),
        executing: (Some(thread), 5),
        root: 9,
        session_refused: false,
        scheduler_refuses: false,
        publisher_refused: false,
        tables_missing: false,
        nodes: 0,
        cost_unaskable: false,
        commit_refused: false,
        write_fails: false,
        return_refused: false,
        shared: false,
        calls: Vec::new(),
        stamps: Vec::new(),
    };
    let opened = model.windows.open(
        0,
        WindowOpening {
            thread,
            process,
            root_epoch: 5,
            root: 9,
            mapping,
            object,
            address: START,
        },
        &mut model.weights,
    );
    assert!(opened.opened);
    model.assert_charge_invariant();
    Fixture {
        model,
        thread,
        process,
    }
}

fn credit(model: &Model) -> Option<u64> {
    model.windows.window(model.cpu).map(FaultWindow::credit)
}

#[test]
fn a_touch_inside_the_window_is_served_and_spends_its_frames() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    let served = serve_fast(model, START + 3 * PAGE + 17, WRITE_FAULT);
    assert_eq!(served, Ok(FastServed::Served));
    assert_eq!(
        model.calls,
        [
            "session",
            "scheduler",
            "leaf",
            "find",
            "commit_within",
            "commit",
            "write",
            "spend",
            "return"
        ]
    );
    assert_eq!(
        model.stamps,
        [FastStamp::Checked, FastStamp::Committed, FastStamp::Written]
    );
    assert_eq!(credit(model), Some(63));
    assert_eq!(model.leaves, [START + 3 * PAGE]);
    model.assert_charge_invariant();
}

#[test]
fn credit_falls_by_the_frames_a_commit_took_index_nodes_included() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    model.nodes = 2;
    assert_eq!(
        serve_fast(model, START + PAGE, WRITE_FAULT),
        Ok(FastServed::Served)
    );
    assert_eq!(credit(model), Some(61));
    model.nodes = 0;
    assert_eq!(
        serve_fast(model, START + 2 * PAGE, READ_FAULT),
        Ok(FastServed::Served)
    );
    assert_eq!(credit(model), Some(60));
    model.assert_charge_invariant();
}

#[test]
fn a_committed_page_with_its_leaf_is_already_present_and_takes_nothing() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    assert_eq!(
        serve_fast(model, START + PAGE, WRITE_FAULT),
        Ok(FastServed::Served)
    );
    model.calls.clear();
    assert_eq!(
        serve_fast(model, START + PAGE, WRITE_FAULT),
        Ok(FastServed::AlreadyPresent)
    );
    assert!(!model.calls.contains(&"commit") && !model.calls.contains(&"spend"));
    assert_eq!(credit(model), Some(63));
    model.assert_charge_invariant();
}

/// A decline of step 1 to 6: nothing changed, window and credit as they
/// were, no frame committed and no leaf written.
fn assert_declined_unchanged(
    model: &mut Model,
    cr2: u64,
    error: u64,
    decline: FastDecline,
) -> Vec<&'static str> {
    let before_credit = credit(model);
    let before_window = model.windows.window(model.cpu).copied();
    let before_weight = model.weights.weight(model.objects[0].id);
    model.calls.clear();
    assert_eq!(serve_fast(model, cr2, error), Err(decline));
    assert_eq!(credit(model), before_credit);
    assert_eq!(model.windows.window(model.cpu).copied(), before_window);
    assert_eq!(model.weights.weight(model.objects[0].id), before_weight);
    assert_eq!(model.objects[0].frames, 0);
    assert!(model.leaves.is_empty());
    assert!(!model.calls.contains(&"commit"));
    assert!(!model.calls.contains(&"write"));
    assert!(!model.calls.contains(&"spend"));
    model.assert_charge_invariant();
    core::mem::take(&mut model.calls)
}

#[test]
fn step_1_declines_without_a_window_or_for_another_thread_root_or_session() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    let cr2 = START + PAGE;
    // Another CPU slot, which has no window.
    model.cpu = 1;
    assert_declined_unchanged(model, cr2, WRITE_FAULT, FastDecline::Identity);
    model.cpu = 0;
    // Another Thread executes here, or none.
    let other = ThreadKey::from_object_id(ids(1)[0]);
    model.executing = (Some(other), 5);
    assert_declined_unchanged(model, cr2, WRITE_FAULT, FastDecline::Identity);
    model.executing = (None, 5);
    assert_declined_unchanged(model, cr2, WRITE_FAULT, FastDecline::Identity);
    // This CPU switched roots since the window was opened.
    model.executing = (Some(fixture.thread), 6);
    let calls = assert_declined_unchanged(model, cr2, WRITE_FAULT, FastDecline::Identity);
    assert!(calls.is_empty(), "no session for a stale epoch: {calls:?}");
    model.executing = (Some(fixture.thread), 5);
    // The root identity no longer validates.
    model.session_refused = true;
    assert_declined_unchanged(model, cr2, WRITE_FAULT, FastDecline::Identity);
    model.session_refused = false;
    model.root = 10;
    assert_declined_unchanged(model, cr2, WRITE_FAULT, FastDecline::Identity);
    let _ = fixture.process;
}

#[test]
fn step_2_declines_when_the_scheduler_stop_or_timer_refuses() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    model.scheduler_refuses = true;
    let calls = assert_declined_unchanged(model, START + PAGE, WRITE_FAULT, FastDecline::Identity);
    assert_eq!(calls, ["session", "scheduler"]);
}

#[test]
fn step_3_declines_outside_the_mapping_or_for_a_refused_access() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    assert_declined_unchanged(model, START - 1, WRITE_FAULT, FastDecline::Mapping);
    assert_declined_unchanged(model, START + 200 * PAGE, READ_FAULT, FastDecline::Mapping);
    // The mapping is writable, not executable.
    assert_declined_unchanged(model, START + PAGE, FETCH_FAULT, FastDecline::Mapping);
    // A read-only mapping refuses a write.
    let read_only = test_mapping(space(2), START, 8, Protection::READ);
    let id = ids(1)[0];
    model.weights.objects.push((id, 0));
    model.objects.push(Object {
        id,
        mapping: read_only,
        committed: Vec::new(),
        frames: 0,
    });
    model.windows.open(
        1,
        WindowOpening {
            thread: fixture.thread,
            process: fixture.process,
            root_epoch: 5,
            root: 9,
            mapping: read_only,
            object: id,
            address: START,
        },
        &mut model.weights,
    );
    model.cpu = 1;
    assert_declined_unchanged(model, START + PAGE, WRITE_FAULT, FastDecline::Mapping);
    assert_eq!(
        serve_fast(model, START + PAGE, READ_FAULT),
        Ok(FastServed::Served)
    );
    model.assert_charge_invariant();
}

#[test]
fn step_4_declines_for_a_missing_table_or_a_refused_publisher() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    model.tables_missing = true;
    assert_declined_unchanged(model, START + PAGE, WRITE_FAULT, FastDecline::Tables);
    model.tables_missing = false;
    model.publisher_refused = true;
    assert_declined_unchanged(model, START + PAGE, WRITE_FAULT, FastDecline::Identity);
}

#[test]
fn step_5_declines_a_cost_above_the_credit() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    model.nodes = 64;
    assert_declined_unchanged(model, START + PAGE, WRITE_FAULT, FastDecline::Credit);
    // Exactly the credit is served.
    model.nodes = 63;
    assert_eq!(
        serve_fast(model, START + PAGE, WRITE_FAULT),
        Ok(FastServed::Served)
    );
    assert_eq!(credit(model), Some(0));
    model.assert_charge_invariant();
    model.nodes = 0;
    model.calls.clear();
    assert_eq!(
        serve_fast(model, START + 2 * PAGE, WRITE_FAULT),
        Err(FastDecline::Credit)
    );
    // A committed page costs nothing, even with no credit left.
    assert_eq!(
        serve_fast(model, START + PAGE, WRITE_FAULT),
        Ok(FastServed::AlreadyPresent)
    );
}

#[test]
fn step_6_declines_a_refused_commit() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    model.commit_refused = true;
    let before = credit(model);
    model.calls.clear();
    assert_eq!(
        serve_fast(model, START + PAGE, WRITE_FAULT),
        Err(FastDecline::Memory)
    );
    assert_eq!(credit(model), before);
    assert!(model.leaves.is_empty() && !model.calls.contains(&"spend"));
    model.assert_charge_invariant();
}

/// DW2 §13.18 part f1: a commit over the credit is one call that takes
/// no frame, and leaves the credit and the window as they were; within the
/// credit the same touch is then served.
#[test]
fn a_commit_over_the_credit_takes_no_frame() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    model.nodes = 64;
    let calls = assert_declined_unchanged(model, START + PAGE, WRITE_FAULT, FastDecline::Credit);
    assert_eq!(
        calls,
        ["session", "scheduler", "leaf", "find", "commit_within"]
    );
    assert!(model.objects[0].committed.is_empty());
    model.nodes = 0;
    assert_eq!(
        serve_fast(model, START + PAGE, WRITE_FAULT),
        Ok(FastServed::Served)
    );
    assert_eq!(credit(model), Some(63));
    model.assert_charge_invariant();
}

/// A cost that cannot be asked declines as a cost over the credit does.
#[test]
fn an_unaskable_cost_declines_as_credit() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    model.cost_unaskable = true;
    assert_declined_unchanged(model, START + PAGE, WRITE_FAULT, FastDecline::Credit);
}

/// A committed page takes no frame (`Done(0)`): with its leaf present the
/// touch is already present; with its leaf empty the leaf is written and
/// the touch served, the credit unspent either way.
#[test]
fn a_commit_of_a_committed_page_takes_nothing_and_the_leaf_decides() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    // Page 1 committed with its leaf, page 2 committed with none.
    model.objects[0].committed.extend([1, 2]);
    model.objects[0].frames = 2;
    model.leaves.push(START + PAGE);
    model.weights.add(model.objects[0].id, 2);
    model.assert_charge_invariant();
    for limit_spent in [false, true] {
        if limit_spent {
            // No credit left: a committed page still takes nothing.
            let spent = credit(model).unwrap();
            model.windows.spend(model.cpu, spent);
            model.weights.subtract(model.objects[0].id, spent);
            model.assert_charge_invariant();
        }
        model.calls.clear();
        let served = serve_fast(model, START + PAGE, WRITE_FAULT);
        assert_eq!(served, Ok(FastServed::AlreadyPresent));
        assert!(!model.calls.contains(&"commit") && !model.calls.contains(&"spend"));
    }
    model.calls.clear();
    assert_eq!(
        serve_fast(model, START + 2 * PAGE, WRITE_FAULT),
        Ok(FastServed::Served)
    );
    assert!(!model.calls.contains(&"commit") && !model.calls.contains(&"spend"));
    assert_eq!(model.leaves, [START + PAGE, START + 2 * PAGE]);
    assert_eq!(credit(model), Some(0));
    assert_eq!(model.objects[0].frames, 2);
    model.assert_charge_invariant();
}

#[test]
fn steps_7_and_8_decline_after_the_commit_with_the_credit_spent() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    model.write_fails = true;
    assert_eq!(
        serve_fast(model, START + PAGE, WRITE_FAULT),
        Err(FastDecline::Leaf)
    );
    assert_eq!(credit(model), Some(63));
    assert_eq!(model.objects[0].frames, 1);
    model.assert_charge_invariant();
    // The serve under T then finds the page committed: cost zero.
    model.write_fails = false;
    model.return_refused = true;
    assert_eq!(
        serve_fast(model, START + 2 * PAGE, WRITE_FAULT),
        Err(FastDecline::Return)
    );
    assert_eq!(credit(model), Some(62));
    assert_eq!(model.leaves, [START + 2 * PAGE]);
    model.assert_charge_invariant();
    model.return_refused = false;
    assert_eq!(
        serve_fast(model, START + PAGE, WRITE_FAULT),
        Ok(FastServed::Served)
    );
    assert_eq!(credit(model), Some(62));
    model.assert_charge_invariant();
}

/// A fixed-seed xorshift: the run is the same every time.
struct Generator(u64);

impl Generator {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

#[test]
fn a_randomised_run_keeps_the_invariant_of_the_charge_after_every_operation() {
    let id = ids(6);
    let threads = [
        ThreadKey::from_object_id(id[0]),
        ThreadKey::from_object_id(id[1]),
    ];
    let process = ProcessKey::from_object_id(id[2]);
    let mappings = [
        test_mapping(space(1), START, 150, Protection::READ_WRITE),
        test_mapping(space(1), START + 400 * PAGE, 30, Protection::READ_WRITE),
        test_mapping(space(2), START, 90, Protection::READ_WRITE),
    ];
    let objects = [id[3], id[4], id[5]];
    let mut model = Model {
        cpu: 0,
        windows: FaultWindows::new(),
        weights: Weights {
            objects: objects.iter().map(|&object| (object, 0)).collect(),
            room: 1000,
        },
        objects: mappings
            .iter()
            .zip(objects)
            .map(|(&mapping, id)| Object {
                id,
                mapping,
                committed: Vec::new(),
                frames: 0,
            })
            .collect(),
        leaves: Vec::new(),
        executing: (Some(threads[0]), 1),
        root: 9,
        session_refused: false,
        scheduler_refuses: false,
        publisher_refused: false,
        tables_missing: false,
        nodes: 0,
        cost_unaskable: false,
        commit_refused: false,
        write_fails: false,
        return_refused: false,
        shared: false,
        calls: Vec::new(),
        stamps: Vec::new(),
    };
    let mut random = Generator(0x9e37_79b9_7f4a_7c15);
    let (mut served, mut declined, mut opened) = (0, 0, 0);
    for _ in 0..20_000 {
        let cpu = usize::try_from(random.below(CPUS as u64)).unwrap();
        let which = usize::try_from(random.below(3)).unwrap();
        let mapping = mappings[which];
        let page = random.below(mapping.byte_len() / PAGE);
        let address = mapping.virtual_start() + page * PAGE;
        match random.below(10) {
            // Open or top up, as a serve under T and P ends.
            0 | 1 => {
                let thread = threads[usize::try_from(random.below(2)).unwrap()];
                let result = model.windows.open(
                    cpu,
                    WindowOpening {
                        thread,
                        process,
                        root_epoch: 1,
                        root: 9,
                        mapping,
                        object: objects[which],
                        address,
                    },
                    &mut model.weights,
                );
                opened += usize::from(result.opened);
            }
            // A fast serve, with each refusal now and then.
            2..=6 => {
                model.cpu = cpu;
                model.executing = (Some(threads[usize::try_from(random.below(2)).unwrap()]), 1);
                model.nodes = random.below(3);
                model.scheduler_refuses = random.below(20) == 0;
                model.tables_missing = random.below(20) == 0;
                model.commit_refused = random.below(20) == 0;
                model.write_fails = random.below(20) == 0;
                model.return_refused = random.below(20) == 0;
                match serve_fast(&mut model, address, WRITE_FAULT) {
                    Ok(_) => served += 1,
                    Err(_) => declined += 1,
                }
                model.calls.clear();
                model.stamps.clear();
            }
            // A mapping change closes its address space's windows.
            7 => {
                let closed = model
                    .windows
                    .close_address_space(mapping.address_space(), &mut model.weights);
                closed.consume_for(mapping.address_space());
                assert!(
                    model
                        .windows
                        .windows()
                        .all(|window| window.mapping().address_space() != mapping.address_space())
                );
            }
            // A refusal closes every window.
            8 => {
                model.windows.close_all(&mut model.weights);
                assert_eq!(model.windows.windows().count(), 0);
            }
            // A release decommits some committed pages, relative to the
            // weight, as the release paths do.
            _ => {
                let object = &mut model.objects[which];
                if let Some(page) = object.committed.pop() {
                    let frames = object.frames.min(1 + random.below(2));
                    object.frames -= frames;
                    model
                        .leaves
                        .retain(|&leaf| leaf != object.mapping.virtual_start() + page * PAGE);
                    let id = object.id;
                    model.weights.subtract(id, frames);
                }
            }
        }
        model.assert_charge_invariant();
    }
    assert!(
        served > 500 && declined > 500 && opened > 100,
        "{served} {declined} {opened}"
    );
}

/// DW2 §15.2: a shared serve of a page with no frame is `NotCommitted`,
/// returned at the commit, before anything is written: the model, its
/// window, its credit and its weights are as they were.
#[test]
fn not_committed_is_returned_before_any_write_and_changes_nothing() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    model.shared = true;
    let calls =
        assert_declined_unchanged(model, START + PAGE, WRITE_FAULT, FastDecline::NotCommitted);
    assert_eq!(
        calls,
        ["session", "scheduler", "leaf", "find", "commit_within"]
    );
    assert!(model.objects[0].committed.is_empty());
    assert_eq!(model.stamps, [FastStamp::Checked]);
}

/// A shared model serve of a committed page: `Served` when its leaf was
/// empty, `AlreadyPresent` when it was this page's; neither commits nor
/// spends, so the credit and the weights stay.
#[test]
fn a_shared_serve_of_a_committed_page_writes_only_its_leaf() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    model.shared = true;
    model.objects[0].committed.push(1);
    model.objects[0].frames = 1;
    model.weights.add(model.objects[0].id, 1);
    model.assert_charge_invariant();
    let before = credit(model);
    assert_eq!(
        serve_fast(model, START + PAGE, WRITE_FAULT),
        Ok(FastServed::Served)
    );
    assert_eq!(
        model.calls,
        [
            "session",
            "scheduler",
            "leaf",
            "find",
            "commit_within",
            "write",
            "return"
        ]
    );
    assert_eq!(model.leaves, [START + PAGE]);
    model.calls.clear();
    assert_eq!(
        serve_fast(model, START + PAGE + 5, READ_FAULT),
        Ok(FastServed::AlreadyPresent)
    );
    assert!(!model.calls.contains(&"commit") && !model.calls.contains(&"spend"));
    assert_eq!(model.leaves, [START + PAGE]);
    assert_eq!(credit(model), before);
    assert_eq!(model.objects[0].frames, 1);
    model.assert_charge_invariant();
}

/// Every decline of a shared serve writes nothing that P guards: no
/// commit, no spend, the window and the weights as they were; only the
/// leaf's own declines (7 and 8) come after a leaf write is attempted.
#[test]
fn every_decline_of_a_shared_serve_writes_nothing() {
    type Knob = fn(&mut Model);
    let knobs: [(Knob, FastDecline); 8] = [
        (|model| model.cpu = 1, FastDecline::Identity),
        (|model| model.session_refused = true, FastDecline::Identity),
        (
            |model| model.scheduler_refuses = true,
            FastDecline::Identity,
        ),
        (
            |model| model.publisher_refused = true,
            FastDecline::Identity,
        ),
        (|model| model.tables_missing = true, FastDecline::Tables),
        (|model| model.cost_unaskable = true, FastDecline::Credit),
        (|model| model.write_fails = true, FastDecline::Leaf),
        (|model| model.return_refused = true, FastDecline::Return),
    ];
    for (knob, decline) in knobs {
        let mut fixture = fixture();
        let model = &mut fixture.model;
        model.shared = true;
        model.objects[0].committed.push(1);
        model.objects[0].frames = 1;
        model.weights.add(model.objects[0].id, 1);
        knob(model);
        let window = model.windows.window(0).copied();
        let weight = model.weights.weight(model.objects[0].id);
        model.calls.clear();
        assert_eq!(
            serve_fast(model, START + PAGE, WRITE_FAULT),
            Err(decline),
            "{decline:?}"
        );
        assert!(!model.calls.contains(&"commit") && !model.calls.contains(&"spend"));
        assert_eq!(model.windows.window(0).copied(), window);
        assert_eq!(model.weights.weight(model.objects[0].id), weight);
        assert_eq!(model.objects[0].committed, [1]);
        if decline != FastDecline::Return {
            assert!(model.leaves.is_empty(), "{decline:?}");
        }
        model.cpu = 0;
        model.assert_charge_invariant();
    }
}

/// What each serve did in a gate test, in order.
#[derive(Default)]
struct GateRun {
    ran: Vec<&'static str>,
}

/// DW2 §15.2: the gate's flag. Clear: only the exclusive serve runs, and
/// the flag is set when it took no frame. Set: the shared serve runs
/// first and answers the fault, except `NotCommitted`, which clears the
/// flag and runs the exclusive serve in the same fault. Another shared
/// decline is the fault's. The serve under T clears it.
#[test]
fn the_gate_tries_the_shared_serve_only_after_a_serve_that_took_no_frame() {
    let mut flag = SharedServeFlag::new();
    let mut run = GateRun::default();
    // Clear, the exclusive serve takes a frame: the flag stays clear.
    let answered = serve_gated(
        &mut flag,
        &mut run,
        |run| {
            run.ran.push("shared");
            Ok(FastServed::Served)
        },
        |run| {
            run.ran.push("exclusive");
            Ok((FastServed::Served, false))
        },
    );
    assert_eq!(answered, (Ok(FastServed::Served), FastKind::Exclusive));
    assert!(!flag.tries_shared());
    // A decline of the exclusive serve leaves it clear.
    let answered = serve_gated(
        &mut flag,
        &mut run,
        |_| Ok(FastServed::Served),
        |run| {
            run.ran.push("exclusive");
            Err::<(FastServed, bool), _>(FastDecline::Credit)
        },
    );
    assert_eq!(answered, (Err(FastDecline::Credit), FastKind::Exclusive));
    assert!(!flag.tries_shared());
    // Clear, the exclusive serve takes no frame: set.
    let _ = serve_gated(
        &mut flag,
        &mut run,
        |_| Ok(FastServed::Served),
        |run| {
            run.ran.push("exclusive");
            Ok((FastServed::AlreadyPresent, true))
        },
    );
    assert!(flag.tries_shared());
    assert_eq!(run.ran, ["exclusive", "exclusive", "exclusive"]);
    run.ran.clear();
    // Set: the shared serve answers and the exclusive one does not run.
    let answered = serve_gated(
        &mut flag,
        &mut run,
        |run| {
            run.ran.push("shared");
            Ok(FastServed::Served)
        },
        |run| {
            run.ran.push("exclusive");
            Ok((FastServed::Served, false))
        },
    );
    assert_eq!(answered, (Ok(FastServed::Served), FastKind::Shared));
    assert!(flag.tries_shared());
    // Set, another shared decline: the fault's, for the serve under T; the
    // flag stays.
    let answered = serve_gated(
        &mut flag,
        &mut run,
        |run| {
            run.ran.push("shared");
            Err(FastDecline::Leaf)
        },
        |run| {
            run.ran.push("exclusive");
            Ok((FastServed::Served, false))
        },
    );
    assert_eq!(answered, (Err(FastDecline::Leaf), FastKind::Shared));
    assert!(flag.tries_shared());
    assert_eq!(run.ran, ["shared", "shared"]);
    run.ran.clear();
    // Set, `NotCommitted`: cleared, and the exclusive serve runs in the
    // same fault; it took a frame, so the flag stays clear.
    let answered = serve_gated(
        &mut flag,
        &mut run,
        |run| {
            run.ran.push("shared");
            Err(FastDecline::NotCommitted)
        },
        |run| {
            run.ran.push("exclusive");
            Ok((FastServed::Served, false))
        },
    );
    assert_eq!(answered, (Ok(FastServed::Served), FastKind::Exclusive));
    assert_eq!(run.ran, ["shared", "exclusive"]);
    assert!(!flag.tries_shared());
    // The serve under T clears a set flag.
    let mut flag = SharedServeFlag::new();
    let _ = serve_gated(&mut flag, &mut run, |_| Ok(()), |_| Ok(((), true)));
    assert!(flag.tries_shared());
    flag.serve_under_t_ran();
    assert!(!flag.tries_shared());
}

/// The gate over the shared and exclusive models: a committed page after
/// a serve that took no frame is served shared; an uncommitted one is
/// `NotCommitted` and committed by the exclusive serve in the same fault.
#[test]
fn the_gate_over_the_models_commits_through_the_exclusive_serve() {
    let mut fixture = fixture();
    let model = &mut fixture.model;
    model.objects[0].committed.push(1);
    model.objects[0].frames = 1;
    model.weights.add(model.objects[0].id, 1);
    let mut flag = SharedServeFlag::new();
    let shared = |model: &mut Model, address| {
        model.shared = true;
        let served = serve_fast(model, address, WRITE_FAULT);
        model.shared = false;
        served
    };
    let exclusive = |model: &mut Model, address| {
        let spent = credit(model);
        serve_fast(model, address, WRITE_FAULT).map(|served| (served, credit(model) == spent))
    };
    // Page 1 is committed: the exclusive serve takes no frame and sets it.
    let answered = serve_gated(
        &mut flag,
        model,
        |model| shared(model, START + PAGE),
        |model| exclusive(model, START + PAGE),
    );
    assert_eq!(answered, (Ok(FastServed::Served), FastKind::Exclusive));
    assert!(flag.tries_shared());
    // Page 2 is not: shared is `NotCommitted`, the exclusive serve commits.
    model.calls.clear();
    let answered = serve_gated(
        &mut flag,
        model,
        |model| shared(model, START + 2 * PAGE),
        |model| exclusive(model, START + 2 * PAGE),
    );
    assert_eq!(answered, (Ok(FastServed::Served), FastKind::Exclusive));
    assert!(!flag.tries_shared());
    assert_eq!(
        model.calls.iter().filter(|call| **call == "commit").count(),
        1
    );
    assert_eq!(credit(model), Some(63));
    model.assert_charge_invariant();
}
