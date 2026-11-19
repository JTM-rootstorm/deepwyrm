extern crate std;

use super::*;
use crate::memory::address_region::Protection;
use crate::object::ObjectRegistry;
use deepwyrm_abi::DW_OBJECT_TYPE_EVENT;
use std::vec::Vec;

/// A registry's weights, in miniature: each object's weight and whether
/// it is live, and a room limit admission checks.
pub(super) struct Weights {
    pub(super) objects: Vec<(ObjectId, u64, bool)>,
    pub(super) room: u64,
}

impl Weights {
    pub(super) fn new(objects: &[ObjectId], room: u64) -> Self {
        Self {
            objects: objects.iter().map(|&object| (object, 0, true)).collect(),
            room,
        }
    }

    pub(super) fn weight(&self, object: ObjectId) -> u64 {
        self.entry(object).1
    }

    fn entry(&self, object: ObjectId) -> &(ObjectId, u64, bool) {
        self.objects
            .iter()
            .find(|entry| entry.0 == object)
            .expect("a known object")
    }

    fn entry_mut(&mut self, object: ObjectId) -> &mut (ObjectId, u64, bool) {
        self.objects
            .iter_mut()
            .find(|entry| entry.0 == object)
            .expect("a known object")
    }

    fn total(&self) -> u64 {
        self.objects.iter().map(|entry| entry.1).sum()
    }
}

impl WindowCharges for Weights {
    fn admit(&self, _object: ObjectId, frames: u64) -> bool {
        self.total() + frames <= self.room
    }

    fn add(&mut self, object: ObjectId, frames: u64) {
        let entry = self.entry_mut(object);
        assert!(entry.2, "added to an object that is not live");
        entry.1 = entry.1.checked_add(frames).expect("weight overflow");
    }

    fn subtract(&mut self, object: ObjectId, frames: u64) {
        let entry = self.entry_mut(object);
        assert!(entry.2, "a window's object is not live");
        entry.1 = entry.1.checked_sub(frames).expect("weight underflow");
    }
}

pub(super) fn ids(count: usize) -> Vec<ObjectId> {
    let mut registry = ObjectRegistry::<16>::new();
    (0..count)
        .map(|_| registry.create(DW_OBJECT_TYPE_EVENT).unwrap().id())
        .collect()
}

pub(super) fn space(raw: u64) -> AddressSpaceKey {
    AddressSpaceKey::for_test(7, raw)
}

const START: u64 = 0x40_0000;

fn opening(
    thread: ObjectId,
    process: ObjectId,
    mapping: Mapping,
    object: ObjectId,
    address: u64,
) -> WindowOpening<u32> {
    WindowOpening {
        thread: ThreadKey::from_object_id(thread),
        process: ProcessKey::from_object_id(process),
        root_epoch: 1,
        root: 9,
        mapping,
        object,
        address,
    }
}

#[test]
fn opening_charges_up_to_64_frames_of_the_pages_after_the_touch() {
    let id = ids(3);
    let (thread, process, object) = (id[0], id[1], id[2]);
    let mut weights = Weights::new(&[object], 1000);
    let mut windows = FaultWindows::<u32, 2>::new();
    let long = test_mapping(space(1), START, 200, Protection::READ_WRITE);
    let opened = windows.open(
        0,
        opening(thread, process, long, object, START),
        &mut weights,
    );
    assert_eq!(
        opened,
        WindowOpened {
            opened: true,
            closed: false
        }
    );
    assert_eq!(windows.window(0).unwrap().credit(), 64);
    assert_eq!(weights.weight(object), 64);

    // Three pages after the touch: three frames.
    let mut windows = FaultWindows::<u32, 2>::new();
    let mut weights = Weights::new(&[object], 1000);
    let short = test_mapping(space(1), START, 5, Protection::READ_WRITE);
    windows.open(
        1,
        opening(thread, process, short, object, START + PAGE_SIZE + 5),
        &mut weights,
    );
    assert_eq!(windows.window(1).unwrap().credit(), 3);
    assert_eq!(weights.weight(object), 3);

    // The last page: nothing is stored.
    let opened = windows.open(
        0,
        opening(thread, process, short, object, START + 4 * PAGE_SIZE),
        &mut weights,
    );
    assert_eq!(opened, WindowOpened::default());
    assert!(windows.window(0).is_none());
    assert_eq!(weights.weight(object), 3);
}

#[test]
fn a_refused_admission_stores_no_window_and_charges_nothing() {
    let id = ids(3);
    let (thread, process, object) = (id[0], id[1], id[2]);
    let mut weights = Weights::new(&[object], 10);
    let mut windows = FaultWindows::<u32, 1>::new();
    let mapping = test_mapping(space(1), START, 200, Protection::READ_WRITE);
    let opened = windows.open(
        0,
        opening(thread, process, mapping, object, START),
        &mut weights,
    );
    assert!(!opened.opened);
    assert!(windows.window(0).is_none());
    assert_eq!(weights.weight(object), 0);
}

#[test]
fn the_same_mapping_and_thread_is_topped_up_by_the_difference() {
    let id = ids(3);
    let (thread, process, object) = (id[0], id[1], id[2]);
    let mut weights = Weights::new(&[object], 1000);
    let mut windows = FaultWindows::<u32, 1>::new();
    let mapping = test_mapping(space(1), START, 200, Protection::READ_WRITE);
    windows.open(
        0,
        opening(thread, process, mapping, object, START),
        &mut weights,
    );
    // Five frames were committed under P alone.
    windows.spend(0, 5);
    let committed = 5;
    assert_eq!(
        weights.weight(object),
        committed + windows.window(0).unwrap().credit()
    );
    let mut again = opening(thread, process, mapping, object, START + 10 * PAGE_SIZE);
    again.root = 11;
    again.root_epoch = 4;
    let opened = windows.open(0, again, &mut weights);
    assert_eq!(
        opened,
        WindowOpened {
            opened: true,
            closed: false
        }
    );
    let window = windows.window(0).unwrap();
    assert_eq!(
        (window.credit(), window.root(), window.root_epoch()),
        (64, 11, 4)
    );
    assert_eq!(weights.weight(object), committed + 64);

    // A full window is kept as it is.
    let opened = windows.open(0, again, &mut weights);
    assert_eq!(opened, WindowOpened::default());
    assert_eq!(weights.weight(object), committed + 64);
}

#[test]
fn another_mapping_or_thread_closes_the_old_window_first() {
    let id = ids(5);
    let (thread, other_thread, process, first, second) = (id[0], id[1], id[2], id[3], id[4]);
    let mut weights = Weights::new(&[first, second], 1000);
    let mut windows = FaultWindows::<u32, 1>::new();
    let one = test_mapping(space(1), START, 200, Protection::READ_WRITE);
    let two = test_mapping(
        space(1),
        START + 400 * PAGE_SIZE,
        100,
        Protection::READ_WRITE,
    );
    windows.open(0, opening(thread, process, one, first, START), &mut weights);
    windows.spend(0, 2);
    let opened = windows.open(
        0,
        opening(thread, process, two, second, two.virtual_start()),
        &mut weights,
    );
    assert_eq!(
        opened,
        WindowOpened {
            opened: true,
            closed: true
        }
    );
    // The old object keeps only the frames committed for it.
    assert_eq!(weights.weight(first), 2);
    assert_eq!(weights.weight(second), 64);
    let opened = windows.open(
        0,
        opening(other_thread, process, two, second, two.virtual_start()),
        &mut weights,
    );
    assert!(opened.closed && opened.opened);
    assert_eq!(weights.weight(second), 64);
}

#[test]
fn closing_returns_the_credit_and_leaves_the_committed_frames() {
    let id = ids(4);
    let (thread, process, first, second) = (id[0], id[1], id[2], id[3]);
    let mut weights = Weights::new(&[first, second], 1000);
    let mut windows = FaultWindows::<u32, 3>::new();
    let one = test_mapping(space(1), START, 200, Protection::READ_WRITE);
    let two = test_mapping(space(2), START, 200, Protection::READ_WRITE);
    windows.open(0, opening(thread, process, one, first, START), &mut weights);
    windows.open(1, opening(thread, process, one, first, START), &mut weights);
    windows.open(
        2,
        opening(thread, process, two, second, START),
        &mut weights,
    );
    windows.spend(0, 3);
    windows.spend(2, 7);
    assert_eq!(weights.weight(first), 3 + 61 + 64);

    let closed = windows.close_address_space(space(1), &mut weights);
    assert_eq!(closed.closed(), 2);
    assert_eq!(closed.address_space(), space(1));
    closed.consume_for(space(1));
    assert_eq!(weights.weight(first), 3);
    assert_eq!(weights.weight(second), 7 + 57);
    assert!(windows.window(0).is_none() && windows.window(1).is_none());
    assert!(windows.window(2).is_some());

    assert!(windows.close(2, &mut weights));
    assert!(!windows.close(2, &mut weights));
    assert_eq!(weights.weight(second), 7);
}

#[test]
fn close_all_closes_every_window() {
    let id = ids(4);
    let (thread, process, first, second) = (id[0], id[1], id[2], id[3]);
    let mut weights = Weights::new(&[first, second], 1000);
    let mut windows = FaultWindows::<u32, 4>::new();
    let one = test_mapping(space(1), START, 200, Protection::READ_WRITE);
    let two = test_mapping(space(2), START, 200, Protection::READ_WRITE);
    windows.open(0, opening(thread, process, one, first, START), &mut weights);
    windows.open(
        3,
        opening(thread, process, two, second, START),
        &mut weights,
    );
    windows.spend(3, 1);
    assert_eq!(windows.close_all(&mut weights), 2);
    assert_eq!(windows.windows().count(), 0);
    assert_eq!((weights.weight(first), weights.weight(second)), (0, 1));
    assert_eq!(windows.close_all(&mut weights), 0);
}

#[test]
#[should_panic(expected = "another address space's WindowsClosed")]
fn windows_closed_is_refused_for_another_address_space() {
    test_windows_closed(space(1)).consume_for(space(2));
}

#[test]
#[should_panic(expected = "not live")]
fn closing_a_window_whose_object_is_not_live_panics() {
    let id = ids(3);
    let (thread, process, object) = (id[0], id[1], id[2]);
    let mut weights = Weights::new(&[object], 1000);
    let mut windows = FaultWindows::<u32, 1>::new();
    let mapping = test_mapping(space(1), START, 200, Protection::READ_WRITE);
    windows.open(
        0,
        opening(thread, process, mapping, object, START),
        &mut weights,
    );
    weights.objects[0].2 = false;
    windows.close(0, &mut weights);
}

#[test]
#[should_panic(expected = "more than its credit")]
fn spending_above_the_credit_panics() {
    let id = ids(3);
    let mut weights = Weights::new(&[id[2]], 1000);
    let mut windows = FaultWindows::<u32, 1>::new();
    let mapping = test_mapping(space(1), START, 3, Protection::READ_WRITE);
    windows.open(
        0,
        opening(id[0], id[1], mapping, id[2], START),
        &mut weights,
    );
    windows.spend(0, 3);
}

#[test]
fn the_reported_usage_is_the_committed_weight_at_every_step() {
    // DW2 §13.16 as decided: a group's reported usage is its kept usage
    // less the credit of the windows whose object counts toward it, so
    // opening, topping up and spending a window never move it apart from
    // the frames actually committed.
    let id = ids(4);
    let (thread, process, counted, other) = (id[0], id[1], id[2], id[3]);
    let mut weights = Weights::new(&[counted, other], 1000);
    let mut windows = FaultWindows::<u32, 2>::new();
    let mapping = test_mapping(space(1), START, 300, Protection::READ_WRITE);
    let mut committed = 0;
    let reported = |weights: &Weights, windows: &FaultWindows<u32, 2>| {
        // The group counts `counted` only; its kept usage is that weight.
        usage_without_credit(
            usize::try_from(weights.weight(counted)).unwrap(),
            windows.credit_toward(|object| object == counted),
        )
    };
    assert_eq!(reported(&weights, &windows), committed);
    windows.open(
        0,
        opening(thread, process, mapping, counted, START),
        &mut weights,
    );
    windows.open(
        1,
        opening(thread, process, mapping, other, START),
        &mut weights,
    );
    assert_eq!(reported(&weights, &windows), committed);
    for frames in [1, 3, 1, 2] {
        windows.spend(0, frames);
        committed += usize::try_from(frames).unwrap();
        assert_eq!(reported(&weights, &windows), committed);
    }
    windows.open(
        0,
        opening(thread, process, mapping, counted, START + 9 * PAGE_SIZE),
        &mut weights,
    );
    assert_eq!(windows.window(0).unwrap().credit(), 64);
    assert_eq!(reported(&weights, &windows), committed);
    windows.close_all(&mut weights);
    assert_eq!(reported(&weights, &windows), committed);
    assert_eq!(usize::try_from(weights.weight(counted)).unwrap(), committed);
}
