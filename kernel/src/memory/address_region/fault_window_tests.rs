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
            closed: false,
            ahead: false
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
            closed: false,
            ahead: false
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
            closed: true,
            ahead: false
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

/// The address of page `n` of the test mapping.
fn at(n: u64) -> u64 {
    START + n * PAGE_SIZE
}

/// A window on CPU 0 over a 200-page mapping, opened at page `first`: the
/// Thread, Process, object, mapping, the weights and the table.
struct Stream {
    thread: ObjectId,
    process: ObjectId,
    object: ObjectId,
    mapping: Mapping,
    weights: Weights,
    windows: FaultWindows<u32, 2>,
    /// Frames committed for the object: each spend and spend ahead.
    committed: u64,
}

impl Stream {
    fn new(pages: u64, first: u64) -> Self {
        let id = ids(3);
        let mut stream = Self {
            thread: id[0],
            process: id[1],
            object: id[2],
            mapping: test_mapping(space(1), START, pages, Protection::READ_WRITE),
            weights: Weights::new(&[id[2]], 100_000),
            windows: FaultWindows::new(),
            committed: 0,
        };
        let opened = stream.serve_under_t(first);
        assert!(
            opened.opened && !opened.ahead,
            "a new window is never a stream"
        );
        stream
    }

    fn serve_under_t(&mut self, page: u64) -> WindowOpened {
        let opened = self.windows.open(
            0,
            opening(
                self.thread,
                self.process,
                self.mapping,
                self.object,
                at(page),
            ),
            &mut self.weights,
        );
        self.check();
        opened
    }

    fn fast_serves(&mut self, frames: u64) {
        for _ in 0..frames {
            self.windows.spend(0, 1);
            self.committed += 1;
            self.check();
        }
    }

    fn spend_ahead(&mut self, frames: u64, end_page: u64) {
        self.windows.spend_ahead(0, frames, at(end_page));
        self.committed += frames;
        self.check();
    }

    fn window(&self) -> FaultWindow<u32> {
        *self.windows.window(0).expect("the window")
    }

    /// The weight invariant: weight = committed frames + credit.
    fn check(&self) {
        let credit = self.windows.window(0).map_or(0, FaultWindow::credit);
        assert_eq!(self.weights.weight(self.object), self.committed + credit);
    }
}

#[test]
fn sequential_touches_that_spend_the_credit_start_a_stream() {
    let mut stream = Stream::new(200, 0);
    assert_eq!(stream.window().credit(), 64);
    stream.fast_serves(64);
    let opened = stream.serve_under_t(65);
    assert!(opened.ahead && opened.opened);
    let window = stream.window();
    assert_eq!((window.base(), window.granted()), (at(65), 64));
    assert_eq!(window.ahead_end(), None);
}

#[test]
fn a_table_miss_in_the_middle_of_the_credit_starts_a_stream() {
    // Five touches, then the sixth page after the open found a table
    // missing: fewer spent, a nearer address.
    let mut stream = Stream::new(200, 10);
    stream.fast_serves(5);
    assert!(stream.serve_under_t(16).ahead);
}

#[test]
fn a_serve_one_page_off_is_no_stream() {
    for page in [15, 17, 10, 0] {
        let mut stream = Stream::new(200, 10);
        stream.fast_serves(5);
        let opened = stream.serve_under_t(page);
        assert!(!opened.ahead, "page {page}");
        let window = stream.window();
        // It is a credit window, recording this serve.
        assert_eq!((window.base(), window.ahead_end()), (at(page), None));
        assert_eq!(window.granted(), window.credit());
    }
    assert_eq!(
        Stream::new(200, 10).windows.take_stream_changes(),
        StreamChanges::default()
    );
}

#[test]
fn spending_ahead_lowers_the_credit_and_records_the_end() {
    let mut stream = Stream::new(200, 0);
    stream.fast_serves(64);
    assert!(stream.serve_under_t(65).ahead);
    stream.spend_ahead(64, 130);
    let window = stream.window();
    assert_eq!(window.credit(), 0);
    assert_eq!(window.ahead_end(), Some(at(130)));
    assert_eq!(window.granted(), 0);
    assert_eq!(
        stream.windows.take_stream_changes(),
        StreamChanges {
            started: 1,
            ended: 0
        }
    );
    assert_eq!(
        stream.windows.take_stream_changes(),
        StreamChanges::default()
    );
}

#[test]
fn a_serve_at_the_end_continues_and_one_inside_changes_nothing() {
    let mut stream = Stream::new(400, 0);
    stream.fast_serves(64);
    assert!(stream.serve_under_t(65).ahead);
    stream.spend_ahead(64, 130);
    // Inside the range (a page table was missing there): the top-up is
    // made, but nothing about the stream changes.
    let opened = stream.serve_under_t(100);
    assert!(!opened.ahead && opened.opened);
    let window = stream.window();
    assert_eq!(
        (window.base(), window.granted(), window.ahead_end()),
        (at(65), 0, Some(at(130)))
    );
    stream.windows.spend(0, window.credit());
    stream.committed += window.credit();
    // At the end: it continues.
    let opened = stream.serve_under_t(130);
    assert!(opened.ahead);
    let window = stream.window();
    assert_eq!(
        (window.base(), window.credit(), window.ahead_end()),
        (at(130), 64, Some(at(130)))
    );
    stream.spend_ahead(64, 195);
    assert_eq!(
        stream.windows.take_stream_changes(),
        StreamChanges {
            started: 1,
            ended: 0
        }
    );
}

#[test]
fn a_serve_elsewhere_ends_the_stream_and_the_window_is_a_credit_window_again() {
    let mut stream = Stream::new(400, 0);
    stream.fast_serves(64);
    assert!(stream.serve_under_t(65).ahead);
    stream.spend_ahead(64, 130);
    // Past the end, the range's own start, and before it.
    for page in [131, 65, 64] {
        let mut stream = Stream {
            windows: FaultWindows {
                slots: stream.windows.slots,
                streams: StreamChanges::default(),
            },
            weights: Weights {
                objects: stream.weights.objects.clone(),
                room: stream.weights.room,
            },
            ..stream
        };
        let opened = stream.serve_under_t(page);
        assert!(!opened.ahead, "page {page}");
        let window = stream.window();
        assert_eq!(window.ahead_end(), None);
        assert_eq!((window.base(), window.granted()), (at(page), 64));
        assert_eq!(stream.windows.take_stream_changes().ended, 1);
        // A credit window again: its own touches start a stream.
        stream.fast_serves(3);
        assert!(stream.serve_under_t(page + 4).ahead);
    }
}

#[test]
fn a_new_or_replaced_window_is_never_a_stream() {
    let mut stream = Stream::new(400, 0);
    stream.fast_serves(64);
    assert!(stream.serve_under_t(65).ahead);
    stream.spend_ahead(64, 130);
    stream.windows.take_stream_changes();
    // Another mapping, at the very page the stream would continue at.
    let other = test_mapping(space(1), START, 401, Protection::READ_WRITE);
    let opened = stream.windows.open(
        0,
        opening(stream.thread, stream.process, other, stream.object, at(130)),
        &mut stream.weights,
    );
    assert!(opened.opened && opened.closed && !opened.ahead);
    assert_eq!(stream.window().ahead_end(), None);
    assert_eq!(
        stream.windows.take_stream_changes(),
        StreamChanges {
            started: 0,
            ended: 1
        }
    );
    stream.check();
}

#[test]
fn closing_a_stream_ends_it() {
    let mut stream = Stream::new(400, 0);
    stream.fast_serves(64);
    assert!(stream.serve_under_t(65).ahead);
    stream.spend_ahead(10, 76);
    // A partial commit ahead: the credit left stays charged.
    assert_eq!(stream.window().credit(), 54);
    stream.windows.take_stream_changes();
    assert!(stream.windows.close(0, &mut stream.weights));
    stream.check();
    assert_eq!(stream.weights.weight(stream.object), stream.committed);
    assert_eq!(stream.windows.take_stream_changes().ended, 1);

    // The address space's close and the close of every window, too; a
    // credit window's close ends nothing.
    for all in [false, true] {
        let mut stream = Stream::new(400, 0);
        stream.fast_serves(64);
        assert!(stream.serve_under_t(65).ahead);
        stream.spend_ahead(64, 130);
        let mut other = Stream::new(400, 0);
        let closed = if all {
            stream.windows.close_all(&mut stream.weights)
        } else {
            stream
                .windows
                .close_address_space(space(1), &mut stream.weights)
                .closed()
        };
        assert_eq!(closed, 1);
        stream.check();
        assert_eq!(stream.windows.take_stream_changes().ended, 1);
        other.windows.close_all(&mut other.weights);
        assert_eq!(other.windows.take_stream_changes().ended, 0);
    }
}

#[test]
fn the_mappings_last_pages_bound_the_credit_a_stream_gets() {
    // 100 pages: after a stream starts at page 65 there are 34 pages left.
    let mut stream = Stream::new(100, 0);
    stream.fast_serves(64);
    let opened = stream.serve_under_t(65);
    assert!(opened.ahead);
    assert_eq!(stream.window().credit(), 34);
    stream.spend_ahead(34, 100);
    // The last page continues the stream with nothing left to commit.
    let mut stream = Stream::new(100, 0);
    stream.fast_serves(64);
    stream.serve_under_t(65);
    stream.spend_ahead(33, 99);
    let opened = stream.serve_under_t(99);
    assert!(opened.ahead && !opened.opened);
    // The window keeps credit the mapping has no page after this one for:
    // a commit ahead clips its range to the mapping, not to the credit.
    assert_eq!(stream.window().credit(), 1);
    stream.windows.spend(0, 1);
    stream.committed += 1;
    // At the very end, a stream that has no credit to commit ahead.
    let mut stream = Stream::new(66, 0);
    stream.fast_serves(64);
    let opened = stream.serve_under_t(65);
    assert!(opened.ahead && !opened.opened);
    assert_eq!(stream.window().credit(), 0);
}

#[test]
fn the_weight_is_the_committed_frames_and_the_credit_through_a_stream() {
    // Each step checks weight = committed + credit (`Stream::check`):
    // open, a full spend ahead, a continuation's top-up, a partial one, a
    // serve elsewhere and a close.
    let mut stream = Stream::new(1000, 0);
    stream.fast_serves(64);
    stream.serve_under_t(65);
    assert_eq!(stream.weights.weight(stream.object), 64 + 64);
    stream.spend_ahead(64, 130);
    stream.serve_under_t(130);
    stream.spend_ahead(20, 151);
    stream.serve_under_t(500);
    stream.fast_serves(7);
    assert!(stream.windows.close(0, &mut stream.weights));
    stream.check();
    assert_eq!(stream.weights.weight(stream.object), 64 + 64 + 20 + 7);
}

#[test]
#[should_panic(expected = "more than its credit")]
fn spending_ahead_above_the_credit_panics() {
    let mut stream = Stream::new(400, 0);
    stream.windows.spend_ahead(0, 65, at(66));
}
