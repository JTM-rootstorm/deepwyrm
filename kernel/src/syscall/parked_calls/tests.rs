use super::*;
use crate::object::ObjectRegistry;
use deepwyrm_abi::DW_OBJECT_TYPE_THREAD;

fn thread_keys<const N: usize>() -> [ThreadKey; N] {
    let mut objects = ObjectRegistry::<8>::new();
    core::array::from_fn(|_| {
        // Each creation stays pending, so each key names its own slot.
        let creation = objects.create(DW_OBJECT_TYPE_THREAD).unwrap();
        ThreadKey::from_object_id(creation.id())
    })
}

#[test]
fn a_thread_takes_back_only_its_own_call() {
    let [first, second, third] = thread_keys::<3>();
    let mut parked = ParkedCalls::<u32, 2>::new();
    assert_eq!(parked.take(first), None);
    parked.park(first, 10);
    parked.park(second, 20);
    assert_eq!(parked.parked(), 2);
    assert_eq!(parked.take(third), None);
    assert_eq!(parked.take(second), Some(20));
    // Taken once: the record is with its running call, not here.
    assert_eq!(parked.take(second), None);
    // The freed slot takes the next park.
    parked.park(third, 30);
    assert_eq!(parked.take(first), Some(10));
    assert_eq!(parked.take(third), Some(30));
    assert_eq!(parked.parked(), 0);
}

#[test]
#[should_panic(expected = "a Thread parked a second call")]
fn a_thread_parks_at_most_one_call() {
    let [first] = thread_keys::<1>();
    let mut parked = ParkedCalls::<u32, 2>::new();
    parked.park(first, 1);
    parked.park(first, 2);
}

#[test]
#[should_panic(expected = "more parked calls than Threads that can run")]
fn the_table_never_holds_more_than_its_threads() {
    let [first, second] = thread_keys::<2>();
    let mut parked = ParkedCalls::<u32, 1>::new();
    parked.park(first, 1);
    parked.park(second, 2);
}

/// A Thread that ends while parked never takes its call back; the runtime
/// settles it once, and a Thread still running keeps its record.
#[test]
fn ended_threads_calls_are_settled_once_and_live_ones_kept() {
    let [first, second, third] = thread_keys::<3>();
    let mut parked = ParkedCalls::<u32, 4>::new();
    let mut asked = 0;
    assert_eq!(
        parked.take_ended(|_| {
            asked += 1;
            true
        }),
        None
    );
    assert_eq!(asked, 0, "an empty table asks about no Thread");
    parked.park(first, 1);
    parked.park(second, 2);
    parked.park(third, 3);
    let ended = |thread: ThreadKey| thread == first || thread == third;
    let mut settled = [
        parked.take_ended(ended),
        parked.take_ended(ended),
        parked.take_ended(ended),
    ];
    settled.sort_by_key(|entry| entry.map(|(_, call)| call));
    assert_eq!(settled, [None, Some((first, 1)), Some((third, 3))]);
    assert_eq!(parked.take(first), None);
    assert_eq!(parked.take(second), Some(2));
}

/// A remote Stop's precommit names a parked call among its facts (DW2
/// §10.15 revision 2 item 4).
#[test]
fn the_table_says_whether_a_thread_holds_a_parked_call() {
    let [first, second] = thread_keys::<2>();
    let mut parked = ParkedCalls::<u32, 2>::new();
    assert!(!parked.holds(first));
    parked.park(first, 1);
    assert!(parked.holds(first));
    assert!(!parked.holds(second));
    assert_eq!(parked.take(first), Some(1));
    assert!(!parked.holds(first));
}
