extern crate std;

use super::*;
use std::sync::Arc;
use std::thread;

#[test]
fn try_lock_is_exclusive_and_drop_releases() {
    let lock = SpinMutex::new(7_u64);
    let mut guard = lock.try_lock().expect("first acquisition succeeds");
    assert!(lock.is_locked());
    assert!(lock.try_lock().is_none());
    *guard = 9;
    drop(guard);
    assert!(!lock.is_locked());
    assert_eq!(*lock.lock(), 9);
}

#[test]
fn acquire_release_serializes_host_threads() {
    let lock = Arc::new(SpinMutex::new(0_u64));
    let mut workers = std::vec::Vec::new();
    for _ in 0..4 {
        let lock = Arc::clone(&lock);
        workers.push(thread::spawn(move || {
            for _ in 0..2_000 {
                *lock.lock() += 1;
            }
        }));
    }

    for worker in workers {
        worker.join().expect("worker completes");
    }
    assert_eq!(*lock.lock(), 8_000);
}
