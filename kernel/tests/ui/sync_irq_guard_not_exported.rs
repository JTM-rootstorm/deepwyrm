// The kernel's lock guards must stay unnameable outside `sync`, so no
// execution owner can store one: holds the E3 guard boundary that
// `task::execution::tests::e3_execution_owners_are_send_sync_without_exporting_lock_guards`
// used to check by scanning sync/mod.rs's text.
#[path = "../../src/sync/mod.rs"]
mod sync;

#[allow(unused_imports)]
use sync::IrqSpinMutexGuard;
