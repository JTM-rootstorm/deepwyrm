#[path = "../../src/sync/spin.rs"]
mod spin;
#[path = "../../src/sync/irq.rs"]
mod irq;

fn require_sync<T: Sync>() {}
fn irq_guard_must_not_be_shared_between_threads<'a>() {
    require_sync::<irq::IrqSpinMutexGuard<'a, u64>>();
}
