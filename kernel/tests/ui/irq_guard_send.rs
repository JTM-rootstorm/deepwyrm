#[path = "../../src/sync/spin.rs"]
mod spin;
#[path = "../../src/sync/irq.rs"]
mod irq;

fn require_send<T: Send>() {}
fn irq_guard_must_not_move_between_threads<'a>() {
    require_send::<irq::IrqSpinMutexGuard<'a, u64>>();
}
