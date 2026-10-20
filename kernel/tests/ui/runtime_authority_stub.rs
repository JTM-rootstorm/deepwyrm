// Minimal crate context for the compile-fail fixtures that build
// `mm/activation/runtime_authority.rs` and `syscall/guard_free.rs` as a
// standalone crate (S2K-3). Both need only `core`; `runtime_authority.rs`
// names the token as `super::GuardFree`, which is this crate root.

#[path = "../../src/arch/x86_64/syscall/guard_free.rs"]
mod guard_free;
#[allow(unused_imports)]
pub(crate) use guard_free::{CarrierRelease, GuardFree};

#[path = "../../src/arch/x86_64/mm/activation/runtime_authority.rs"]
mod runtime_authority;
