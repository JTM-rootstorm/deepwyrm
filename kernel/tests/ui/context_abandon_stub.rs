// Crate context for the compile-fail fixtures that build the real
// `arch/x86_64/context.rs`, including its target-only
// `abandon_to_kernel_continuation` (S2K-3a). The harness passes
// `--cfg target_os="none"` for these fixtures, which type-checks the
// target-only items on the host; nothing is code-generated or run.

#[path = "../../src/memory/kernel_stack.rs"]
mod kernel_stack;

mod memory {
    pub(crate) mod kernel_stack {
        pub(crate) use crate::kernel_stack::*;
    }
}

include!("runtime_authority_stub.rs");

#[path = "../../src/arch/x86_64/context.rs"]
mod context;

mod arch {
    pub(crate) mod x86_64 {
        pub(crate) mod syscall {
            pub(crate) use crate::GuardFree;
        }
        pub(crate) use crate::context;
    }
}
