// Minimal crate context for the compile-fail fixtures that build
// `syscall/boundary_tokens.rs` as a standalone crate (S2K-3).

#[path = "../../src/memory/kernel_stack.rs"]
mod kernel_stack;

mod memory {
    pub(crate) mod kernel_stack {
        pub(crate) use crate::kernel_stack::*;
    }
}

#[path = "../../src/arch/x86_64/syscall/boundary_tokens.rs"]
mod boundary_tokens;
