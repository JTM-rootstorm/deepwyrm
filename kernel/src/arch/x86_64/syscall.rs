//! DW0-E4 x86_64 privilege transition, SYSCALL, and IRETQ contracts.

mod frame;
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
mod live;
mod msr;

#[allow(
    unused_imports,
    reason = "E4 return validation is consumed by E5 mapping-aware syscall adapters and E7 userspace entry"
)]
pub(crate) use frame::{
    ProcessUserReturnMappingValidation, RawSyscallFrame, RawUserReturnContext, UserReturnError,
    UserReturnMappingValidation, ValidatedUserReturn, is_lower_canonical_user_address,
    sanitize_user_rflags,
};
#[allow(
    unused_imports,
    reason = "E4 MSR constants remain visible to target/source contract checks"
)]
pub(crate) use msr::{E4_FMASK, SyscallMsrPlan, normalize_cr0_for_e5, normalize_cr4_for_e4};

#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unused_imports,
    reason = "E4 exception-runtime binding is consumed by the later primordial/task runtime"
)]
pub(crate) use super::exceptions::{
    UserExceptionBindError, UserExceptionBinding, UserExceptionHandler, bind_user_exception_handler,
};
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
#[allow(
    unused_imports,
    reason = "E4 target entry is wired into primordial runtime and E5 syscall adapters in later E work"
)]
pub(crate) use live::{
    SyscallRuntimeBindError, SyscallRuntimeBinding, bind_current_thread_stack,
    bind_native_syscall_runtime, current_binding_generation, enter_validated_user,
    install_syscall_boundary, validate_live_syscall_boundary,
};

#[cfg(test)]
#[path = "syscall/tests.rs"]
mod tests;
