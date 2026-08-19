#![cfg_attr(
    not(all(target_os = "none", target_arch = "x86_64")),
    allow(
        dead_code,
        reason = "E4 frame contracts are host-tested before target/E5 consumers"
    )
)]

//! Fixed-width x86_64 user-entry and raw-SYSCALL frame contracts.

use deepwyrm_abi::{DwStatus, DwSyscallId};

use crate::syscall::RawSyscallArguments;
use crate::task::{FpSimdPolicy, GeneralPurposeRegisters, SavedThreadContext, UserTlsPolicy};

pub(crate) const SAFE_USER_RFLAGS_MASK: u64 = 0x0020_0cd5;
pub(crate) const REQUIRED_USER_RFLAGS: u64 = 0x0000_0202;
pub(crate) const SYSCALL_RETURN_AUTHORIZED: u64 = 1;
const USER_END_EXCLUSIVE: u64 = 0x0000_8000_0000_0000;

#[repr(C, align(64))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PerCpuEntryState {
    pub(crate) entry_stack_top: u64,
    pub(crate) current_kernel_stack_top: u64,
    pub(crate) binding_generation: u64,
    pub(crate) staged_user_rsp: u64,
    pub(crate) staged_user_rip: u64,
    pub(crate) staged_user_rflags: u64,
    pub(crate) reserved: [u64; 2],
}

impl PerCpuEntryState {
    pub(crate) const fn empty() -> Self {
        Self {
            entry_stack_top: 0,
            current_kernel_stack_top: 0,
            binding_generation: 1,
            staged_user_rsp: 0,
            staged_user_rip: 0,
            staged_user_rflags: 0,
            reserved: [0; 2],
        }
    }
}

pub(crate) trait UserReturnMappingValidation {
    fn executable_at(&mut self, instruction_pointer: u64) -> bool;
    fn writable_byte_below(&mut self, stack_pointer: u64) -> bool;
}

/// Mapping validator bound to the exact Process whose user context is being
/// created. Cross-process Thread handles must not validate RIP/RSP against the
/// caller's active address space by accident.
pub(crate) trait ProcessUserReturnMappingValidation: UserReturnMappingValidation {
    fn process_key(&self) -> crate::task::ProcessKey;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum UserReturnError {
    NonCanonicalUserAddress,
    InstructionNotExecutable,
    StackNotWritable,
    UnsupportedTlsPolicy,
    UnsupportedFpSimdPolicy,
    BindingChanged,
}

pub(crate) const fn sanitize_user_rflags(saved: u64) -> u64 {
    (saved & SAFE_USER_RFLAGS_MASK) | REQUIRED_USER_RFLAGS
}

pub(crate) const fn is_lower_canonical_user_address(address: u64) -> bool {
    address != 0 && address < USER_END_EXCLUSIVE
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawUserReturnContext {
    pub(crate) r15: u64,
    pub(crate) r14: u64,
    pub(crate) r13: u64,
    pub(crate) r12: u64,
    pub(crate) rbp: u64,
    pub(crate) rbx: u64,
    pub(crate) r9: u64,
    pub(crate) r8: u64,
    pub(crate) r10: u64,
    pub(crate) rdx: u64,
    pub(crate) rsi: u64,
    pub(crate) rdi: u64,
    pub(crate) rax: u64,
    pub(crate) rcx: u64,
    pub(crate) r11: u64,
    pub(crate) user_rip: u64,
    pub(crate) user_rflags: u64,
    pub(crate) user_rsp: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ValidatedUserReturn(RawUserReturnContext);

impl ValidatedUserReturn {
    pub(crate) fn initial<M: UserReturnMappingValidation>(
        context: SavedThreadContext,
        mappings: &mut M,
    ) -> Result<Self, UserReturnError> {
        validate_policies(context)?;
        validate_return_mapping(context.user_rip, context.user_rsp, mappings)?;
        let mut gprs = context.gprs;
        gprs.rdi = context.startup_arguments[0];
        gprs.rsi = context.startup_arguments[1];
        Ok(Self(raw_user_context(
            gprs,
            context.user_rip,
            context.user_rsp,
            sanitize_user_rflags(context.user_rflags),
        )))
    }

    pub(crate) const fn raw(&self) -> &RawUserReturnContext {
        &self.0
    }
}

fn validate_policies(context: SavedThreadContext) -> Result<(), UserReturnError> {
    if context.tls_policy != UserTlsPolicy::DisabledKernelGsOnly {
        return Err(UserReturnError::UnsupportedTlsPolicy);
    }
    if context.fp_simd_policy != FpSimdPolicy::Unavailable {
        return Err(UserReturnError::UnsupportedFpSimdPolicy);
    }
    Ok(())
}

fn validate_return_mapping<M: UserReturnMappingValidation>(
    instruction_pointer: u64,
    stack_pointer: u64,
    mappings: &mut M,
) -> Result<(), UserReturnError> {
    if !is_lower_canonical_user_address(instruction_pointer)
        || !is_lower_canonical_user_address(stack_pointer)
        || stack_pointer.checked_sub(1).is_none()
    {
        return Err(UserReturnError::NonCanonicalUserAddress);
    }
    if !mappings.executable_at(instruction_pointer) {
        return Err(UserReturnError::InstructionNotExecutable);
    }
    if !mappings.writable_byte_below(stack_pointer) {
        return Err(UserReturnError::StackNotWritable);
    }
    Ok(())
}

const fn raw_user_context(
    gprs: GeneralPurposeRegisters,
    rip: u64,
    rsp: u64,
    rflags: u64,
) -> RawUserReturnContext {
    RawUserReturnContext {
        r15: gprs.r15,
        r14: gprs.r14,
        r13: gprs.r13,
        r12: gprs.r12,
        rbp: gprs.rbp,
        rbx: gprs.rbx,
        r9: gprs.r9,
        r8: gprs.r8,
        r10: gprs.r10,
        rdx: gprs.rdx,
        rsi: gprs.rsi,
        rdi: gprs.rdi,
        rax: gprs.rax,
        rcx: gprs.rcx,
        r11: gprs.r11,
        user_rip: rip,
        user_rflags: rflags,
        user_rsp: rsp,
    }
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RawSyscallFrame {
    pub(super) r15: u64,
    pub(super) r14: u64,
    pub(super) r13: u64,
    pub(super) r12: u64,
    pub(super) rbp: u64,
    pub(super) rbx: u64,
    pub(super) r9: u64,
    pub(super) r8: u64,
    pub(super) r10: u64,
    pub(super) rdx: u64,
    pub(super) rsi: u64,
    pub(super) rdi: u64,
    pub(super) rax: u64,
    pub(super) user_rip: u64,
    pub(super) user_rflags: u64,
    pub(super) user_rsp: u64,
    pub(super) binding_generation: u64,
    pub(super) return_authorized: u64,
}

impl RawSyscallFrame {
    pub(crate) const fn validates_entry(&self) -> bool {
        is_lower_canonical_user_address(self.user_rip)
            && self.binding_generation != 0
            && self.return_authorized == 0
    }

    pub(crate) fn request(&self) -> Option<(DwSyscallId, RawSyscallArguments)> {
        let number = u32::try_from(self.rax).ok()?;
        Some((
            DwSyscallId(number),
            RawSyscallArguments::new([self.rdi, self.rsi, self.rdx, self.r10, self.r8, self.r9]),
        ))
    }

    #[cfg_attr(
        not(all(target_os = "none", target_arch = "x86_64")),
        allow(
            dead_code,
            reason = "status is written by the target E4 raw dispatch boundary"
        )
    )]
    pub(crate) fn set_status(&mut self, status: DwStatus) {
        self.rax = i64::from(status.0) as u64;
    }

    pub(crate) fn rebind_after_kernel_resume(
        &mut self,
        current_binding_generation: u64,
    ) -> Result<(), UserReturnError> {
        if current_binding_generation == 0 || self.return_authorized != 0 {
            return Err(UserReturnError::BindingChanged);
        }
        self.binding_generation = current_binding_generation;
        Ok(())
    }

    pub(crate) fn authorize_return<M: UserReturnMappingValidation>(
        &mut self,
        current_binding_generation: u64,
        mappings: &mut M,
    ) -> Result<(), UserReturnError> {
        if current_binding_generation == 0 || self.binding_generation != current_binding_generation
        {
            return Err(UserReturnError::BindingChanged);
        }
        validate_return_mapping(self.user_rip, self.user_rsp, mappings)?;
        self.user_rflags = sanitize_user_rflags(self.user_rflags);
        self.return_authorized = SYSCALL_RETURN_AUTHORIZED;
        Ok(())
    }

    #[cfg_attr(
        not(all(target_os = "none", target_arch = "x86_64")),
        allow(
            dead_code,
            reason = "generation is checked by the target E4 raw dispatch boundary"
        )
    )]
    pub(crate) const fn binding_generation(&self) -> u64 {
        self.binding_generation
    }

    #[cfg(test)]
    pub(crate) const fn test_status_bits(&self) -> u64 {
        self.rax
    }

    #[cfg(test)]
    pub(crate) const fn test_return_authorized(&self) -> u64 {
        self.return_authorized
    }

    #[cfg(test)]
    pub(crate) fn synthetic(
        number: u64,
        arguments: [u64; 6],
        rip: u64,
        rsp: u64,
        rflags: u64,
        generation: u64,
    ) -> Self {
        Self {
            r15: 0x15,
            r14: 0x14,
            r13: 0x13,
            r12: 0x12,
            rbp: 0xb0,
            rbx: 0xb,
            r9: arguments[5],
            r8: arguments[4],
            r10: arguments[3],
            rdx: arguments[2],
            rsi: arguments[1],
            rdi: arguments[0],
            rax: number,
            user_rip: rip,
            user_rflags: rflags,
            user_rsp: rsp,
            binding_generation: generation,
            return_authorized: 0,
        }
    }
}
