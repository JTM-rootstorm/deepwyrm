.section .text.kernel_context,"ax",@progbits
.p2align 4

/*
 * Validated Thread-owned switch entry. RDX/RCX name the exact outgoing stack
 * bottom/top. The checks use the assembly entry RSP, so they cover the return
 * address plus the seven words the raw switch saves below it without relying
 * on compiler frame geometry.
 */
.globl dw_x86_64_switch_owned_kernel_context
.type dw_x86_64_switch_owned_kernel_context,@function
dw_x86_64_switch_owned_kernel_context:
    movq %rsp, %r8
    andq $0xf, %r8
    cmpq $8, %r8
    jne .Lowned_switch_fail
    movq %rsp, %r8
    subq $56, %r8
    jc .Lowned_switch_fail
    cmpq %rdx, %r8
    jb .Lowned_switch_fail
    movq %rsp, %r8
    addq $8, %r8
    jc .Lowned_switch_fail
    cmpq %rcx, %r8
    ja .Lowned_switch_fail
    jmp dw_x86_64_switch_kernel_context
.Lowned_switch_fail:
    ud2
.size dw_x86_64_switch_owned_kernel_context, .-dw_x86_64_switch_owned_kernel_context

/*
 * SysV kernel-continuation switch frame, addressed by saved RSP:
 *   +0  R15
 *   +8  R14
 *   +16 R13
 *   +24 R12
 *   +32 RBP
 *   +40 RBX
 *   +48 RFLAGS
 *   +56 return RIP
 *
 * Caller-saved registers belong to the ordinary function-call boundary and
 * therefore need no extra persistence here. No user/IRET frame participates.
 */
.globl dw_x86_64_switch_kernel_context
.type dw_x86_64_switch_kernel_context,@function
dw_x86_64_switch_kernel_context:
    pushfq
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rsp, (%rdi)
    movq %rsi, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    popfq
    retq
.size dw_x86_64_switch_kernel_context, .-dw_x86_64_switch_kernel_context

.section .note.GNU-stack,"",@progbits
