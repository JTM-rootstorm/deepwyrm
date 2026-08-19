.section .text.kernel_context,"ax",@progbits
.p2align 4

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
