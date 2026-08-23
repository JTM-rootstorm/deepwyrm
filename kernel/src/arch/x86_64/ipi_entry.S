.section .text.ipi,"ax",@progbits

/*
 * Both fixed IPI entries are returning interrupt-gate boundaries. They save
 * the complete interrupted GPR set, normalize GS only for CPL3 origins, and
 * restore the exact register frame before IRETQ. The Rust dispatch boundary
 * owns local-APIC EOI and may return only after that acknowledgement succeeds.
 */
.macro IPI_ENTRY symbol, dispatch, local_prefix
    .p2align 4
    .globl \symbol
    .type \symbol,@function
\symbol:
    /* Interrupt gates enter with IF clear. */
    cld
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    /* Saved CS follows RIP after the 15 private register words. */
    movq 128(%rsp), %rax
    testb $3, %al
    jz .L\local_prefix\()_kernel_origin
    swapgs
    movq %rsp, %r12
    andq $-16, %rsp
    callq \dispatch
    movq %r12, %rsp
    swapgs
    jmp .L\local_prefix\()_restore
.L\local_prefix\()_kernel_origin:
    movq %rsp, %r12
    andq $-16, %rsp
    callq \dispatch
    movq %r12, %rsp
.L\local_prefix\()_restore:
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    iretq
    .size \symbol, .-\symbol
.endm

IPI_ENTRY dw_x86_64_rendezvous_ipi_entry, dw_x86_64_rendezvous_ipi_dispatch, rendezvous_ipi
IPI_ENTRY dw_x86_64_tlb_shootdown_ipi_entry, dw_x86_64_tlb_shootdown_ipi_dispatch, tlb_shootdown_ipi

.section .note.GNU-stack,"",@progbits
