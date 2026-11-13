.section .text.exceptions,"ax",@progbits
.p2align 4

/*
 * Every exception stub enters .Lexception_common with exactly two private
 * words above the processor frame: vector, then error code. E4 additionally
 * copies old RSP/SS into fixed normalized fields when saved CS has RPL3, and
 * writes zero copies for kernel-origin entries. The original hardware frame
 * remains untouched below the normalized snapshot.
 */
.macro NO_ERROR vector
    .p2align 4
    .globl dw_x86_64_exception_vector_\vector
    .type dw_x86_64_exception_vector_\vector,@function
dw_x86_64_exception_vector_\vector:
    pushq $0
    pushq $\vector
    jmp .Lexception_common
    .size dw_x86_64_exception_vector_\vector, .-dw_x86_64_exception_vector_\vector
.endm

.macro ERROR vector
    .p2align 4
    .globl dw_x86_64_exception_vector_\vector
    .type dw_x86_64_exception_vector_\vector,@function
dw_x86_64_exception_vector_\vector:
    pushq $\vector
    jmp .Lexception_common
    .size dw_x86_64_exception_vector_\vector, .-dw_x86_64_exception_vector_\vector
.endm

NO_ERROR 0
NO_ERROR 1
NO_ERROR 2
NO_ERROR 3
NO_ERROR 4
NO_ERROR 5
NO_ERROR 6
NO_ERROR 7
ERROR 8
NO_ERROR 9
ERROR 10
ERROR 11
ERROR 12
ERROR 13

/*
 * #PF (DW2 M6 §8.5): a CPL3 fault takes the returning tail below, which may
 * serve it from an on-demand MemoryObject and resume the faulting
 * instruction. A kernel-origin fault keeps the terminal common entry.
 */
    .p2align 4
    .globl dw_x86_64_exception_vector_14
    .type dw_x86_64_exception_vector_14,@function
dw_x86_64_exception_vector_14:
    pushq $14
    /* vector, error, RIP, then saved CS */
    testb $3, 24(%rsp)
    jz .Lexception_common
    jmp .Luser_page_fault
    .size dw_x86_64_exception_vector_14, .-dw_x86_64_exception_vector_14

NO_ERROR 15
NO_ERROR 16
ERROR 17
NO_ERROR 18
NO_ERROR 19
NO_ERROR 20
ERROR 21
NO_ERROR 22
NO_ERROR 23
NO_ERROR 24
NO_ERROR 25
NO_ERROR 26
NO_ERROR 27
NO_ERROR 28
ERROR 29
ERROR 30
NO_ERROR 31

.p2align 4
.Lexception_common:
    cli
    cld
    /* RFLAGS.AC is user-settable and interrupt delivery keeps it: clear it so
       SMAP holds in the handler (DW2 M2). CLAC would #UD without SMAP; the
       saved user RFLAGS keeps the user's AC. */
    pushfq
    btrq $18, (%rsp)
    popfq
    /* Preserve RAX before using it to normalize the optional old-stack tail. */
    pushq %rax
    movq 32(%rsp), %rax
    testb $3, %al
    jz .Lexception_kernel_origin
    movq 56(%rsp), %rax
    pushq %rax                    /* copied old SS */
    movq 56(%rsp), %rax
    pushq %rax                    /* copied old RSP */
    jmp .Lexception_stack_normalized
.Lexception_kernel_origin:
    pushq $0                      /* copied old SS */
    pushq $0                      /* copied old RSP */
.Lexception_stack_normalized:
    movq %cr2, %rax
    pushq %rax
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %rbx
    movq %rsp, %rdi
    andq $-16, %rsp
    callq dw_x86_64_exception_dispatch
    ud2

.p2align 4
.equ DW_TIMER_FRAME_SIZE, 160
.equ DW_TIMER_FRAME_R15, 0
.equ DW_TIMER_FRAME_RAX, 112
.equ DW_TIMER_FRAME_RIP, 120
.equ DW_TIMER_FRAME_CS, 128
.equ DW_TIMER_FRAME_RFLAGS, 136
.equ DW_TIMER_FRAME_RSP, 144
.equ DW_TIMER_FRAME_SS, 152
.equ DW_GS_CURRENT_STACK_TOP, 8
.globl dw_x86_64_apic_timer_entry
.type dw_x86_64_apic_timer_entry,@function
dw_x86_64_apic_timer_entry:
    /* Interrupt gates enter with IF clear. Preserve the complete interrupted GPR set. */
    cld
    /* RFLAGS.AC is user-settable and interrupt delivery keeps it: clear it so
       SMAP holds in the handler (DW2 M2). CLAC would #UD without SMAP; the
       saved user RFLAGS keeps the user's AC. */
    pushfq
    btrq $18, (%rsp)
    popfq
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
    jz .Lapic_timer_kernel_origin
    swapgs
    movq %rsp, %r12
    andq $-16, %rsp
    callq dw_x86_64_timer_interrupt_dispatch

    /*
     * E0 requires CPL3 interrupts to land on the fixed CPU-private RSP0
     * stack. Before the DW1-B preemption gate may retain this frame across a
     * Thread switch, copy the complete image onto the interrupted Thread's
     * currently bound kernel stack. The entry-stack image is abandoned after
     * this point and may be reused by a later privilege transition.
     */
    movq %r12, %rsi
    movq %gs:DW_GS_CURRENT_STACK_TOP, %rsp
    testq %rsp, %rsp
    jz .Lapic_timer_entry_fail
    subq $DW_TIMER_FRAME_SIZE, %rsp
    movq %rsp, %rdi
    movl $(DW_TIMER_FRAME_SIZE / 8), %ecx
    cld
    rep movsq
    movq %rsp, %r12
    movq %rsp, %rdi
    andq $-16, %rsp
    callq dw_x86_64_timer_pre_iret_gate
    movq %r12, %rsp
    swapgs
    jmp .Lapic_timer_restore
.Lapic_timer_kernel_origin:
    movq %rsp, %r12
    andq $-16, %rsp
    callq dw_x86_64_timer_interrupt_dispatch
    movq %r12, %rsp
.Lapic_timer_restore:
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
.Lapic_timer_entry_fail:
    ud2
.size dw_x86_64_apic_timer_entry, .-dw_x86_64_apic_timer_entry

/*
 * CPL3 #PF tail (DW2 M6 §8.5). The stub left the vector and error code above
 * the hardware frame on the CPU-private RSP0 stack. Like the timer entry,
 * this copies the interrupted context onto the Thread's bound kernel stack
 * in the 160-byte timer frame layout, without the vector and error words,
 * and calls the gate with CR2 and the error code captured here. The gate
 * returns only for a served fault; the exit is the timer entry's.
 */
.p2align 4
.Luser_page_fault:
    cld
    /* Clear the user-settable AC so SMAP holds in the handler (DW2 M2). */
    pushfq
    btrq $18, (%rsp)
    popfq
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
    /* The 15 register words, then the vector and the error code. */
    movq %cr2, %r13
    movq 128(%rsp), %r14
    swapgs
    movq %rsp, %rsi
    movq %gs:DW_GS_CURRENT_STACK_TOP, %rdx
    testq %rdx, %rdx
    jz .Luser_page_fault_fail
    subq $DW_TIMER_FRAME_SIZE, %rdx
    movq %rdx, %rdi
    movl $15, %ecx
    cld
    rep movsq
    /* Skip the vector and error words; copy RIP, CS, RFLAGS, RSP and SS. */
    addq $16, %rsi
    movl $5, %ecx
    rep movsq
    movq %rdx, %rsp
    movq %rsp, %r12
    movq %rsp, %rdi
    movq %r13, %rsi
    movq %r14, %rdx
    andq $-16, %rsp
    callq dw_x86_64_user_page_fault_gate
    movq %r12, %rsp
    swapgs
    jmp .Lapic_timer_restore
.Luser_page_fault_fail:
    ud2

.p2align 4
.globl dw_x86_64_apic_error_entry
.type dw_x86_64_apic_error_entry,@function
dw_x86_64_apic_error_entry:
    pushq $0
    pushq $0xfe
    jmp .Lterminal_interrupt_common
.size dw_x86_64_apic_error_entry, .-dw_x86_64_apic_error_entry

.p2align 4
.globl dw_x86_64_apic_spurious_entry
.type dw_x86_64_apic_spurious_entry,@function
dw_x86_64_apic_spurious_entry:
    /* APIC spurious delivery has no source to acknowledge and returns directly. */
    iretq
.size dw_x86_64_apic_spurious_entry, .-dw_x86_64_apic_spurious_entry

.p2align 4
.Lterminal_interrupt_common:
    cli
    cld
    /* RFLAGS.AC is user-settable and interrupt delivery keeps it: clear it so
       SMAP holds in the handler (DW2 M2). CLAC would #UD without SMAP; the
       saved user RFLAGS keeps the user's AC. */
    pushfq
    btrq $18, (%rsp)
    popfq
    pushq %rax
    movq 32(%rsp), %rax
    testb $3, %al
    jz .Lterminal_kernel_origin
    movq 56(%rsp), %rax
    pushq %rax                    /* copied old SS */
    movq 56(%rsp), %rax
    pushq %rax                    /* copied old RSP */
    jmp .Lterminal_stack_normalized
.Lterminal_kernel_origin:
    pushq $0
    pushq $0
.Lterminal_stack_normalized:
    movq %cr2, %rax
    pushq %rax
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rbp
    pushq %rdi
    pushq %rsi
    pushq %rdx
    pushq %rcx
    pushq %rbx
    movq %rsp, %rdi
    andq $-16, %rsp
    callq dw_x86_64_terminal_interrupt_dispatch
    ud2

.section .rodata.exceptions,"a",@progbits
.p2align 3
.globl dw_x86_64_exception_handler_table
.type dw_x86_64_exception_handler_table,@object
dw_x86_64_exception_handler_table:
    .quad dw_x86_64_exception_vector_0
    .quad dw_x86_64_exception_vector_1
    .quad dw_x86_64_exception_vector_2
    .quad dw_x86_64_exception_vector_3
    .quad dw_x86_64_exception_vector_4
    .quad dw_x86_64_exception_vector_5
    .quad dw_x86_64_exception_vector_6
    .quad dw_x86_64_exception_vector_7
    .quad dw_x86_64_exception_vector_8
    .quad dw_x86_64_exception_vector_9
    .quad dw_x86_64_exception_vector_10
    .quad dw_x86_64_exception_vector_11
    .quad dw_x86_64_exception_vector_12
    .quad dw_x86_64_exception_vector_13
    .quad dw_x86_64_exception_vector_14
    .quad dw_x86_64_exception_vector_15
    .quad dw_x86_64_exception_vector_16
    .quad dw_x86_64_exception_vector_17
    .quad dw_x86_64_exception_vector_18
    .quad dw_x86_64_exception_vector_19
    .quad dw_x86_64_exception_vector_20
    .quad dw_x86_64_exception_vector_21
    .quad dw_x86_64_exception_vector_22
    .quad dw_x86_64_exception_vector_23
    .quad dw_x86_64_exception_vector_24
    .quad dw_x86_64_exception_vector_25
    .quad dw_x86_64_exception_vector_26
    .quad dw_x86_64_exception_vector_27
    .quad dw_x86_64_exception_vector_28
    .quad dw_x86_64_exception_vector_29
    .quad dw_x86_64_exception_vector_30
    .quad dw_x86_64_exception_vector_31
.size dw_x86_64_exception_handler_table, .-dw_x86_64_exception_handler_table

.section .note.GNU-stack,"",@progbits
