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
ERROR 14
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
    pushq $0
    pushq $0xff
    jmp .Lterminal_interrupt_common
.size dw_x86_64_apic_spurious_entry, .-dw_x86_64_apic_spurious_entry

.p2align 4
.Lterminal_interrupt_common:
    cli
    cld
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
