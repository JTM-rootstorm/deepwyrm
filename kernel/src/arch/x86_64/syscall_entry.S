.section .text.syscall,"ax",@progbits
.p2align 4

/* PerCpuEntryState offsets, locked by Rust offset tests. */
.equ E4_GS_ENTRY_STACK_TOP,       0
.equ E4_GS_CURRENT_STACK_TOP,     8
.equ E4_GS_BINDING_GENERATION,   16
.equ E4_GS_STAGED_USER_RSP,      24
.equ E4_GS_STAGED_USER_RIP,      32
.equ E4_GS_STAGED_USER_RFLAGS,   40

/* RawSyscallFrame offsets. */
.equ E4_SC_R15,                   0
.equ E4_SC_R14,                   8
.equ E4_SC_R13,                  16
.equ E4_SC_R12,                  24
.equ E4_SC_RBP,                  32
.equ E4_SC_RBX,                  40
.equ E4_SC_R9,                   48
.equ E4_SC_R8,                   56
.equ E4_SC_R10,                  64
.equ E4_SC_RDX,                  72
.equ E4_SC_RSI,                  80
.equ E4_SC_RDI,                  88
.equ E4_SC_RAX,                  96
.equ E4_SC_USER_RIP,             104
.equ E4_SC_USER_RFLAGS,          112
.equ E4_SC_USER_RSP,             120
.equ E4_SC_BINDING_GENERATION,   128
.equ E4_SC_RETURN_AUTHORIZED,    136
.equ E4_SC_FRAME_SIZE,           144

/* RawUserReturnContext offsets. */
.equ E4_UR_R15,                    0
.equ E4_UR_R14,                    8
.equ E4_UR_R13,                   16
.equ E4_UR_R12,                   24
.equ E4_UR_RBP,                   32
.equ E4_UR_RBX,                   40
.equ E4_UR_R9,                    48
.equ E4_UR_R8,                    56
.equ E4_UR_R10,                   64
.equ E4_UR_RDX,                   72
.equ E4_UR_RSI,                   80
.equ E4_UR_RDI,                   88
.equ E4_UR_RAX,                   96
.equ E4_UR_RCX,                  104
.equ E4_UR_R11,                  112
.equ E4_UR_USER_RIP,             120
.equ E4_UR_USER_RFLAGS,          128
.equ E4_UR_USER_RSP,             136

.globl dw_x86_64_syscall_entry
.type dw_x86_64_syscall_entry,@function
dw_x86_64_syscall_entry:
    /*
     * SYSCALL leaves the user RSP live. The only permitted writes before the
     * stack switch are to supervisor-only GS scratch fixed by E0.
     */
    movq %rsp, %gs:E4_GS_STAGED_USER_RSP
    movq %rcx, %gs:E4_GS_STAGED_USER_RIP
    movq %r11, %gs:E4_GS_STAGED_USER_RFLAGS
    movq %gs:E4_GS_ENTRY_STACK_TOP, %rsp
    testq %rsp, %rsp
    jz .Le4_entry_fail

    subq $E4_SC_FRAME_SIZE, %rsp
    movq %r15, E4_SC_R15(%rsp)
    movq %r14, E4_SC_R14(%rsp)
    movq %r13, E4_SC_R13(%rsp)
    movq %r12, E4_SC_R12(%rsp)
    movq %rbp, E4_SC_RBP(%rsp)
    movq %rbx, E4_SC_RBX(%rsp)
    movq %r9, E4_SC_R9(%rsp)
    movq %r8, E4_SC_R8(%rsp)
    movq %r10, E4_SC_R10(%rsp)
    movq %rdx, E4_SC_RDX(%rsp)
    movq %rsi, E4_SC_RSI(%rsp)
    movq %rdi, E4_SC_RDI(%rsp)
    movq %rax, E4_SC_RAX(%rsp)

    /* User R12 is saved, so it becomes private scratch from here onward. */
    movq %gs:E4_GS_STAGED_USER_RIP, %r12
    movq %r12, E4_SC_USER_RIP(%rsp)
    movq %gs:E4_GS_STAGED_USER_RFLAGS, %r12
    movq %r12, E4_SC_USER_RFLAGS(%rsp)
    movq %gs:E4_GS_STAGED_USER_RSP, %r12
    movq %r12, E4_SC_USER_RSP(%rsp)
    movq %gs:E4_GS_BINDING_GENERATION, %r12
    movq %r12, E4_SC_BINDING_GENERATION(%rsp)
    movq $0, E4_SC_RETURN_AUTHORIZED(%rsp)

    movq %rsp, %r12
    movq %gs:E4_GS_CURRENT_STACK_TOP, %rsp
    testq %rsp, %rsp
    jz .Le4_entry_fail
    movq %r12, %rdi
    callq dw_x86_64_syscall_dispatch

    cmpq $1, E4_SC_RETURN_AUTHORIZED(%r12)
    jne .Le4_entry_fail

    /* Build the exact E0 IRETQ frame on the current Thread's kernel stack. */
    pushq $0x2b
    pushq E4_SC_USER_RSP(%r12)
    pushq E4_SC_USER_RFLAGS(%r12)
    pushq $0x33
    pushq E4_SC_USER_RIP(%r12)

    movq E4_SC_R15(%r12), %r15
    movq E4_SC_R14(%r12), %r14
    movq E4_SC_R13(%r12), %r13
    movq E4_SC_RBP(%r12), %rbp
    movq E4_SC_RBX(%r12), %rbx
    movq E4_SC_R9(%r12), %r9
    movq E4_SC_R8(%r12), %r8
    movq E4_SC_R10(%r12), %r10
    movq E4_SC_RDX(%r12), %rdx
    movq E4_SC_RSI(%r12), %rsi
    movq E4_SC_RDI(%r12), %rdi
    movq E4_SC_RAX(%r12), %rax
    xorl %ecx, %ecx
    xorl %r11d, %r11d
    movq E4_SC_R12(%r12), %r12
    iretq
.size dw_x86_64_syscall_entry, .-dw_x86_64_syscall_entry

.p2align 4
.globl dw_x86_64_iret_to_user
.type dw_x86_64_iret_to_user,@function
dw_x86_64_iret_to_user:
    /* RDI is a Rust-validated RawUserReturnContext. */
    movq %rdi, %r12
    movq %gs:E4_GS_CURRENT_STACK_TOP, %rsp
    testq %rsp, %rsp
    jz .Le4_entry_fail

    pushq $0x2b
    pushq E4_UR_USER_RSP(%r12)
    pushq E4_UR_USER_RFLAGS(%r12)
    pushq $0x33
    pushq E4_UR_USER_RIP(%r12)

    movq E4_UR_R15(%r12), %r15
    movq E4_UR_R14(%r12), %r14
    movq E4_UR_R13(%r12), %r13
    movq E4_UR_RBP(%r12), %rbp
    movq E4_UR_RBX(%r12), %rbx
    movq E4_UR_R9(%r12), %r9
    movq E4_UR_R8(%r12), %r8
    movq E4_UR_R10(%r12), %r10
    movq E4_UR_RDX(%r12), %rdx
    movq E4_UR_RSI(%r12), %rsi
    movq E4_UR_RDI(%r12), %rdi
    movq E4_UR_RAX(%r12), %rax
    movq E4_UR_RCX(%r12), %rcx
    movq E4_UR_R11(%r12), %r11
    movq E4_UR_R12(%r12), %r12
    iretq
.size dw_x86_64_iret_to_user, .-dw_x86_64_iret_to_user

.p2align 4
.Le4_entry_fail:
    cli
1:
    hlt
    jmp 1b

.section .note.GNU-stack,"",@progbits
