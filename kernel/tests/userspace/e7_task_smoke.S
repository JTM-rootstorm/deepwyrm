/* DW0-E7 synthetic CPL3 smoke body.
 *
 * Build tooling prepends generated ABI constants and appends a re-sectioned
 * copy of abi/generated/syscall_veneer_x86_64.S. This source deliberately
 * calls dw_syscall6 rather than spelling the raw SYSCALL convention itself.
 */
.globl _start
.type _start,@function
_start:
    /*
     * E8 regression: CPL3 may legally reload the DPL3 data selector into GS,
     * replacing the effective GS base with this descriptor's zero base. The
     * SYSCALL entry must recover its kernel entry-state base before any %gs
     * access rather than trusting the user-resident base.
     */
    movw $0x2b, %ax
    movw %ax, %gs

    movl $DW_E7_SYSCALL_ABI_GET_INFO, %edi
    movabsq $DW_E7_USER_INFO_ADDRESS, %rsi
    movl $DW_E7_ABI_INFO_SIZE, %edx
    movabsq $DW_E7_USER_REQUIRED_ADDRESS, %rcx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    subq $16, %rsp
    movq $0, (%rsp)
    callq dw_syscall6
    addq $16, %rsp
    testl %eax, %eax
    jne .Le7_fail

    movabsq $DW_E7_USER_INFO_ADDRESS, %r10
    cmpl $DW_E7_ABI_INFO_SIZE, 0(%r10)
    jne .Le7_fail
    cmpl $1, 4(%r10)
    jne .Le7_fail
    cmpl $DW_E7_ABI_VERSION, 8(%r10)
    jne .Le7_fail
    cmpl $DW_E7_PAGE_SIZE, 12(%r10)
    jne .Le7_fail

    movabsq $DW_E7_USER_REQUIRED_ADDRESS, %r10
    cmpq $DW_E7_ABI_INFO_SIZE, (%r10)
    jne .Le7_fail

    /* F3 regression: the active monotonic clock is available from real CPL3. */
    movl $DW_E7_SYSCALL_CLOCK_GET, %edi
    movl $DW_E7_CLOCK_MONOTONIC_ACTIVE, %esi
    movabsq $DW_E7_USER_CLOCK_ADDRESS, %rdx
    xorl %ecx, %ecx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    subq $16, %rsp
    movq $0, (%rsp)
    callq dw_syscall6
    addq $16, %rsp
    testl %eax, %eax
    jne .Le7_fail
    movabsq $DW_E7_USER_CLOCK_ADDRESS, %r10
    cmpq $0, (%r10)
    je .Le7_fail

    /* Unknown numeric dispatch must return NOT_SUPPORTED and preserve return. */
    movl $DW_E7_UNKNOWN_SYSCALL, %edi
    xorl %esi, %esi
    xorl %edx, %edx
    xorl %ecx, %ecx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    subq $16, %rsp
    movq $0, (%rsp)
    callq dw_syscall6
    addq $16, %rsp
    cmpl $DW_E7_STATUS_NOT_SUPPORTED, %eax
    jne .Le7_fail

    /* This call is deliberately nonreturning after kernel reschedule. */
    movl $DW_E7_SYSCALL_PROCESS_EXIT, %edi
    xorl %esi, %esi
    xorl %edx, %edx
    xorl %ecx, %ecx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    subq $16, %rsp
    movq $0, (%rsp)
    callq dw_syscall6

.Le7_fail:
    ud2
    jmp .Le7_fail
.size _start, .-_start
