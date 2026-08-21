/* DW0-F9 synthetic CPL3 atomic wait/wake body.
 *
 * Both Threads enter the same blob. The selector runtime supplies role zero
 * to the waiter and role one to the waker in the first user argument.
 */
.globl _start
.type _start,@function
_start:
    testq %rdi, %rdi
    jne .Lf9_waker

.Lf9_waiter:
    movl $DW_F9_SYSCALL_ATOMIC_WAIT32, %edi
    movabsq $DW_F9_USER_DATA_ADDRESS, %rsi
    xorl %edx, %edx
    movq $-1, %rcx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    subq $16, %rsp
    movq $0, (%rsp)
    callq dw_syscall6
    addq $16, %rsp
    testl %eax, %eax
    jne .Lf9_fail

    movl $DW_F9_SYSCALL_PROCESS_EXIT, %edi
    xorl %esi, %esi
    xorl %edx, %edx
    xorl %ecx, %ecx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    subq $16, %rsp
    movq $0, (%rsp)
    callq dw_syscall6

.Lf9_waker:
    movabsq $DW_F9_USER_DATA_ADDRESS, %r10
    movl $1, (%r10)
    movl $DW_F9_SYSCALL_ATOMIC_WAKE, %edi
    movabsq $DW_F9_USER_DATA_ADDRESS, %rsi
    movl $1, %edx
    movabsq $(DW_F9_USER_DATA_ADDRESS + 8), %rcx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    subq $16, %rsp
    movq $0, (%rsp)
    callq dw_syscall6
    addq $16, %rsp
    testl %eax, %eax
    jne .Lf9_fail
    cmpl $1, DW_F9_USER_DATA_ADDRESS + 8
    jne .Lf9_fail

    /* The waiter owns terminal process exit; this Thread remains blocked. */
    movl $DW_F9_SYSCALL_ATOMIC_WAIT32, %edi
    movabsq $DW_F9_USER_DATA_ADDRESS, %rsi
    movl $1, %edx
    movq $-1, %rcx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    subq $16, %rsp
    movq $0, (%rsp)
    callq dw_syscall6

.Lf9_fail:
    ud2
    jmp .Lf9_fail
.size _start, .-_start
