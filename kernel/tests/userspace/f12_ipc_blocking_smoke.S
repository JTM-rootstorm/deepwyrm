/* DW0-F12 synthetic CPL3 IPC/blocking body.
 *
 * Both Threads enter this blob. Role zero is the service/receiver; role one
 * is the producer/waker. Build tooling prepends the fixed F12 data layout and
 * generated ABI constants, then appends the generated syscall veneer. Every
 * native syscall below therefore calls dw_syscall6 rather than spelling the
 * raw SYSCALL convention.
 */

.macro DW_F12_CALL
    subq $16, %rsp
    movq $0, (%rsp)
    callq dw_syscall6
    addq $16, %rsp
.endm

.globl _start
.type _start,@function
_start:
    testq %rdi, %rdi
    jne .Lf12_producer

.Lf12_service:
    /* Create the main and child-bootstrap Channel pairs. */
    movl $DW_F12_SYSCALL_CHANNEL_CREATE, %edi
    movl $DW_F12_RIGHTS_CHANNEL, %esi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_MAIN_RX, %rdx
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_MAIN_TX, %rcx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail

    movl $DW_F12_SYSCALL_CHANNEL_CREATE, %edi
    movl $DW_F12_RIGHTS_CHANNEL, %esi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_BOOTSTRAP_SOURCE, %rdx
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_BOOTSTRAP_PEER, %rcx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail

    /* Keep a transferable Event source and a SIGNAL-only sibling. */
    movl $DW_F12_SYSCALL_EVENT_CREATE, %edi
    movl $DW_F12_RIGHTS_EVENT, %esi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_EVENT_SOURCE, %rdx
    xorl %ecx, %ecx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail

    movl $DW_F12_SYSCALL_HANDLE_DUPLICATE, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_EVENT_SOURCE, %r10
    movq (%r10), %rsi
    movl $DW_F12_RIGHT_SIGNAL, %edx
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_EVENT_SIGNALER, %rcx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail

    /* Publish one finite absolute deadline before the first blocking wait. */
    movl $DW_F12_SYSCALL_CLOCK_GET, %edi
    xorl %esi, %esi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_CLOCK_NOW, %rdx
    xorl %ecx, %ecx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_CLOCK_NOW, %r10
    movq (%r10), %rax
    movabsq $1000000000, %r11
    addq %r11, %rax
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_DEADLINE, %r10
    movq %rax, (%r10)
    movb $'A', DW_F12_USER_DATA_ADDRESS + DW_F12_MESSAGE_A
    movb $'B', DW_F12_USER_DATA_ADDRESS + DW_F12_MESSAGE_B

    /* Role one makes this Channel readable, waking this real syscall. */
    movl $DW_F12_SYSCALL_WAIT_ONE, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_MAIN_RX, %r10
    movq (%r10), %rsi
    movl $DW_F12_SIGNAL_READABLE, %edx
    movq $DW_F12_DEADLINE_INFINITE, %rcx
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_WAIT_RESULT, %r8
    xorl %r9d, %r9d
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail

    /* Ordered receive: byte-only A precedes B plus one reduced-right Event. */
    movl $DW_F12_SYSCALL_CHANNEL_RECEIVE, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_MAIN_RX, %r10
    movq (%r10), %rsi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_RECEIVE_BYTES, %rdx
    movl $16, %ecx
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_RECEIVED_HANDLE, %r8
    movl $1, %r9d
    subq $16, %rsp
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_RECEIVE_RESULT, %rax
    movq %rax, (%rsp)
    callq dw_syscall6
    addq $16, %rsp
    testl %eax, %eax
    jne .Lf12_fail
    cmpl $1, DW_F12_USER_DATA_ADDRESS + DW_F12_RECEIVE_RESULT + 8
    jne .Lf12_fail
    cmpl $0, DW_F12_USER_DATA_ADDRESS + DW_F12_RECEIVE_RESULT + 12
    jne .Lf12_fail
    cmpb $'A', DW_F12_USER_DATA_ADDRESS + DW_F12_RECEIVE_BYTES
    jne .Lf12_fail

    movl $DW_F12_SYSCALL_CHANNEL_RECEIVE, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_MAIN_RX, %r10
    movq (%r10), %rsi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_RECEIVE_BYTES, %rdx
    movl $16, %ecx
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_RECEIVED_HANDLE, %r8
    movl $1, %r9d
    subq $16, %rsp
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_RECEIVE_RESULT, %rax
    movq %rax, (%rsp)
    callq dw_syscall6
    addq $16, %rsp
    testl %eax, %eax
    jne .Lf12_fail
    cmpl $1, DW_F12_USER_DATA_ADDRESS + DW_F12_RECEIVE_RESULT + 8
    jne .Lf12_fail
    cmpl $1, DW_F12_USER_DATA_ADDRESS + DW_F12_RECEIVE_RESULT + 12
    jne .Lf12_fail
    cmpb $'B', DW_F12_USER_DATA_ADDRESS + DW_F12_RECEIVE_BYTES
    jne .Lf12_fail
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_RECEIVED_HANDLE, %r10
    cmpq $0, (%r10)
    je .Lf12_fail
    movq DW_F12_USER_DATA_ADDRESS + DW_F12_MOVED_EVENT_SOURCE, %rax
    cmpq %rax, (%r10)
    je .Lf12_fail
    cmpq $DW_F12_RIGHT_WAIT, 8(%r10)
    jne .Lf12_fail
    cmpl $DW_F12_OBJECT_TYPE_EVENT, 16(%r10)
    jne .Lf12_fail

    /* Wake the producer's atomic sleep without spinning. */
    movl $1, DW_F12_USER_DATA_ADDRESS + DW_F12_SYNC0
    movl $DW_F12_SYSCALL_ATOMIC_WAKE, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_SYNC0, %rsi
    movl $1, %edx
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_WOKEN, %rcx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail
    cmpl $1, DW_F12_USER_DATA_ADDRESS + DW_F12_WOKEN
    jne .Lf12_fail

    /* The SIGNAL-only duplicate in role one satisfies this finite wait. */
    movl $DW_F12_SYSCALL_WAIT_ONE, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_RECEIVED_HANDLE, %r10
    movq (%r10), %rsi
    movl $DW_F12_SIGNAL_SIGNALED, %edx
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_DEADLINE, %r10
    movq (%r10), %rcx
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_WAIT_RESULT, %r8
    xorl %r9d, %r9d
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail

    /* Move the bootstrap source into a CREATED child via process_create. */
    movl $DW_F12_PROCESS_ARGS_SIZE, DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_ARGS
    movl $1, DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_ARGS + 4
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_TASK_GROUP, %r10
    movq (%r10), %rax
    movq %rax, DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_ARGS + 8
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_BOOTSTRAP_SOURCE, %r10
    movq (%r10), %rax
    movq %rax, DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_ARGS + 16
    movq $DW_F12_RIGHTS_PROCESS, DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_ARGS + 24
    movq $DW_F12_RIGHTS_ADDRESS_REGION, DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_ARGS + 32
    movq $DW_F12_RIGHT_READ, DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_ARGS + 40

    movl $DW_F12_SYSCALL_PROCESS_CREATE, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_ARGS, %rsi
    movl $DW_F12_PROCESS_ARGS_SIZE, %edx
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_RESULT, %rcx
    movl $DW_F12_PROCESS_RESULT_SIZE, %r8d
    xorl %r9d, %r9d
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail
    cmpl $DW_F12_PROCESS_RESULT_SIZE, DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_RESULT
    jne .Lf12_fail
    cmpl $1, DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_RESULT + 4
    jne .Lf12_fail
    cmpq $0, DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_RESULT + 8
    je .Lf12_fail
    cmpq $0, DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_RESULT + 16
    je .Lf12_fail
    cmpq $0, DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_RESULT + 24
    je .Lf12_fail

    /* The moved parent-local source is stale; child-local value is informational. */
    movl $DW_F12_SYSCALL_HANDLE_CLOSE, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_BOOTSTRAP_SOURCE, %r10
    movq (%r10), %rsi
    xorl %edx, %edx
    xorl %ecx, %ecx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    DW_F12_CALL
    cmpl $DW_F12_STATUS_BAD_HANDLE, %eax
    jne .Lf12_fail

    movl $DW_F12_SYSCALL_OBJECT_GET_INFO, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_RESULT + 8, %r10
    movq (%r10), %rsi
    movl $DW_F12_OBJECT_INFO_TASK_STATE, %edx
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_TASK_INFO, %rcx
    movl $DW_F12_TASK_INFO_SIZE, %r8d
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_INFO_REQUIRED, %r9
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail
    cmpl $DW_F12_TASK_INFO_SIZE, DW_F12_USER_DATA_ADDRESS + DW_F12_TASK_INFO
    jne .Lf12_fail
    cmpl $1, DW_F12_USER_DATA_ADDRESS + DW_F12_TASK_INFO + 4
    jne .Lf12_fail
    cmpl $DW_F12_TASK_STATE_CREATED, DW_F12_USER_DATA_ADDRESS + DW_F12_TASK_INFO + 8
    jne .Lf12_fail

    movl $DW_F12_SYSCALL_PROCESS_TERMINATE, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_RESULT + 8, %r10
    movq (%r10), %rsi
    movl $DW_F12_TERMINATION_AUTHORIZED, %edx
    xorl %ecx, %ecx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail

    movl $DW_F12_SYSCALL_OBJECT_GET_INFO, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_PROCESS_RESULT + 8, %r10
    movq (%r10), %rsi
    movl $DW_F12_OBJECT_INFO_TASK_STATE, %edx
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_TASK_INFO, %rcx
    movl $DW_F12_TASK_INFO_SIZE, %r8d
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_INFO_REQUIRED, %r9
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail
    cmpl $DW_F12_TASK_STATE_EXITED, DW_F12_USER_DATA_ADDRESS + DW_F12_TASK_INFO + 8
    jne .Lf12_fail
    cmpl $DW_F12_TERMINATION_AUTHORIZED, DW_F12_USER_DATA_ADDRESS + DW_F12_TASK_INFO + 12
    jne .Lf12_fail

    /* Role one remains blocked on sync1 and is cleaned up by this exit. */
    movl $DW_F12_SYSCALL_PROCESS_EXIT, %edi
    xorl %esi, %esi
    xorl %edx, %edx
    xorl %ecx, %ecx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    DW_F12_CALL

.Lf12_producer:
    /* A is byte-only and must be observable before B. */
    movl $DW_F12_SYSCALL_CHANNEL_SEND, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_MAIN_TX, %r10
    movq (%r10), %rsi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_MESSAGE_A, %rdx
    movl $1, %ecx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail

    /* B moves the original Event with only WAIT authority. */
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_EVENT_SOURCE, %r10
    movq (%r10), %rax
    movq %rax, DW_F12_USER_DATA_ADDRESS + DW_F12_MOVED_EVENT_SOURCE
    movq %rax, DW_F12_USER_DATA_ADDRESS + DW_F12_TRANSFER
    movq $DW_F12_RIGHT_WAIT, DW_F12_USER_DATA_ADDRESS + DW_F12_TRANSFER + 8
    movl $DW_F12_TRANSFER_MOVE, DW_F12_USER_DATA_ADDRESS + DW_F12_TRANSFER + 16

    movl $DW_F12_SYSCALL_CHANNEL_SEND, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_MAIN_TX, %r10
    movq (%r10), %rsi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_MESSAGE_B, %rdx
    movl $1, %ecx
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_TRANSFER, %r8
    movl $1, %r9d
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail

    /* The service writes sync0 then performs the only matching wake. */
    movl $DW_F12_SYSCALL_ATOMIC_WAIT32, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_SYNC0, %rsi
    xorl %edx, %edx
    movq $DW_F12_DEADLINE_INFINITE, %rcx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail

    movl $DW_F12_SYSCALL_EVENT_SIGNAL, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_EVENT_SIGNALER, %r10
    movq (%r10), %rsi
    xorl %edx, %edx
    movl $DW_F12_SIGNAL_SIGNALED, %ecx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    DW_F12_CALL
    testl %eax, %eax
    jne .Lf12_fail

    /* Terminal process exit, not a spin loop, owns this blocked Thread. */
    movl $DW_F12_SYSCALL_ATOMIC_WAIT32, %edi
    movabsq $DW_F12_USER_DATA_ADDRESS + DW_F12_SYNC1, %rsi
    xorl %edx, %edx
    movq $DW_F12_DEADLINE_INFINITE, %rcx
    xorl %r8d, %r8d
    xorl %r9d, %r9d
    DW_F12_CALL

.Lf12_fail:
    ud2
    jmp .Lf12_fail
.size _start, .-_start
