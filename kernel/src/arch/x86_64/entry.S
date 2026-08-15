#ifndef DW_KERNEL_BOOT_STACK_SIZE
#error "DW_KERNEL_BOOT_STACK_SIZE must come from layout.toml"
#endif

#ifndef DW_KERNEL_BOOT_STACK_ALIGNMENT
#error "DW_KERNEL_BOOT_STACK_ALIGNMENT must come from layout.toml"
#endif

.section .text.entry,"ax",@progbits
.p2align 4
.globl _dw_kernel_entry
.type _dw_kernel_entry,@function
_dw_kernel_entry:
    /* RDI is the only incoming value consumed by the Rust entry point. */
    leaq __dw_boot_stack_top(%rip), %rsp
    andq $-16, %rsp
    cli
    cld
    xorl %ebp, %ebp
    callq dw_kernel_rust_entry

    /* The Rust boundary is no-return. Fail stopped if that is violated. */
.Lrust_entry_returned:
    cli
    hlt
    jmp .Lrust_entry_returned
.size _dw_kernel_entry, .-_dw_kernel_entry

.section .bss.boot_stack,"aw",@nobits
.balign DW_KERNEL_BOOT_STACK_ALIGNMENT
.globl __dw_boot_stack_bottom
.hidden __dw_boot_stack_bottom
__dw_boot_stack_bottom:
    .skip DW_KERNEL_BOOT_STACK_SIZE
.globl __dw_boot_stack_top
.hidden __dw_boot_stack_top
__dw_boot_stack_top:

.section .note.GNU-stack,"",@progbits
