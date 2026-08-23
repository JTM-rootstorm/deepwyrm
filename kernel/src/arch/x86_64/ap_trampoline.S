.section .rodata.ap_trampoline_template,"a",@progbits
.balign 16
.globl __dw_ap_trampoline_template_start
.hidden __dw_ap_trampoline_template_start
__dw_ap_trampoline_template_start:
.code16
    cli
    cld
    movw %cs, %ax
    movw %ax, %ds
    xorw %ax, %ax
    movw %ax, %es
    movw %ax, %ss
    lgdtl (.Lgdt_pointer - __dw_ap_trampoline_template_start)
    movl %cr0, %eax
    orl $0x1, %eax
    movl %eax, %cr0
    ljmpl *( .Lprotected_pointer - __dw_ap_trampoline_template_start)

.code32
.globl __dw_ap_trampoline_protected_entry
.hidden __dw_ap_trampoline_protected_entry
__dw_ap_trampoline_protected_entry:
.Lprotected_entry:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    calll 1f
1:
    popl %ebx
    subl $(1b - __dw_ap_trampoline_template_start), %ebx
    movl %cr4, %eax
    orl $0x20, %eax
    movl %eax, %cr4
    movl (.Lpage_table_root - __dw_ap_trampoline_template_start)(%ebx), %eax
    movl %eax, %cr3
    movl $0xc0000080, %ecx
    rdmsr
    orl $0x00000900, %eax
    wrmsr
    movl %cr0, %eax
    orl $0x80010001, %eax
    movl %eax, %cr0
    leal (.Llong_entry - __dw_ap_trampoline_template_start)(%ebx), %eax
    pushl $0x18
    pushl %eax
    lretl

.code64
.Llong_entry:
    movw $0x10, %ax
    movw %ax, %ds
    movw %ax, %es
    movw %ax, %ss
    movq (.Lstack_top - __dw_ap_trampoline_template_start)(%rbx), %rsp
    xorq %rbp, %rbp
    movl (.Lcpu_index - __dw_ap_trampoline_template_start)(%rbx), %edi
    movl (.Llocal_apic_id - __dw_ap_trampoline_template_start)(%rbx), %esi
    movq (.Lhigher_half_entry - __dw_ap_trampoline_template_start)(%rbx), %rax
    jmp *%rax

.balign 8
.Lgdt:
.globl __dw_ap_trampoline_gdt
.hidden __dw_ap_trampoline_gdt
__dw_ap_trampoline_gdt:
    .quad 0x0000000000000000
    .quad 0x00cf9a000000ffff
    .quad 0x00cf92000000ffff
    .quad 0x00af9a000000ffff
.Lgdt_end:
.Lgdt_pointer:
    .word .Lgdt_end - .Lgdt - 1
.globl __dw_ap_trampoline_gdt_base
.hidden __dw_ap_trampoline_gdt_base
__dw_ap_trampoline_gdt_base:
    .long 0
.Lprotected_pointer:
.globl __dw_ap_trampoline_protected_pointer
.hidden __dw_ap_trampoline_protected_pointer
__dw_ap_trampoline_protected_pointer:
    .long 0
    .word 0x08
.globl __dw_ap_trampoline_page_table_root
.hidden __dw_ap_trampoline_page_table_root
.Lpage_table_root:
__dw_ap_trampoline_page_table_root:
    .long 0
.globl __dw_ap_trampoline_cpu_index
.hidden __dw_ap_trampoline_cpu_index
.Lcpu_index:
__dw_ap_trampoline_cpu_index:
    .long 0
.globl __dw_ap_trampoline_local_apic_id
.hidden __dw_ap_trampoline_local_apic_id
.Llocal_apic_id:
__dw_ap_trampoline_local_apic_id:
    .long 0
.balign 8
.globl __dw_ap_trampoline_stack_top
.hidden __dw_ap_trampoline_stack_top
.Lstack_top:
__dw_ap_trampoline_stack_top:
    .quad 0
.globl __dw_ap_trampoline_higher_half_entry
.hidden __dw_ap_trampoline_higher_half_entry
.Lhigher_half_entry:
__dw_ap_trampoline_higher_half_entry:
    .quad 0
.globl __dw_ap_trampoline_template_end
.hidden __dw_ap_trampoline_template_end
__dw_ap_trampoline_template_end:

.section .note.GNU-stack,"",@progbits
