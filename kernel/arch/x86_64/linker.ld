OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_dw_kernel_entry)

ASSERT(DEFINED(DW_KERNEL_LINK_BASE),
       "DW_KERNEL_LINK_BASE must come from layout.toml")
ASSERT(DEFINED(DW_KERNEL_BASE_PAGE_SIZE),
       "DW_KERNEL_BASE_PAGE_SIZE must come from layout.toml")
ASSERT(DEFINED(DW_KERNEL_BOOT_STACK_SIZE),
       "DW_KERNEL_BOOT_STACK_SIZE must come from layout.toml")
ASSERT(DEFINED(DW_KERNEL_BOOT_STACK_ALIGNMENT),
       "DW_KERNEL_BOOT_STACK_ALIGNMENT must come from layout.toml")
ASSERT(DEFINED(DW_KERNEL_THREAD_STACK_COUNT),
       "DW_KERNEL_THREAD_STACK_COUNT must come from task_layout.toml")
ASSERT(DEFINED(DW_KERNEL_THREAD_STACK_SIZE),
       "DW_KERNEL_THREAD_STACK_SIZE must come from task_layout.toml")
ASSERT(DEFINED(DW_KERNEL_THREAD_STACK_GUARD_SIZE),
       "DW_KERNEL_THREAD_STACK_GUARD_SIZE must come from task_layout.toml")
ASSERT(DEFINED(DW_KERNEL_THREAD_STACK_ALIGNMENT),
       "DW_KERNEL_THREAD_STACK_ALIGNMENT must come from task_layout.toml")
ASSERT(DEFINED(DW_KERNEL_PRIVILEGE_ENTRY_STACK_COUNT),
       "DW_KERNEL_PRIVILEGE_ENTRY_STACK_COUNT must come from task_layout.toml")
ASSERT(DEFINED(DW_KERNEL_PRIVILEGE_ENTRY_STACK_SIZE),
       "DW_KERNEL_PRIVILEGE_ENTRY_STACK_SIZE must come from task_layout.toml")
ASSERT(DEFINED(DW_KERNEL_PRIVILEGE_ENTRY_STACK_GUARD_SIZE),
       "DW_KERNEL_PRIVILEGE_ENTRY_STACK_GUARD_SIZE must come from task_layout.toml")
ASSERT(DEFINED(DW_KERNEL_PRIVILEGE_ENTRY_STACK_ALIGNMENT),
       "DW_KERNEL_PRIVILEGE_ENTRY_STACK_ALIGNMENT must come from task_layout.toml")

PHDRS
{
    text PT_LOAD FLAGS(5);
    rodata PT_LOAD FLAGS(4);
    data PT_LOAD FLAGS(6);
}

SECTIONS
{
    . = DW_KERNEL_LINK_BASE;
    __dw_kernel_image_start = .;
    __dw_text_start = .;

    .text ALIGN(CONSTANT(MAXPAGESIZE)) :
    {
        KEEP(*(.text.entry))
        KEEP(*(.text.exceptions))
        *(.text .text.*)
    } :text
    __dw_text_end = .;

    __dw_rodata_start = ALIGN(CONSTANT(MAXPAGESIZE));
    .rodata ALIGN(CONSTANT(MAXPAGESIZE)) :
    {
        KEEP(*(.rodata.exceptions))
        *(.rodata .rodata.*)
        *(.data.rel.ro .data.rel.ro.*)
        *(.got .got.*)
        *(.eh_frame .eh_frame.*)
    } :rodata
    __dw_rodata_end = .;

    __dw_data_start = ALIGN(CONSTANT(MAXPAGESIZE));
    .data ALIGN(CONSTANT(MAXPAGESIZE)) :
    {
        *(.data .data.*)
        *(.sdata .sdata.*)
    } :data

    .bss ALIGN(CONSTANT(MAXPAGESIZE)) (NOLOAD) :
    {
        __dw_bss_start = .;
        *(.bss.boot_stack)

        /*
         * The three terminal IST stacks descend toward one deliberately
         * nonpresent base page each.  The loader maps the complete writable
         * PT_LOAD during transition; Deepwyrm's first owned root omits only
         * these three guard leaves.
         */
        . = ALIGN(DW_KERNEL_BASE_PAGE_SIZE);
        __dw_ist_region_start = .;

        __dw_double_fault_ist_guard = .;
        . += DW_KERNEL_BASE_PAGE_SIZE;
        __dw_double_fault_ist_bottom = .;
        . += 4 * DW_KERNEL_BASE_PAGE_SIZE;
        __dw_double_fault_ist_top = .;

        __dw_nmi_ist_guard = .;
        . += DW_KERNEL_BASE_PAGE_SIZE;
        __dw_nmi_ist_bottom = .;
        . += 4 * DW_KERNEL_BASE_PAGE_SIZE;
        __dw_nmi_ist_top = .;

        __dw_machine_check_ist_guard = .;
        . += DW_KERNEL_BASE_PAGE_SIZE;
        __dw_machine_check_ist_bottom = .;
        . += 4 * DW_KERNEL_BASE_PAGE_SIZE;
        __dw_machine_check_ist_top = .;

        __dw_ist_region_end = .;

        /*
         * E3 reserves one guard page followed by one fixed-size supervisor
         * RW/NX kernel stack for each schedulable userspace Thread. The loader
         * transition mapping covers the complete writable PT_LOAD; Deepwyrm's
         * first owned root deliberately omits each formula-derived guard leaf.
         */
        . = ALIGN(DW_KERNEL_THREAD_STACK_ALIGNMENT);
        __dw_thread_kernel_stack_region_start = .;
        . += DW_KERNEL_THREAD_STACK_COUNT *
             (DW_KERNEL_THREAD_STACK_GUARD_SIZE + DW_KERNEL_THREAD_STACK_SIZE);
        __dw_thread_kernel_stack_region_end = .;

        /* E4 BSP SYSCALL/CPL3 landing stack: one nonpresent guard + RW/NX payload. */
        . = ALIGN(DW_KERNEL_PRIVILEGE_ENTRY_STACK_ALIGNMENT);
        __dw_privilege_entry_stack_guard = .;
        . += DW_KERNEL_PRIVILEGE_ENTRY_STACK_GUARD_SIZE;
        __dw_privilege_entry_stack_bottom = .;
        . += DW_KERNEL_PRIVILEGE_ENTRY_STACK_SIZE;
        __dw_privilege_entry_stack_top = .;

        *(.bss .bss.*)
        *(.sbss .sbss.*)
        *(COMMON)
        __dw_bss_end = .;
    } :data
    __dw_data_end = .;

    __dw_kernel_image_end = .;

    /DISCARD/ :
    {
        *(.comment)
        *(.note .note.*)
    }
}

ASSERT(_dw_kernel_entry == DW_KERNEL_LINK_BASE,
       "entry must begin at the fixed kernel link base")
ASSERT((__dw_kernel_image_start & (DW_KERNEL_BASE_PAGE_SIZE - 1)) == 0,
       "kernel image must be base-page aligned")
ASSERT((__dw_boot_stack_bottom & (DW_KERNEL_BOOT_STACK_ALIGNMENT - 1)) == 0,
       "boot stack does not satisfy its required alignment")
ASSERT((__dw_boot_stack_top - __dw_boot_stack_bottom) == DW_KERNEL_BOOT_STACK_SIZE,
       "boot stack size does not match layout.toml")
ASSERT((__dw_ist_region_start & (DW_KERNEL_BASE_PAGE_SIZE - 1)) == 0,
       "IST region must be base-page aligned")
ASSERT((__dw_double_fault_ist_bottom - __dw_double_fault_ist_guard) == DW_KERNEL_BASE_PAGE_SIZE,
       "double-fault IST guard must be exactly one page")
ASSERT((__dw_double_fault_ist_top - __dw_double_fault_ist_bottom) == 4 * DW_KERNEL_BASE_PAGE_SIZE,
       "double-fault IST usable stack must be exactly 16 KiB")
ASSERT(__dw_double_fault_ist_top == __dw_nmi_ist_guard,
       "double-fault and NMI IST ranges must be contiguous and disjoint")
ASSERT((__dw_nmi_ist_bottom - __dw_nmi_ist_guard) == DW_KERNEL_BASE_PAGE_SIZE,
       "NMI IST guard must be exactly one page")
ASSERT((__dw_nmi_ist_top - __dw_nmi_ist_bottom) == 4 * DW_KERNEL_BASE_PAGE_SIZE,
       "NMI IST usable stack must be exactly 16 KiB")
ASSERT(__dw_nmi_ist_top == __dw_machine_check_ist_guard,
       "NMI and machine-check IST ranges must be contiguous and disjoint")
ASSERT((__dw_machine_check_ist_bottom - __dw_machine_check_ist_guard) == DW_KERNEL_BASE_PAGE_SIZE,
       "machine-check IST guard must be exactly one page")
ASSERT((__dw_machine_check_ist_top - __dw_machine_check_ist_bottom) == 4 * DW_KERNEL_BASE_PAGE_SIZE,
       "machine-check IST usable stack must be exactly 16 KiB")
ASSERT((__dw_ist_region_end - __dw_ist_region_start) == 15 * DW_KERNEL_BASE_PAGE_SIZE,
       "IST region must contain exactly three guards and three four-page stacks")

ASSERT((__dw_thread_kernel_stack_region_start & (DW_KERNEL_THREAD_STACK_ALIGNMENT - 1)) == 0,
       "thread kernel-stack region must satisfy its configured alignment")
ASSERT(DW_KERNEL_THREAD_STACK_COUNT == 16,
       "DW0-E3 thread kernel-stack count must remain 16")
ASSERT(DW_KERNEL_THREAD_STACK_SIZE == 65536,
       "DW0-E3 thread kernel-stack size must remain 64 KiB")
ASSERT(DW_KERNEL_THREAD_STACK_GUARD_SIZE == DW_KERNEL_BASE_PAGE_SIZE,
       "each E3 thread kernel stack must have exactly one base-page guard")
ASSERT(DW_KERNEL_THREAD_STACK_ALIGNMENT == DW_KERNEL_BASE_PAGE_SIZE,
       "E3 thread kernel-stack alignment must equal the base page size")
ASSERT((__dw_thread_kernel_stack_region_end - __dw_thread_kernel_stack_region_start) ==
       DW_KERNEL_THREAD_STACK_COUNT *
       (DW_KERNEL_THREAD_STACK_GUARD_SIZE + DW_KERNEL_THREAD_STACK_SIZE),
       "E3 thread kernel-stack arena geometry does not match task_layout.toml")

ASSERT(DW_KERNEL_PRIVILEGE_ENTRY_STACK_COUNT == 1,
       "DW0-E4 BSP privilege-entry stack count must remain one")
ASSERT(DW_KERNEL_PRIVILEGE_ENTRY_STACK_SIZE == 16384,
       "DW0-E4 BSP privilege-entry stack must remain 16 KiB")
ASSERT(DW_KERNEL_PRIVILEGE_ENTRY_STACK_GUARD_SIZE == DW_KERNEL_BASE_PAGE_SIZE,
       "DW0-E4 privilege-entry stack must have one base-page guard")
ASSERT(DW_KERNEL_PRIVILEGE_ENTRY_STACK_ALIGNMENT == DW_KERNEL_BASE_PAGE_SIZE,
       "DW0-E4 privilege-entry stack alignment must remain one base page")
ASSERT((__dw_privilege_entry_stack_bottom - __dw_privilege_entry_stack_guard) ==
       DW_KERNEL_PRIVILEGE_ENTRY_STACK_GUARD_SIZE,
       "privilege-entry guard geometry drifted")
ASSERT((__dw_privilege_entry_stack_top - __dw_privilege_entry_stack_bottom) ==
       DW_KERNEL_PRIVILEGE_ENTRY_STACK_SIZE,
       "privilege-entry stack extent drifted")
