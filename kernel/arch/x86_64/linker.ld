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
