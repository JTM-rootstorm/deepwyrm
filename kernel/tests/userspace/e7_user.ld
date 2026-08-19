OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

PHDRS
{
    text PT_LOAD FLAGS(5);
}

SECTIONS
{
    . = 0x0000000040000000;
    .text : ALIGN(16)
    {
        KEEP(*(.text.deepwyrm_test_e7_user))
    } :text

    /DISCARD/ :
    {
        *(.comment)
        *(.note .note.*)
        *(.eh_frame .eh_frame.*)
        *(.data .data.*)
        *(.bss .bss.*)
    }
}

ASSERT(SIZEOF(.text) > 0, "E7 userspace text must not be empty")
ASSERT(SIZEOF(.text) <= 4096, "E7 userspace text must fit one base page")
