ENTRY(_start);

SECTIONS
{
    . = ALIGN(16);
    .text :
    {
        *(.text.prologue)
        *(.text)
        *(.rodata)
    }
    .data :
    {
        *(.data)
    }

    /* Emit a 32-bit word containing (task_entry_fn - _start) */
    /* Make it a const so it does not have got and this stuff... */
    .const : ALIGN(4) {
        PROVIDE_HIDDEN(__task_entry_off = .);
        LONG(task_entry_fn - _start);
    }

    /DISCARD/ :
    {
        *(.interp)
        *(.comment)
        *(.got)
        *(.got.plt)
        *(.ARM.attributes)
    }
}
