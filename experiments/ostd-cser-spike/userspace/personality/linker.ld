ENTRY(_start)

SECTIONS
{
    . = 0x00400000;
    .text : ALIGN(16) { *(.text .text.*) }

    /DISCARD/ :
    {
        *(.comment)
        *(.eh_frame .eh_frame_hdr)
        *(.note .note.*)
    }
}
