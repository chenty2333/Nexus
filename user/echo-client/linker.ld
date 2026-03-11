OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(axle_user_prog_start)

PHDRS {
  text PT_LOAD FLAGS(0x7);
}

SECTIONS {
  . = 0x0000000100000000;

  .text : ALIGN(16) {
    *(.text .text.*)
  } :text

  .rodata : ALIGN(16) {
    *(.rodata .rodata.*)
  } :text

  .data : ALIGN(16) {
    *(.data .data.*)
  } :text

  .bss : ALIGN(16) {
    *(.bss .bss.*)
    *(COMMON)
  } :text

  /DISCARD/ : {
    *(.eh_frame .eh_frame_hdr)
    *(.note .note.*)
    *(.comment)
    *(.gnu*)
  }
}
