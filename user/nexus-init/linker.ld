OUTPUT_FORMAT(elf64-x86-64)
ENTRY(axle_user_prog_start)

SECTIONS
{
  . = 0x100000000;

  .text : ALIGN(16) {
    *(.text .text.*)
  }

  .rodata : ALIGN(16) {
    *(.rodata .rodata.*)
  }

  .data : ALIGN(16) {
    *(.data .data.*)
  }

  .bss : ALIGN(16) {
    *(.bss .bss.* COMMON)
  }
}
