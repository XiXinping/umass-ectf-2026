/* memory.x */

MEMORY
{
  BOOTLOADER (rx) : ORIGIN = 0x00000000, LENGTH = 24K

  /* 0x0000_6000 - 0x0002_7FFF: application code + rodata */
  FLASH      (rx) : ORIGIN = 0x00006000, LENGTH = 136K

  /* 0x0002_8000 - 0x0003_9FFF: 72 × 1K pages reserved for file storage */
  FILES      (r)  : ORIGIN = 0x00028000, LENGTH = 72K

  FAT        (r)  : ORIGIN = 0x0003A000, LENGTH = 1K

  APP2       (rx) : ORIGIN = 0x0003A400, LENGTH = 23K

  RAM        (rwx): ORIGIN = 0x20200000, LENGTH = 32K
}

_stack_start = ORIGIN(RAM) + LENGTH(RAM);

SECTIONS
{
  .rodata : ALIGN(4)
  {
    *(.rodata .rodata.*);
    . = ALIGN(4);
  } > APP2
}
