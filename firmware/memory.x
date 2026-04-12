/* memory.x */
/*flash layout 
SRAM ：32KB= 0x8000
*/


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
}/* cortex-m-rt places .vector_table at the start of FLASH (0x6000) automatically */
/* _stack_start = initial SP value, first word of the vector table */
_stack_start = ORIGIN(RAM) + LENGTH(RAM);

