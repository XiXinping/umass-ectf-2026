/* memory.x */
/*flash layout 
SRAM ：32KB= 0x8000
*/


MEMORY
{
  /* 0x0000_0000 - 0x0000_5FFF: 被 Bootloader 占用 */
  BOOTLOADER (rx) : ORIGIN = 0x00000000, LENGTH = 24K

  /* 0x0000_6000 - 0x0003_9FFF: 你的主要应用程序区域 (APP1) */
  FLASH      (rx) : ORIGIN = 0x00006000, LENGTH = 208K

  /* 0x0003_A000 - 0x0003_A3FF: 文件分配表 (FAT) */
  FAT        (r)  : ORIGIN = 0x0003A000, LENGTH = 1K

  /* 0x0003_A400 - 0x0003_FFFF: 备用程序空间 (APP2) */
  APP2       (rx) : ORIGIN = 0x0003A400, LENGTH = 23K

  /* RAM 区域：根据你提供的数据 */
  RAM        (rwx): ORIGIN = 0x20200000, LENGTH = 32K
}

/* cortex-m-rt places .vector_table at the start of FLASH (0x6000) automatically */
/* _stack_start = initial SP value, first word of the vector table */
_stack_start = ORIGIN(RAM) + LENGTH(RAM);

