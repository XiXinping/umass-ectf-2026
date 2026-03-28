#![no_std]
#![no_main]



#[path = "../filesystem.rs"]
mod filesystem;
#[path = "../flash.rs"]
mod flash;

use defmt::*;
use {defmt_rtt as _, panic_probe as _};

#[cortex_m_rt::exception]
unsafe fn NonMaskableInt() {
    const SYSCTL_NMIICLR: *mut u32 = 0x400B_0078 as *mut u32;
    unsafe { core::ptr::write_volatile(SYSCTL_NMIICLR, 0x7F) };
}

unsafe fn set_vtor(addr: u32) {
    const VTOR: *mut u32 = 0xE000_ED08 as *mut u32;
    unsafe { core::ptr::write_volatile(VTOR, addr) };
}

fn fs_error_code(err: filesystem::FsError) -> u8 {
    match err {
        filesystem::FsError::InvalidSlot => 1,
        filesystem::FsError::NameTooLong => 2,
        filesystem::FsError::ContentsTooLarge => 3,
        filesystem::FsError::InvalidFatEntry => 4,
        filesystem::FsError::FlashWriteError => 5,
    }
}

#[cortex_m_rt::entry]
fn main() -> ! {
    unsafe { set_vtor(0x0000_6000) };
    info!("read_file_test boot");
    let _p = embassy_mspm0::init(Default::default());

    let mut hw_flash = flash::HwFlash;
    let mut fs = filesystem::Filesystem::empty();

    let name = b"rf_test";
    let test_contents = b"read_file smoke test";
    let uuid = [0xCD; filesystem::UUID_SIZE];
    let slot = 1u8;

    // Step 1: Create and write a test file to flash
    info!("Step 1: Creating test file");
    let file = match filesystem::Filesystem::create_file(2, name, test_contents) {
        Ok(file) => file,
        Err(err) => {
            error!("create_file failed, code={}", fs_error_code(err));
            loop {
                cortex_m::asm::wfi();
            }
        }
    };

    info!("Step 2: Writing test file to flash");
    
    // Debug: print file structure BEFORE writing
    info!("File before write:");
    info!("  in_use: 0x{:X}", file.in_use);
    info!("  group_id: {}", file.group_id);
    info!("  name[0..8]: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
        file.name[0], file.name[1], file.name[2], file.name[3],
        file.name[4], file.name[5], file.name[6], file.name[7]);
    info!("  contents_len: {}", file.contents_len);
    
    match fs.write_file(slot, &file, &uuid, &mut hw_flash) {
        Ok(()) => {
            info!("write_file succeeded");
        }
        Err(err) => {
            error!("write_file failed, code={}", fs_error_code(err));
            loop {
                cortex_m::asm::wfi();
            }
        }
    }
    // DEBUG: Print FAT metadata after write
    let entry = fs.get_file_metadata(slot).unwrap();
    info!("FAT entry after write:");
    info!("  flash_addr: 0x{:X}", entry.flash_addr);
    info!("  length: {}", entry.length);
   
    // DEBUG: Dump raw flash bytes directly
let entry = fs.get_file_metadata(slot).unwrap();

info!("FAT entry after write:");
info!("  flash_addr: 0x{:08X}", entry.flash_addr);
info!("  length: {}", entry.length);

// 读取原始 flash 前 64 字节
let mut raw_buf = [0u8; 64];

// 强制使用 Flash trait 的 read 方法（避免调用错函数）
filesystem::Flash::read(&hw_flash, entry.flash_addr, &mut raw_buf);

info!("Raw flash data (first 48 bytes):");

// 打印 0..16
info!(
    "  [00..16]: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} \
{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
    raw_buf[0], raw_buf[1], raw_buf[2], raw_buf[3],
    raw_buf[4], raw_buf[5], raw_buf[6], raw_buf[7],
    raw_buf[8], raw_buf[9], raw_buf[10], raw_buf[11],
    raw_buf[12], raw_buf[13], raw_buf[14], raw_buf[15],
);

// 打印 16..32
info!(
    "  [16..32]: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} \
{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
    raw_buf[16], raw_buf[17], raw_buf[18], raw_buf[19],
    raw_buf[20], raw_buf[21], raw_buf[22], raw_buf[23],
    raw_buf[24], raw_buf[25], raw_buf[26], raw_buf[27],
    raw_buf[28], raw_buf[29], raw_buf[30], raw_buf[31],
);

// 打印 32..48
info!(
    "  [32..48]: {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} \
{:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X} {:02X}",
    raw_buf[32], raw_buf[33], raw_buf[34], raw_buf[35],
    raw_buf[36], raw_buf[37], raw_buf[38], raw_buf[39],
    raw_buf[40], raw_buf[41], raw_buf[42], raw_buf[43],
    raw_buf[44], raw_buf[45], raw_buf[46], raw_buf[47],
);
    // Step 2: Read the file back from flash
    info!("Step 3: Reading test file from flash");
    let mut read_file = filesystem::File::default();
    match fs.read_file(slot, &mut read_file, &hw_flash) {
        Ok(()) => {
            info!("read_file succeeded");
        }
        Err(err) => {
            error!("read_file failed, code={}", fs_error_code(err));
            loop {
                cortex_m::asm::wfi();
            }
        }
    }

    // Step 3: Verify the read file matches the written file
    info!("Step 4: Verifying file contents");

    // Check in_use flag
    if read_file.in_use != filesystem::FILE_IN_USE {
        error!("in_use flag mismatch: expected 0x{:X}, got 0x{:X}", 
            filesystem::FILE_IN_USE, read_file.in_use);
        loop {
            cortex_m::asm::wfi();
        }
    }
    info!("in_use flag: OK");

    // Check group_id
    if read_file.group_id != 2 {
        error!("group_id mismatch: expected 2, got {}", read_file.group_id);
        loop {
            cortex_m::asm::wfi();
        }
    }
    info!("group_id: OK");

    // Check name
    let read_name_len = read_file.name.iter().position(|&b| b == 0).unwrap_or(read_file.name.len());
    info!("Expected name length: {}, read name length: {}", name.len(), read_name_len);
    
    // Print the actual characters
    info!("Expected name: {:?}", name);
    info!("Read name chars:");
    for i in 0..8 {
        info!("  [{}] = 0x{:02X}", i, read_file.name[i]);
    }
    
    if read_name_len != name.len() {
        error!("name length mismatch: expected {}, got {}", name.len(), read_name_len);
        loop {
            cortex_m::asm::wfi();
        }
    }
    
    if &read_file.name[..read_name_len] != name {
        error!("name content mismatch");
        loop {
            cortex_m::asm::wfi();
        }
    }
    info!("name: OK");

    // Check contents_len
    if read_file.contents_len != test_contents.len() as u16 {
        error!("contents_len mismatch: expected {}, got {}", 
            test_contents.len(), read_file.contents_len);
        loop {
            cortex_m::asm::wfi();
        }
    }
    info!("contents_len: OK");

    // Check contents
    if &read_file.contents[..test_contents.len()] != test_contents {
        error!("contents mismatch");
        loop {
            cortex_m::asm::wfi();
        }
    }
    info!("contents: OK");

    // All checks passed
    info!("read_file_test PASSED - all verification checks succeeded");

    loop {
        cortex_m::asm::wfi();
    }
}