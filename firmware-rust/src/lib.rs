#![no_std]

mod bindings;
mod commands;
mod filesystem;
mod host_messaging;
mod platform;
mod protocol;
mod security;

use host_messaging::{print_debug, print_error, read_packet, MsgStatus};
use platform::{init as platform_init, status_led_off, status_led_on};
use protocol::{MsgType, MAX_MSG_SIZE};

static mut UART_BUF: [u8; MAX_MSG_SIZE] = [0; MAX_MSG_SIZE];

#[no_mangle]
pub extern "C" fn main() -> i32 {
    platform_init();
    filesystem::init();

    loop {
        let _ = print_debug(b"Ready\n");
        status_led_on();

        let mut cmd = MsgType::Error;
        let mut pkt_len: u16 = 0;

        let result = unsafe { read_packet(0, &mut cmd, core::ptr::addr_of_mut!(UART_BUF) as *mut u8, &mut pkt_len) };
        if result != MsgStatus::Ok {
            status_led_off();
            match result {
                MsgStatus::BadPtr => {
                    let _ = print_error(b"Bad cmd pointer\n");
                }
                MsgStatus::NoAck => {
                    let _ = print_error(b"Failed to receive ACK from host\n");
                }
                MsgStatus::BadLen => {
                    let _ = print_error(b"Received bad length\n");
                }
                _ => {
                    let _ = print_error(b"Failed to receive cmd from host\n");
                }
            }
            continue;
        }

        status_led_off();

        let data = unsafe { &UART_BUF[..pkt_len as usize] };

        match cmd {
            MsgType::List => {
                let _ = commands::list(data);
            }
            MsgType::Read => {
                let _ = commands::read(data);
            }
            MsgType::Write => {
                let _ = commands::write(data);
            }
            MsgType::Receive => {
                let _ = commands::receive(data);
            }
            MsgType::Interrogate => {
                let _ = commands::interrogate(data);
            }
            MsgType::Listen => {
                let _ = commands::listen();
            }
            _ => {
                let _ = print_error(b"Invalid Command\n");
            }
        }
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
