use embassy_mspm0::gpio::{Level, Output};
use embassy_mspm0::mode::Blocking;
use embassy_mspm0::uart::{Config as UartConfig, Uart};

pub struct Platform {
    uart0: Uart<'static, Blocking>,
    uart1: Uart<'static, Blocking>,
    led: Output<'static>,
}

static mut PLATFORM: Option<Platform> = None;

pub fn init() {
    let p = embassy_mspm0::init(Default::default());

    let uart_config = UartConfig::default();
    let uart0 = Uart::new_blocking(p.UART0, p.PA11, p.PA10, uart_config).unwrap();
    let uart1 = Uart::new_blocking(p.UART1, p.PA9, p.PA8, UartConfig::default()).unwrap();

    let led = Output::new(p.PB14, Level::High);

    unsafe {
        PLATFORM = Some(Platform { uart0, uart1, led });
    }
}

pub fn status_led_on() {
    unsafe {
        if let Some(platform) = PLATFORM.as_mut() {
            platform.led.set_high();
        }
    }
}

pub fn status_led_off() {
    unsafe {
        if let Some(platform) = PLATFORM.as_mut() {
            platform.led.set_low();
        }
    }
}

pub fn uart_readbyte(uart_id: i32) -> i32 {
    let mut byte = [0u8; 1];
    unsafe {
        let result = match PLATFORM.as_mut() {
            Some(platform) => {
                if uart_id == 1 {
                    platform.uart1.blocking_read(&mut byte)
                } else {
                    platform.uart0.blocking_read(&mut byte)
                }
            }
            None => return -1,
        };

        if result.is_err() {
            -1
        } else {
            byte[0] as i32
        }
    }
}

pub fn uart_writebyte(uart_id: i32, data: u8) {
    let buf = [data];
    unsafe {
        if let Some(platform) = PLATFORM.as_mut() {
            let _ = if uart_id == 1 {
                platform.uart1.blocking_write(&buf)
            } else {
                platform.uart0.blocking_write(&buf)
            };
        }
    }
}