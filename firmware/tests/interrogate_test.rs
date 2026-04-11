#![no_std]
#![no_main]

use panic_probe as _;

#[cfg(test)]
#[defmt_test::tests]
mod interrogate_test {
    use core::module_path;
    use ectf_2026::GLOBAL_PUB_KEY;
    use ectf_2026::GLOBAL_RNG;
    use ectf_2026::GLOBAL_SECRET;
    use ectf_2026::GLOBAL_SHARED_SECRETS;
    use ectf_2026::flash::HwFlash;
    use ectf_2026::host::HostUart;
    use ectf_2026::command;
    use defmt::unwrap;
    use ectf_2026::host::MsgType;
    use ectf_2026::crypto::SharedSecrets;
    use ectf_2026::permission::gen_shared_secrets;
    use ectf_2026::random::SecureRng;
    use ectf_2026::secrets::NUM_PERMS;
    use ectf_2026::secure_filesystem;
    use ectf_2026::secure_filesystem::ProtectedFile;
    use embassy_mspm0::uart::Config;
    use embassy_mspm0::uart::Uart;
    use hex_literal::hex;
    use uuid::timestamp;
    use x25519_dalek::PublicKey;
    use x25519_dalek::StaticSecret;

    struct TestContext {
        uart0: HostUart<'static>,
        transfer: HostUart<'static>,
    }

    #[init]
    fn init_uart() -> TestContext {
        let p = embassy_mspm0::init(Default::default());

        let mut config = Config::default();
        config.baudrate = 115200;

        let uart0 = unwrap!(Uart::new_blocking(p.UART0, p.PA11, p.PA10, config));
        let host = HostUart::new(uart0);

        let uart1 = unwrap!(Uart::new_blocking(p.UART1, p.PA9, p.PA8, config));
        let transfer = HostUart::new(uart1);

        TestContext {
            uart0: host,
            transfer,
        }
    }

    
    #[test]
    fn test_send_uart_listen(ctx: &mut TestContext) {
        let _ = ctx.uart0.write_packet(MsgType::Listen, &[]);
    }
    

    #[test]
    fn test_receive_cmd(ctx: &mut TestContext) {
        let read_slot: u8 = 0; // slot to read from HSM B

        let request_buf = [read_slot; 1];
        let _ = ctx.transfer.write_packet(MsgType::Receive, &request_buf);

    }

    #[test]
    fn test_receive_execute(ctx: &mut TestContext) {
        let mut buf = [0u8; command::TRANSFER_PAYLOAD_SIZE];
        let (cmd, len) = ctx.transfer
            .read_packet(&mut buf, command::TRANSFER_PAYLOAD_SIZE as u16)
            .expect("Failed to read encrypted file");

        assert_eq!(cmd, MsgType::Receive, "Expected Receive response");
        assert!(len >= command::TRANSFER_PAYLOAD_SIZE as u16, "Response too short");

        ctx.uart0.print_debug("Receive: got encrypted file");
        ctx.uart0.print_hex_debug(&buf[..len as usize]);
    }


    #[test]
    fn test_interrogate_cmd(ctx: &mut TestContext) {
        let _ = ctx.transfer.write_packet(MsgType::Interrogate, &[]);
    }

    #[test]
    fn test_interrogate(ctx: &mut TestContext) {
        let mut buf = [0u8; command::TRANSFER_PAYLOAD_SIZE];
        let (cmd, len) = ctx.transfer
            .read_packet(&mut buf, command::TRANSFER_PAYLOAD_SIZE as u16)
            .expect("Failed to read interrogation response");

        assert_eq!(cmd, MsgType::Interrogate, "Expected Interrogate response");

        ctx.uart0.print_debug("Interrogate: got file metadata");
        ctx.uart0.print_hex_debug(&buf[..len as usize]);
    }


}