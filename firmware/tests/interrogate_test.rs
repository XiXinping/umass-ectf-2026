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
    use ectf_2026::permission::SharedSecrets;
    use ectf_2026::permission::gen_shared_secrets;
    use ectf_2026::random::SecureRng;
    use ectf_2026::secrets::NUM_PERMS;
    use ectf_2026::secure_filesystem;
    use ectf_2026::secure_filesystem::ProtectedFile;
    use embassy_mspm0::uart::Config;
    use embassy_mspm0::uart::Uart;
    use hex_literal::hex;
    use x25519_dalek::PublicKey;
    use x25519_dalek::StaticSecret;

    struct TestContext<'a> {
        uart0: HostUart<'a>,
        transfer: HostUart<'a>,
    }
    #[init] 
    fn init_uart() -> TestContext<'static> {
        let p = embassy_mspm0::init(Default::default());

        let mut config = Config::default();
        config.baudrate = 115200;
        
        let uart0: Uart<'_, embassy_mspm0::mode::Blocking> = unwrap!(Uart::new_blocking(p.UART0, p.PA11, p.PA10, config));
        let mut host: HostUart<'_> = HostUart::new(uart0);

        let uart1: Uart<'_, embassy_mspm0::mode::Blocking> = unwrap!(Uart::new_blocking(p.UART1, p.PA9, p.PA8, config));
        let mut transfer: HostUart<'_> = HostUart::new(uart1);

        TestContext {
            uart0: host,
            transfer,
        }
    }
    #[test]
    fn test_send_uart() {
        let p = embassy_mspm0::init(Default::default());

        let mut config = Config::default();
        config.baudrate = 115200;

        // UART0 — host/control interface
        let uart0 = unwrap!(Uart::new_blocking(p.UART0, p.PA11, p.PA10, config));
        let mut host = HostUart::new(uart0);

        let uart1 = unwrap!(Uart::new_blocking(p.UART1, p.PA9, p.PA8, config));
        let mut transfer = HostUart::new(uart1);

        let mut request_buf = [0u8; 1];
        request_buf[0] = read_slot;
        let _ = host.write_packet(MsgType::Listen, &[]);
    }

    #[test]
    fn test_receive() {

        let p = embassy_mspm0::init(Default::default());

        let mut config = Config::default();
        config.baudrate = 115200;

        // UART0 — host/control interface
        let uart0 = unwrap!(Uart::new_blocking(p.UART0, p.PA11, p.PA10, config));
        let mut host = HostUart::new(uart0);

        let uart1 = unwrap!(Uart::new_blocking(p.UART1, p.PA9, p.PA8, config));
        let mut transfer = HostUart::new(uart1);

        let mut buf: [u8; command::TRANSFER_PAYLOAD_SIZE] = [0u8; command::TRANSFER_PAYLOAD_SIZE];

        let mut rng = SecureRng::new().expect("RNG init failed");
        let secret = StaticSecret::random_from_rng(&mut rng);
        let pub_key = PublicKey::from(&secret);
        let shared_secrets: [SharedSecrets; NUM_PERMS] = gen_shared_secrets(secret.clone());

        critical_section::with(|cs: critical_section::CriticalSection<'_>| {
            *GLOBAL_RNG.borrow(cs).borrow_mut() = Some(rng);
            *GLOBAL_SECRET.borrow(cs).borrow_mut() = Some(secret.clone());
            *GLOBAL_PUB_KEY.borrow(cs).borrow_mut() = Some(pub_key);
            *GLOBAL_SHARED_SECRETS.borrow(cs).borrow_mut() = Some(shared_secrets);
        });

        let group_id: u16 = 0xbeef;
        const FILE_UUID: [u8; 16] = hex!("67e5504410b1426f9247bb680e5fe0c8");
        let mut file_name = [0u8; 32];

        let input_name = "top_secret.bin";
        let name_bytes = input_name.as_bytes();

        file_name[..name_bytes.len()].copy_from_slice(name_bytes);

        let super_secret_data = b"This is secret data";
        let mut plaintext = [0u8; 8192];
        plaintext[..super_secret_data.len()].copy_from_slice(super_secret_data);

        let mut file = ProtectedFile::default();
        secure_filesystem::ProtectedFile::create_in(
            &mut file, group_id, FILE_UUID, &file_name, &plaintext,
        )
        .expect("Failed to create protected file");

        let mut hw_flash: HwFlash = HwFlash;
        let mut fs = secure_filesystem::Filesystem::init(&hw_flash);

        fs.write_file(0, &file, FILE_UUID, &mut hw_flash)
            .expect("Failed to write to slot!");

        fs.write_file(1, &file, FILE_UUID, &mut hw_flash)
            .expect("Failed to write to slot!");

        fs.write_file(0, &file, FILE_UUID, &mut hw_flash)
            .expect("Failed to write to slot!");

        fs.write_file(1, &file, FILE_UUID, &mut hw_flash)
            .expect("Failed to write to slot!");


        match host.read_packet(&mut buf, command::TRANSFER_PAYLOAD_SIZE as u16) {
            Ok((msg_type, len)) => {
                host.print_debug("Got cmd:");
                host.print_hex_debug(&[msg_type as u8]);
                command::handle_command(
                    &mut host,
                    &mut transfer,
                    msg_type,
                    len,
                    &mut buf,
                    &mut hw_flash,
                    &mut fs,
                );
            }
            Err(_) => {
                host.print_error("read failed");
            }
        }

    }

    #[test]
    fn test_interrogate() {

        let p = embassy_mspm0::init(Default::default());

        let mut config = Config::default();
        config.baudrate = 115200;

        // UART0 — host/control interface
        let uart0 = unwrap!(Uart::new_blocking(p.UART0, p.PA11, p.PA10, config));
        let mut host = HostUart::new(uart0);

        let uart1 = unwrap!(Uart::new_blocking(p.UART1, p.PA9, p.PA8, config));
        let mut transfer = HostUart::new(uart1);

        let mut buf: [u8; command::TRANSFER_PAYLOAD_SIZE] = [0u8; command::TRANSFER_PAYLOAD_SIZE];

        let mut rng = SecureRng::new().expect("RNG init failed");
        let secret = StaticSecret::random_from_rng(&mut rng);
        let pub_key = PublicKey::from(&secret);
        let shared_secrets: [SharedSecrets; NUM_PERMS] = gen_shared_secrets(secret.clone());

        critical_section::with(|cs: critical_section::CriticalSection<'_>| {
            *GLOBAL_RNG.borrow(cs).borrow_mut() = Some(rng);
            *GLOBAL_SECRET.borrow(cs).borrow_mut() = Some(secret.clone());
            *GLOBAL_PUB_KEY.borrow(cs).borrow_mut() = Some(pub_key);
            *GLOBAL_SHARED_SECRETS.borrow(cs).borrow_mut() = Some(shared_secrets);
        });

        let group_id: u16 = 0xbeef;
        const FILE_UUID: [u8; 16] = hex!("67e5504410b1426f9247bb680e5fe0c8");
        let mut file_name = [0u8; 32];

        let input_name = "top_secret.bin";
        let name_bytes = input_name.as_bytes();

        file_name[..name_bytes.len()].copy_from_slice(name_bytes);

        let super_secret_data = b"This is secret data";
        let mut plaintext = [0u8; 8192];
        plaintext[..super_secret_data.len()].copy_from_slice(super_secret_data);

        let mut file = ProtectedFile::default();
        secure_filesystem::ProtectedFile::create_in(
            &mut file, group_id, FILE_UUID, &file_name, &plaintext,
        )
        .expect("Failed to create protected file");

        let mut hw_flash: HwFlash = HwFlash;
        let mut fs = secure_filesystem::Filesystem::init(&hw_flash);

        fs.write_file(0, &file, FILE_UUID, &mut hw_flash)
            .expect("Failed to write to slot!");

        fs.write_file(1, &file, FILE_UUID, &mut hw_flash)
            .expect("Failed to write to slot!");

        fs.write_file(0, &file, FILE_UUID, &mut hw_flash)
            .expect("Failed to write to slot!");

        fs.write_file(1, &file, FILE_UUID, &mut hw_flash)
            .expect("Failed to write to slot!");


        match host.read_packet(&mut buf, command::TRANSFER_PAYLOAD_SIZE as u16) {
            Ok((msg_type, len)) => {
                host.print_debug("Got cmd:");
                host.print_hex_debug(&[msg_type as u8]);
                command::handle_command(
                    &mut host,
                    &mut transfer,
                    msg_type,
                    len,
                    &mut buf,
                    &mut hw_flash,
                    &mut fs,
                );
            }
            Err(_) => {
                host.print_error("read failed");
            }
        }

    }


}