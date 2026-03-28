```
cd /d/uart_firmware && echo "=== ICSR ===" && probe-rs read b32 0xE000ED04 1 --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1 && echo "=== VTOR ===" && probe-rs read b32 0xE000ED08 1 --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1

cargo objcopy --release -- -O binary firmware.bin
cd /d/uart_firmware && cargo build --release 2>&1 && probe-rs download --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 target/thumbv6m-none-eabi/release/embassy-mspm0-l2228-examples 2>&1 && probe-rs reset --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1 && sleep 2 && echo "=== ICSR ===" && probe-rs read b32 0xE000ED04 1 --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1 && echo "=== UART0 PWREN (0x40108800) ===" && probe-rs read b32 0x40108800 1 --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1 && echo "=== UART0 CTL0 (0x40109100) ===" && probe-rs read b32 0x40109100 1 --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1 && echo "=== UART0 IBRD (0x40109110) ===" && probe-rs read b32 0x40109110 2 --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1
probe-rs reset --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1 && sleep 2 && echo "=== ICSR ===" && probe-rs read b32 0xE000ED04 1 --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1 && echo "=== UART0 PWREN (0x40108800) ===" && probe-rs read b32 0x40108800 1 --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1 && echo "=== UART0 CTL0 (0x40109100) ===" && probe-rs read b32 0x40109100 1 --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1 && echo "=== UART0 IBRD (0x40109110) ===" && probe-rs read b32 0x40109110 2 --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1
cd /d/uart_firmware
cargo build --release 2>&1 
probe-rs download --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 target/thumbv6m-none-eabi/release/embassy-mspm0-l2228-examples 2>&1 
probe-rs reset --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1 
sleep 2 
&& echo "=== ICSR ===" && probe-rs read b32 0xE000ED04 1 --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1 
&& echo "=== UART0 PWREN (0x40108800) ===" && probe-rs read b32 0x40108800 1 --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1 
&& echo "=== UART0 CTL0 (0x40109100) ===" && probe-rs read b32 0x40109100 1 --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1 && echo "=== UART0 IBRD (0x40109110) ===" && probe-rs read b32 0x40109110 2 --chip MSPM0L2228 --protocol swd --probe 0451:bef3-2 2>&1

```