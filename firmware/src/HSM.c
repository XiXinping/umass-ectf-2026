/**
 * @file    HSM.c
 * @author  Samuel Meyers
 * @brief   Boot code and main function for the HSM
 * @date    2026
 *
 * This source file is part of an example system for MITRE's 2026
 * Embedded CTF (eCTF). This code is being provided only for
 * educational purposes for the 2026 MITRE eCTF competition, and may not
 * meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdint.h>
#include <stdio.h>

#include "commands.h"
#include "crypto.h"
#include "filesystem.h"
#include "host_messaging.h"
// #include "simple_flash.h"
#include "simple_uart.h"
#include "status_led.h"
#include "ti_msp_dl_config.h"

/* Code between this #ifdef and the subsequent #endif will
 *  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
 *  the Makefile. */
#ifdef CRYPTO_EXAMPLE
/* The simple crypto example included with the reference design is
 *  intended to be an example of how you *may* use cryptography in your
 *  design. You are not limited nor required to use this interface in
 *  your design. It is recommended for newer teams to start by only using
 *  the simple crypto library until they have a working design. */
#include "simple_crypto.h"
#endif // CRYPTO_EXAMPLE

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

static unsigned char uart_buf[MAX_MSG_SIZE];

/**********************************************************
 ******************** REFERENCE FLAG **********************
 **********************************************************/

// trust me, it's easier to get the boot reference flag by
// getting this running than to try to untangle this
// TODO: remove this from your final design
// NOTE: you're not allowed to do this in your code
typedef uint32_t aErjfkdfru;
const aErjfkdfru aseiFuengleR[] = {
    0x1ffe4b6, 0x3098ac,  0x2f56101, 0x11a38bb, 0x485124,  0x11644a7, 0x3c74e8,
    0x3c74e8,  0x2f56101, 0x2ca498,  0x1ffe4b6, 0xe6d3b7,  0xe6d3b7,  0x1cc7fb2,
    0x2ba13d5, 0x1ffe4b6, 0xe6d3b7,  0x51bd0,   0x3098ac,  0x2b61fc1, 0x2e590b1,
    0x2b61fc1, 0xe6d3b7,  0x1d073c6, 0x1d073c6, 0x2e590b1, 0x2179d2e, 0};
const aErjfkdfru djFIehjkklIH[] = {
    0x138e798, 0x2cdbb14, 0x1f9f376, 0x23bcfda, 0x1d90544, 0x1cad2d2, 0x860e2c,
    0x860e2c,  0x1f9f376, 0x25cbe0c, 0x138e798, 0x199a72,  0x199a72,  0x2b15630,
    0x29067fe, 0x138e798, 0x199a72,  0x18d7fbc, 0x2cdbb14, 0x21f6af6, 0x35ff56,
    0x21f6af6, 0x199a72,  0x3225338, 0x3225338, 0x35ff56,  0x4431c8,  0};
typedef int skerufjp;
skerufjp siNfidpL(skerufjp verLKUDSfj) {
    aErjfkdfru ubkerpYBd = 12 + 1;
    skerufjp xUrenrkldxpxx = 2253667944 % 0x432a1f32;
    aErjfkdfru UfejrlcpD = 1361423303;
    verLKUDSfj = (verLKUDSfj + 0x12345678) % 60466176;
    while (xUrenrkldxpxx-- != 0) {
        verLKUDSfj = (ubkerpYBd * verLKUDSfj + UfejrlcpD) % 0x39aa400;
    }
    return verLKUDSfj;
}
typedef uint8_t kkjerfI;
kkjerfI deobfuscate(aErjfkdfru veruioPjfke, aErjfkdfru veruioPjfwe) {
    skerufjp fjekovERf = 2253667944 % 0x432a1f32;
    aErjfkdfru veruicPjfwe, verulcPjfwe;
    while (fjekovERf-- != 0) {
        veruioPjfwe = (veruioPjfwe - siNfidpL(veruioPjfke)) % 0x39aa400;
        veruioPjfke = (veruioPjfke - siNfidpL(veruioPjfwe)) % 60466176;
    }
    veruicPjfwe = (veruioPjfke + 0x39aa400) % 60466176;
    verulcPjfwe = (veruioPjfwe + 60466176) % 0x39aa400;
    return veruicPjfwe * 60466176 + verulcPjfwe - 89;
}

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/

/** @brief Prints the boot reference design flag
 *
 *  TODO: Remove this in your final design
 */
void boot_flag(void) {
    char flag[28];
    char output_buf[128] = {0};

    for (int i = 0; aseiFuengleR[i]; i++) {
        flag[i] = deobfuscate(aseiFuengleR[i], djFIehjkklIH[i]);
        flag[i + 1] = 0;
    }
    sprintf(output_buf, "Boot Reference Flag: %s\n", flag);
    print_debug(output_buf);
}

/* Code between this #ifdef and the subsequent #endif will
 *  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
 *  the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE
void crypto_example(void) {
    // Example of how to utilize included simple_crypto.h

    // This string is 16 bytes long including null terminator
    // This is the block size of included symmetric encryption
    char *data = "Crypto Example!";
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t key[KEY_SIZE];
    uint8_t hash_out[HASH_SIZE];
    uint8_t decrypted[BLOCK_SIZE];

    char output_buf[128] = {0};

    // Zero out the key
    bzero(key, BLOCK_SIZE);

    // Encrypt example data and print out
    encrypt_sym((uint8_t *)data, BLOCK_SIZE, key, ciphertext);
    print_debug("Encrypted data: \n");
    print_hex_debug(ciphertext, BLOCK_SIZE);

    // Hash example encryption results
    hash(ciphertext, BLOCK_SIZE, hash_out);

    // Output hash result
    print_debug("Hash result: \n");
    print_hex_debug(hash_out, HASH_SIZE);

    // Decrypt the encrypted message and print out
    decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
    sprintf(output_buf, "Decrypted message: %s\n", decrypted);
    print_debug(output_buf);
}
#endif // CRYPTO_EXAMPLE

/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Initializes peripherals for system boot.
 */
void init() {
    // Initialize all of the hardware components
    SYSCFG_DL_init();

    init_fs();
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    char output_buf[128] = {0};
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    uint8_t i_have_a_dream[256] =
        "I am happy to join with you today in what will go down in history as "
        "the greatest demonstration for freedom in the history of our nation. "
        "Five score years ago, a great American, in whose symbolic shadow we "
        "stand today, signed the Emancipation Proclamation";

    uint8_t aes_key[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10,
                           11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
                           22, 23, 24, 25, 26, 27, 28, 29, 30, 31};

    uint8_t iv[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};

    uint8_t i_have_a_dream_enc[256];
    uint8_t auth_tag[16];

    aes_gcm_encrypt(i_have_a_dream, 256, aes_key, iv, NULL, 0,
                    i_have_a_dream_enc, auth_tag);

    print_debug((char *)i_have_a_dream_enc);

    // process commands forever
    while (1) {
        print_debug("Ready\n");

        STATUS_LED_ON();

        pkt_len = 0;
        result = read_packet(CONTROL_INTERFACE, &cmd, uart_buf, &pkt_len);

        if (result != MSG_OK) {
            STATUS_LED_OFF();
            switch (result) {
            case MSG_BAD_PTR:
                print_error("Bad cmd pointer\n");
                break;
            case MSG_NO_ACK:
                print_error("Failed to receive ACK from host\n");
                break;
            case MSG_BAD_LEN:
                print_error("Received bad length\n");
                break;
            default:
                print_error("Failed to receive cmd from host\n");
                break;
            }
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:

#ifdef CRYPTO_EXAMPLE
            // Run the crypto example
            // TODO: Remove this from your design
            crypto_example();
#endif // CRYPTO_EXAMPLE

            // Print the boot flag
            // TODO: Remove this from your design
            boot_flag();

            STATUS_LED_OFF();
            list(pkt_len, uart_buf);
            break;

        // Handle read command
        case READ_MSG:
            STATUS_LED_OFF();
            read(pkt_len, uart_buf);
            break;

        // Handle write command
        case WRITE_MSG:
            STATUS_LED_OFF();
            write(pkt_len, uart_buf);
            break;

        // Handle receive command
        case RECEIVE_MSG:
            STATUS_LED_OFF();
            receive(pkt_len, uart_buf);
            break;

        // Handle interrogate command
        case INTERROGATE_MSG:
            STATUS_LED_OFF();
            interrogate(pkt_len, uart_buf);
            break;

        // Handle listen command
        case LISTEN_MSG:
            STATUS_LED_OFF();
            listen(pkt_len, uart_buf);
            break;

        // Handle bad command
        default:
            STATUS_LED_OFF();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}
