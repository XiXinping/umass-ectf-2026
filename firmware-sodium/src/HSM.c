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
#include <string.h>

#include "commands.h"
#include "crypto.h"
#include "filesystem.h"
#include "host_messaging.h"
#include "simple_flash.h"
#include "simple_uart.h"
#include "status_led.h"
#include "ti_msp_dl_config.h"

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

static unsigned char uart_buf[MAX_MSG_SIZE];

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

    print_debug((char *)i_have_a_dream);

    aes_gcm_encrypt(i_have_a_dream, 256, aes_key, iv, NULL, 0,
                    i_have_a_dream_enc, auth_tag);

    print_debug((char *)i_have_a_dream_enc);

    // initialize the device
    init();

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
