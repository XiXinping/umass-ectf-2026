#define WOLFSSL_USER_SETTINGS
#include "authentication.h"
#include "crypto.h"
#include "helpers.h"
#include "secrets.h"
#include "security.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
// #include "helpers.h"
#include "simple_flash.h"
#include <wolfssl/wolfcrypt/pwdbased.h>

// pin_storage_t g_pin_data;
// bool g_authenticated = false;
// uint64_t g_session_expiration_ms = 0;
// uint64_t g_last_time_ms = 0;
// timestamp_storage_t g_time_data;
// crypto_storage_t g_crypto_data;
// bool g_time_anomaly_detected = false;

// PIN Auth/Storage/Update

/*
bool timestamp_storage_valid(const timestamp_storage_t *state) {
    uint32_t checksum;

    if (state == NULL)
        return false;
    if (state->magic != TIMESTAMP_STORAGE_MAGIC)
        return false;
    if (state->max_observed_timestamp_ms < state->first_timestamp_ms)
        return false;

    checksum = simple_checksum32((const uint8_t *)state,
                                 offsetof(timestamp_storage_t, checksum));
    return checksum == state->checksum;
}


bool pin_storage_valid(const pin_storage_t *state) {
    uint32_t checksum;

    if (state == NULL)
        return false;
    if (state->magic != PIN_STORAGE_MAGIC)
        return false;
    if (state->failed_attempts > PIN_MAX_RETRIES)
        return false;
    if (state->session_active && state->session_expiration_ms == 0U)
        return false;
    if (!state->session_active && state->session_expiration_ms != 0U)
        return false;

    checksum = simple_checksum32((const uint8_t *)state,
                                 offsetof(pin_storage_t, checksum));
    return checksum == state->checksum;
}
    */
/*
security_status_t register_failed_pin_attempt(void) {
    // uint64_t now = monotonic_time_ms();
    g_pin_data.failed_attempts++;
    // g_pin_data.penalty_expiration_ms = safe_add_u64(now, PIN_FAILURE_DELAY_MS);
    g_pin_data.session_active = false;
    // g_pin_data.session_expiration_ms = 0;
    g_authenticated = false;
    // g_session_expiration_ms = 0;
    // flush_timestamp_state_if_needed();
    return SECURITY_ERR_INVALID_PIN;
}
    */
bool pin_is_lower_hex(const uint8_t *pin, size_t len) {
    size_t i;

    if (pin == NULL || len != PIN_LENGTH)
        return false;
    for (i = 0; i < len; i++) {
        uint8_t c = pin[i];
        bool is_digit = (c >= (uint8_t)'0' && c <= (uint8_t)'9');
        bool is_lower_hex_alpha = (c >= (uint8_t)'a' && c <= (uint8_t)'f');
        if (!is_digit && !is_lower_hex_alpha)
            return false;
    }
    return true;
}

/*
bool authenticate_request_pin(const uint8_t *pin, uint16_t pin_len,
                              uint8_t *err) {
    if (err == NULL)
        return false;
    if (pin == NULL || pin_len != PIN_LENGTH) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }

    security_status_t st = verify_pin(pin, PIN_LENGTH);
    if (st != SECURITY_OK) {
        *err = status_to_error_code(st);
        return false;
    }

    return true;
}
*/

/*
bool penalty_active(void) {
    if (g_time_anomaly_detected)
        return true;
    uint64_t now = monotonic_time_ms();
    return now < g_pin_data.penalty_expiration_ms;
}
    */

security_status_t verify_pin(uint8_t *pin, size_t len) {
    if (pin == NULL)
        return SECURITY_ERR_INVALID_LENGTH;
    // if (g_time_anomaly_detected)
    //    return SECURITY_ERR_TIME_ANOMALY;
    // if (security_penalty_active())
    //     return SECURITY_ERR_PENALTY_ACTIVE;
    // if (g_pin_data.failed_attempts >= PIN_MAX_RETRIES)
    //    return SECURITY_ERR_MAX_RETRIES;
    // if (!pin_is_lower_hex(pin, len))
    //    return register_failed_pin_attempt();

    uint8_t derived[PIN_HASH_SIZE];

    if (wc_PBKDF2(derived, pin, PIN_LENGTH, PIN_SALT, PIN_SALT_SIZE, 1234567,
                  sizeof(derived), WC_SHA256) != 0) {
        return SECURITY_ERR_CRYPTO_FAIL;
    }

    bool match = constant_time_compare(derived, g_pin_data.hash, PIN_HASH_SIZE);
    secure_zero(derived, sizeof(derived));

    /*
    if (!match)
        return register_failed_pin_attempt();

    g_authenticated = true;
    // g_pin_data.failed_attempts = 0;
    // g_pin_data.penalty_expiration_ms = 0;
    //g_session_expiration_ms =
    //    safe_add_u64(monotonic_time_ms(), AUTH_SESSION_TIMEOUT_MS);
    g_pin_data.session_active = true;
   // g_pin_data.session_expiration_ms = g_session_expiration_ms;
    // flush_timestamp_state_if_needed();
    return SECURITY_OK;
}

// security_status_t provision_pin(const uint8_t *pin, size_t len) {
//     if (pin == NULL)
//         return SECURITY_ERR_INVALID_LENGTH;
//     if (len != PIN_LENGTH)
//         return SECURITY_ERR_INVALID_LENGTH;
//     if (!pin_is_lower_hex(pin, len))
//         return SECURITY_ERR_INVALID_PIN;
//     if (g_time_anomaly_detected)
//         return SECURITY_ERR_TIME_ANOMALY;
//     if (trng_generate(g_pin_data.salt, PIN_SALT_SIZE) != 0)
//         return SECURITY_ERR_CRYPTO_FAIL;
//
//     if (pbkdf2_sha256(pin, len, g_pin_data.salt, PIN_SALT_SIZE,
//                       PIN_PBKDF2_ITERATIONS, g_pin_data.hash,
//                       PIN_HASH_SIZE) != 0) {
//         return SECURITY_ERR_CRYPTO_FAIL;
//     }
//
//     g_pin_data.penalty_expiration_ms = 0;
//     g_pin_data.failed_attempts = 0;
//     g_pin_data.session_active = false;
//     g_pin_data.session_expiration_ms = 0;
//     g_authenticated = false;
//     g_session_expiration_ms = 0;
//     flush_timestamp_state_if_needed();
//     return SECURITY_OK;
// }

/*

bool verify_auth(void) {
    if (g_time_anomaly_detected) {
        g_authenticated = false;
        g_session_expiration_ms = 0;
        g_pin_data.session_active = false;
        g_pin_data.session_expiration_ms = 0;
        return false;
    }
    if (!g_authenticated || !g_pin_data.session_active)
        return false;
    if (monotonic_time_ms() >= g_session_expiration_ms) {
        g_authenticated = false;
        g_session_expiration_ms = 0;
        g_pin_data.session_active = false;
        g_pin_data.session_expiration_ms = 0;
        return false;
    }
    return true;
}
    */

void logout(void) {
    g_authenticated = false;
    // g_session_expiration_ms = 0;
    g_pin_data.session_active = false;
   // g_pin_data.session_expiration_ms = 0;
}

/*
void persist_timestamp_state(void) {
    g_time_data.magic = TIMESTAMP_STORAGE_MAGIC;
    g_time_data.checksum = simple_checksum32(
        (const uint8_t *)&g_time_data, offsetof(timestamp_storage_t, checksum));
    flash_simple_erase_page(TIME_FLASH_ADDR);
    flash_simple_write(TIME_FLASH_ADDR, (uint8_t *)&g_time_data,
                       sizeof(g_time_data));
}

void load_timestamp_state(void) {
    flash_read(TIME_FLASH_ADDR, (uint8_t *)&g_time_data, sizeof(g_time_data));
}
    */

/*
bool crypto_storage_valid(const crypto_storage_t *state) {
    uint32_t checksum;
    if (state == NULL)
        return false;
    if (state->magic != CRYPTO_STORAGE_MAGIC)
        return false;

    checksum = simple_checksum32((const uint8_t *)state,
                                 offsetof(crypto_storage_t, checksum));
    return checksum == state->checksum;
}
*/

/*
void persist_crypto_state(void) {
    g_crypto_data.magic = CRYPTO_STORAGE_MAGIC;
    g_crypto_data.checksum = simple_checksum32(
        (const uint8_t *)&g_crypto_data, offsetof(crypto_storage_t, checksum));
    flash_simple_erase_page(CRYPTO_FLASH_ADDR);
    flash_simple_write(CRYPTO_FLASH_ADDR, (uint8_t *)&g_crypto_data,
                       sizeof(g_crypto_data));
}

void load_crypto_state(void) {
    flash_read(CRYPTO_FLASH_ADDR, (uint8_t *)&g_crypto_data,
               sizeof(g_crypto_data));
}
*/

/*
uint8_t status_to_error_code(security_status_t status) {
    return (uint8_t)status;
}
    */

/* 
uint64_t monotonic_time_ms(void) {
    uint64_t tolerated_now;
    uint64_t now = platform_get_time_ms();
    if (!checked_add_u64(now, TIMESTAMP_DRIFT_TOLERANCE_MS, &tolerated_now)) {
        tolerated_now = UINT64_MAX;
    }

    if (tolerated_now < g_time_data.max_observed_timestamp_ms) {
        g_time_anomaly_detected = true;
        g_authenticated = false;
        return g_last_time_ms;
    }

    if (now < g_last_time_ms) {
        g_time_anomaly_detected = true;
        g_authenticated = false;
        return g_last_time_ms;
    }

    g_last_time_ms = now;
    if (now > g_time_data.max_observed_timestamp_ms) {
        g_time_data.max_observed_timestamp_ms = now;
    }
    return now;
}
    */

/*
void flush_timestamp_state_if_needed(void) {
    if (g_time_anomaly_detected)
        return;
    if (g_time_data.max_observed_timestamp_ms <= g_time_data.first_timestamp_ms)
        return;
    persist_timestamp_state();
}
    */