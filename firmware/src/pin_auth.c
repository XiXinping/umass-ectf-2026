#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include "pin_auth.h"
#include "security.h"



static pin_storage_t g_pin_data;
static bool g_authenticated = false;
static uint64_t g_session_expiration_ms = 0;
static uint64_t g_last_time_ms = 0;
static timestamp_storage_t g_time_data;
static bool g_time_anomaly_detected = false;


// PIN Auth/Storage/Update

static bool pin_storage_valid(const pin_storage_t *state) {
    uint32_t checksum;

    if (state == NULL) return false;
    if (state->magic != PIN_STORAGE_MAGIC) return false;
    if (state->failed_attempts > PIN_MAX_RETRIES) return false;
    if (state->session_active && state->session_expiration_ms == 0U) return false;
    if (!state->session_active && state->session_expiration_ms != 0U) return false;

    checksum = simple_checksum32((const uint8_t*)state,
                                 offsetof(struct pin_storage_t, checksum));
    return checksum == state->checksum;
}


static security_status_t register_failed_pin_attempt(void) {
    uint64_t now = monotonic_time_ms();
    g_pin_data.failed_attempts++;
    g_pin_data.penalty_expiration_ms = safe_add_u64(now, PIN_FAILURE_DELAY_MS);
    g_pin_data.session_active = false;
    g_pin_data.session_expiration_ms = 0;
    g_authenticated = false;
    g_session_expiration_ms = 0;
    flush_timestamp_state_if_needed();
    persist_pin();
    return SECURITY_ERR_INVALID_PIN;
}

static bool pin_is_lower_hex(const uint8_t *pin, size_t len) {
    size_t i;

    if (pin == NULL || len != PIN_LENGTH) return false;
    for (i = 0; i < len; i++) {
        uint8_t c = pin[i];
        bool is_digit = (c >= (uint8_t)'0' && c <= (uint8_t)'9');
        bool is_lower_hex_alpha = (c >= (uint8_t)'a' && c <= (uint8_t)'f');
        if (!is_digit && !is_lower_hex_alpha) return false;
    }
    return true;
}

static bool authenticate_request_pin(const uint8_t *body, uint16_t body_len, uint8_t *err) {
    if (err == NULL) return false;
    if (body == NULL || body_len < PIN_LENGTH) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }

    security_status_t st = security_verify_pin(body, PIN_LENGTH);
    if (st != SECURITY_OK) {
        *err = status_to_error_code(st);
        return false;
    }

    return true;
}


/* -------------------- Penalty -------------------- */


bool security_penalty_active(void) {
    if (g_time_anomaly_detected) return true;
    uint64_t now = monotonic_time_ms();
    return now < g_pin_data.penalty_expiration_ms;
}


/* -------------------- PIN Verification -------------------- */

security_status_t security_verify_pin(const uint8_t *pin, size_t len) {
    if (pin == NULL) return SECURITY_ERR_INVALID_LENGTH;
    if (len != PIN_LENGTH) return SECURITY_ERR_INVALID_LENGTH;
    if (g_time_anomaly_detected) return SECURITY_ERR_TIME_ANOMALY;
    if (security_penalty_active()) return SECURITY_ERR_PENALTY_ACTIVE;
    if (g_pin_data.failed_attempts >= PIN_MAX_RETRIES) return SECURITY_ERR_MAX_RETRIES;
    if (!pin_is_lower_hex(pin, len)) return register_failed_pin_attempt();

    uint8_t derived[PIN_HASH_SIZE];
    if (pbkdf2_sha256(pin, len, g_pin_data.salt, PIN_SALT_SIZE,
                      PIN_PBKDF2_ITERATIONS, derived, PIN_HASH_SIZE) != 0) {
        return SECURITY_ERR_CRYPTO_FAIL;
    }

    bool match = constant_time_compare(derived, g_pin_data.hash, PIN_HASH_SIZE);
    secure_zero(derived, sizeof(derived));

    if (!match) return register_failed_pin_attempt();

    g_authenticated = true;
    g_pin_data.failed_attempts = 0;
    g_pin_data.penalty_expiration_ms = 0;
    g_session_expiration_ms = safe_add_u64(monotonic_time_ms(), AUTH_SESSION_TIMEOUT_MS);
    g_pin_data.session_active = true;
    g_pin_data.session_expiration_ms = g_session_expiration_ms;
    flush_timestamp_state_if_needed();
    persist_pin();
    return SECURITY_OK;
}

security_status_t security_provision_pin(const uint8_t *pin, size_t len) {
    if (pin == NULL) return SECURITY_ERR_INVALID_LENGTH;
    if (len != PIN_LENGTH) return SECURITY_ERR_INVALID_LENGTH;
    if (!pin_is_lower_hex(pin, len)) return SECURITY_ERR_INVALID_PIN;
    if (g_time_anomaly_detected) return SECURITY_ERR_TIME_ANOMALY;
    if (trng_generate(g_pin_data.salt, PIN_SALT_SIZE) != 0) return SECURITY_ERR_CRYPTO_FAIL;

    if (pbkdf2_sha256(pin, len, g_pin_data.salt, PIN_SALT_SIZE,
                      PIN_PBKDF2_ITERATIONS, g_pin_data.hash, PIN_HASH_SIZE) != 0) {
        return SECURITY_ERR_CRYPTO_FAIL;
    }

    g_pin_data.penalty_expiration_ms = 0;
    g_pin_data.failed_attempts = 0;
    g_pin_data.session_active = false;
    g_pin_data.session_expiration_ms = 0;
    g_authenticated = false;
    g_session_expiration_ms = 0;
    flush_timestamp_state_if_needed();
    persist_pin();
    return SECURITY_OK;
}

bool security_is_authenticated(void) {
    if (g_time_anomaly_detected) {
        g_authenticated = false;
        g_session_expiration_ms = 0;
        g_pin_data.session_active = false;
        g_pin_data.session_expiration_ms = 0;
        persist_pin();
        return false;
    }
    if (!g_authenticated || !g_pin_data.session_active) return false;
    if (monotonic_time_ms() >= g_session_expiration_ms) {
        g_authenticated = false;
        g_session_expiration_ms = 0;
        g_pin_data.session_active = false;
        g_pin_data.session_expiration_ms = 0;
        persist_pin();
        return false;
    }
    return true;
}

void security_logout(void) {
    g_authenticated = false;
    g_session_expiration_ms = 0;
    g_pin_data.session_active = false;
    g_pin_data.session_expiration_ms = 0;
    persist_pin();
}
