#include "security.h"
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define PIN_LENGTH 6
#define PIN_SALT_SIZE 16
#define PIN_HASH_SIZE 32
#define PIN_PBKDF2_ITERATIONS 10000
#define PIN_FAILURE_DELAY_MS 5000
#define PIN_MAX_RETRIES 5
#define AUTH_SESSION_TIMEOUT_MS 5000  // 5 seconds
#define PIN_STORAGE_MAGIC 0x50494E53U /* PINS */

/* Keep PIN authentication scoped to one host command by default. */
#ifndef SECURITY_REQUIRE_PIN_EACH_COMMAND
#define SECURITY_REQUIRE_PIN_EACH_COMMAND 1
#endif

/*
 * Flash regions intended for protected storage.
 * Platform should map these ranges to the most restrictive policy available.
 */
#define SECURITY_FLASH_REGION_TIME_ADDR 0x00002000U
#define SECURITY_FLASH_REGION_CRYPTO_ADDR 0x00003000U

/*
 * Optional platform hooks to lock/check clock config after boot.
 * Override these macros with platform-specific implementations.
 */
#ifndef SECURITY_LOCK_CLOCK_CONFIG
#define SECURITY_LOCK_CLOCK_CONFIG() true
#endif

#ifndef SECURITY_IS_CLOCK_CONFIG_LOCKED
#define SECURITY_IS_CLOCK_CONFIG_LOCKED() true
#endif

typedef struct {
    uint32_t magic;
    uint8_t salt[PIN_SALT_SIZE];
    uint8_t hash[PIN_HASH_SIZE];
    uint64_t penalty_expiration_ms;
    uint8_t failed_attempts;
    bool session_active;
    uint8_t reserved[6];
    uint64_t session_expiration_ms;
    uint32_t checksum;
} pin_storage_t;

typedef struct {
    uint32_t magic;
    uint64_t first_timestamp_ms;        // First seen timestamp?
    uint64_t max_observed_timestamp_ms; // Is this tracker for largest timestamp
                                        // seen or largest delta seen?
    uint32_t checksum; // Good idea, although have to ensure that this is not
                       // tampered with
} timestamp_storage_t;

/* Load the PIN from persistent storage */
static void load_pin();

extern uint64_t platform_get_time_ms(void);
/* Load the timestamp state from persistent storage */
static void load_timestamp_state(void);

static void load_crypto_state(void);

/* Provision a new PIN (salt + PBKDF2 hash) */
security_status_t provision_pin(const uint8_t *pin, size_t len);

/* Verify a PIN for protected actions; returns error codes, enforces penalty &
 * max retries */
security_status_t verify_pin(const uint8_t *pin, size_t len);

/* Check if current session is authenticated */
bool verify_auth(void);

/* Logout the current session */
void logout(void);

/* Check if penalty delay is active */
bool penalty_active(void);
