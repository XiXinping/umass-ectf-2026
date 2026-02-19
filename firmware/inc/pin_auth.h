#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define PIN_LENGTH 6
#define PIN_SALT_SIZE 16
#define PIN_HASH_SIZE 32
#define PIN_PBKDF2_ITERATIONS 10000
#define PIN_FAILURE_DELAY_MS 5000
#define PIN_MAX_RETRIES 5
#define AUTH_SESSION_TIMEOUT_MS 5000  // 5 seconds
#define PIN_STORAGE_MAGIC       0x50494E53U /* PINS */


/* Keep PIN authentication scoped to one host command by default. */
#ifndef SECURITY_REQUIRE_PIN_EACH_COMMAND
#define SECURITY_REQUIRE_PIN_EACH_COMMAND 1
#endif

typedef struct {
    uint32_t magic;
    uint8_t salt[PIN_SALT_SIZE];
    uint8_t hash[PIN_HASH_SIZE];// should hash and salt be stored together unencrypted?
    uint64_t penalty_expiration_ms;
    uint8_t failed_attempts;
    bool session_active;
    uint8_t reserved[6];
    uint64_t session_expiration_ms;
    uint32_t checksum;
} pin_storage_t;


typedef struct {
    uint32_t magic;
    uint64_t first_timestamp_ms; // First seen timestamp?
    uint64_t max_observed_timestamp_ms; // Is this tracker for largest timestamp seen or largest delta seen?
    uint32_t checksum; // Good idea, although have to ensure that this is not tampered with
} timestamp_storage_t;
