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

/* Provision a new PIN (salt + PBKDF2 hash) */
security_status_t provision_pin(const uint8_t *pin, size_t len);

/* Verify a PIN for protected actions; returns error codes, enforces penalty &
 * max retries */
security_status_t verify_pin(const uint8_t *pin, size_t len);

/* Check if current session is authenticated */
bool verify_auth(void);

/* Logout the current session */
void logout(void);

/* Check if HSM has permission for a specific action */
bool validate_permission(uint16_t group_id, permission_t perm);

/* Check if penalty delay is active */
bool penalty_active(void);

/* ---------------- Remote HSM / File Transfer ---------------- */

/* Verify that a remote HSM message is valid:
   - sender identity via ECC signature
   - permission group of sender
   - file integrity via AES-GCM tag */
bool security_verify_remote_hsm(const uint8_t *msg, size_t msg_len,
                                const uint8_t *signature, size_t sig_len,
                                const uint8_t *file, size_t file_len,
                                const uint8_t *tag, uint16_t sender_group,
                                permission_t action);
