#include "system.h"
#include "host_messaging.h"
#include "simple_crypto.h"
#include "simple_flash.h"

#include <stdio.h>
#include <string.h>

/* -------------------- Internal State -------------------- */

typedef struct {
    uint32_t magic;
    uint8_t salt[PIN_SALT_SIZE];
    uint8_t hash[PIN_HASH_SIZE]; // should hash and salt be stored together
                                 // unencrypted?
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

typedef struct {
    uint32_t magic; // what is magic?
    uint8_t key[AES_GCM_KEY_SIZE];
    uint8_t last_iv[AES_GCM_IV_SIZE];
    uint8_t last_tag[AES_GCM_TAG_SIZE];
    uint32_t checksum; // is this the sha256 of the file?
} crypto_storage_t;

static pin_storage_t g_pin_data;
static bool g_authenticated = false;
static uint64_t g_session_expiration_ms = 0;
static uint64_t g_last_time_ms = 0;
static timestamp_storage_t g_time_data;
static crypto_storage_t g_crypto_data;
static bool g_time_anomaly_detected = false;

/* Permissions table (indexed by group_id when group_id < MAX_PERMS) */
static group_permission_t g_permissions[MAX_PERMS];

/* Platform hooks */
extern uint64_t platform_get_time_ms(void);
extern int trng_generate(uint8_t *buf, size_t len);

/* Flash addresses */
#define PIN_FLASH_ADDR SECURITY_FLASH_REGION_PIN_ADDR
#define PERMS_FLASH_ADDR SECURITY_FLASH_REGION_PERMS_ADDR
#define TIME_FLASH_ADDR SECURITY_FLASH_REGION_TIME_ADDR
#define CRYPTO_FLASH_ADDR SECURITY_FLASH_REGION_CRYPTO_ADDR

#define TIMESTAMP_STORAGE_MAGIC 0x54534D50U /* TSMP */
#define CRYPTO_STORAGE_MAGIC 0x43525950U    /* CRYP */
#define PIN_STORAGE_MAGIC 0x50494E53U       /* PINS */
#define TIMESTAMP_DRIFT_TOLERANCE_MS 1000U

/* Host message command lengths */
#define HOST_LIST_CMD_LEN PIN_LENGTH
#define HOST_READ_CMD_LEN (PIN_LENGTH + 1U)
#define HOST_WRITE_MIN_CMD_LEN                                                 \
    (PIN_LENGTH + 1U + 2U + HSM_FILE_NAME_SIZE + HSM_FILE_UUID_SIZE + 2U)
#define HOST_INTERROGATE_CMD_LEN PIN_LENGTH
#define HOST_RECEIVE_CMD_LEN (PIN_LENGTH + 1U + 1U)

/* -------------------- Internal Helpers -------------------- */
static void persist_timestamp_state(void);

static void secure_zero(void *buf, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--)
        *p++ = 0;
}

static bool constant_time_compare(const uint8_t *a, const uint8_t *b,
                                  size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

static uint64_t safe_add_u64(uint64_t base, uint64_t delta) {
    if (UINT64_MAX - base < delta)
        return UINT64_MAX;
    return base + delta;
}

static bool checked_add_u32(uint32_t a, uint32_t b, uint32_t *out) {
    if (out == NULL)
        return false;
    if (UINT32_MAX - a < b)
        return false;
    *out = a + b;
    return true;
}

static bool checked_add_u64(uint64_t a, uint64_t b, uint64_t *out) {
    if (out == NULL)
        return false;
    if (UINT64_MAX - a < b)
        return false;
    *out = a + b;
    return true;
}

static uint32_t simple_checksum32(const uint8_t *buf, size_t len) {
    uint32_t acc = 0xA5A5A5A5U;
    size_t i;

    if (buf == NULL)
        return 0U;
    for (i = 0; i < len; i++) {
        acc ^= ((uint32_t)buf[i] << ((i & 3U) * 8U));
        acc = (acc << 5) | (acc >> 27);
    }
    return acc;
}

/* Clamp non-monotonic rollback from platform time source. */
static uint64_t monotonic_time_ms(void) {
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

static void flush_timestamp_state_if_needed(void) {
    if (g_time_anomaly_detected)
        return;
    if (g_time_data.max_observed_timestamp_ms <= g_time_data.first_timestamp_ms)
        return;
    persist_timestamp_state();
}

static const group_permission_t *permission_entry(uint16_t group_id) {
    if (group_id >= MAX_PERMS)
        return NULL;

    const group_permission_t *entry = &g_permissions[group_id];
    if (entry->group_id == group_id)
        return entry;

    for (int i = 0; i < MAX_PERMS; i++) {
        if (g_permissions[i].group_id == group_id)
            return &g_permissions[i];
    }
    return NULL;
}

static bool permission_allowed(uint16_t group_id, permission_enum_t perm) {
    const group_permission_t *entry = permission_entry(group_id);
    if (entry == NULL)
        return false;

    switch (perm) {
    case PERM_READ:
        return entry->read;
    case PERM_WRITE:
        return entry->write;
    case PERM_RECEIVE:
        return entry->receive;
    default:
        return false;
    }
}

static bool verify_sender_identity(const uint8_t *msg, size_t msg_len,
                                   const uint8_t *signature, size_t sig_len) {
    if (msg == NULL || signature == NULL || sig_len == 0)
        return false;
    return ecc_verify_signature(msg, msg_len, signature, sig_len);
}

static bool verify_sender_permission(uint16_t sender_group,
                                     permission_enum_t action) {
    return permission_allowed(sender_group, action);
}

static bool verify_file_integrity(const uint8_t *file, size_t file_len,
                                  const uint8_t *tag) {
    if (file == NULL || tag == NULL)
        return false;
    return aes_gcm_verify(file, file_len, tag);
}

static bool pin_storage_valid(const pin_storage_t *state) {
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

static void persist_pin(void) {
    g_pin_data.magic = PIN_STORAGE_MAGIC;
    g_pin_data.checksum = simple_checksum32((const uint8_t *)&g_pin_data,
                                            offsetof(pin_storage_t, checksum));
    flash_erase_page(PIN_FLASH_ADDR);
    flash_write(PIN_FLASH_ADDR, (uint8_t *)&g_pin_data, sizeof(g_pin_data));
}

static void load_pin(void) {
    flash_read(PIN_FLASH_ADDR, (uint8_t *)&g_pin_data, sizeof(g_pin_data));
}

static void persist_permissions(void) {
    flash_erase_page(PERMS_FLASH_ADDR);
    flash_write(PERMS_FLASH_ADDR, (uint8_t *)g_permissions,
                sizeof(g_permissions));
}

static void load_permissions(void) {
    flash_read(PERMS_FLASH_ADDR, (uint8_t *)g_permissions,
               sizeof(g_permissions));
}

static bool timestamp_storage_valid(const timestamp_storage_t *state) {
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

static void persist_timestamp_state(void) {
    g_time_data.magic = TIMESTAMP_STORAGE_MAGIC;
    g_time_data.checksum = simple_checksum32(
        (const uint8_t *)&g_time_data, offsetof(timestamp_storage_t, checksum));
    flash_erase_page(TIME_FLASH_ADDR);
    flash_write(TIME_FLASH_ADDR, (uint8_t *)&g_time_data, sizeof(g_time_data));
}

static void load_timestamp_state(void) {
    flash_read(TIME_FLASH_ADDR, (uint8_t *)&g_time_data, sizeof(g_time_data));
}

static bool crypto_storage_valid(const crypto_storage_t *state) {
    uint32_t checksum;
    if (state == NULL)
        return false;
    if (state->magic != CRYPTO_STORAGE_MAGIC)
        return false;

    checksum = simple_checksum32((const uint8_t *)state,
                                 offsetof(crypto_storage_t, checksum));
    return checksum == state->checksum;
}

static void persist_crypto_state(void) {
    g_crypto_data.magic = CRYPTO_STORAGE_MAGIC;
    g_crypto_data.checksum = simple_checksum32(
        (const uint8_t *)&g_crypto_data, offsetof(crypto_storage_t, checksum));
    flash_erase_page(CRYPTO_FLASH_ADDR);
    flash_write(CRYPTO_FLASH_ADDR, (uint8_t *)&g_crypto_data,
                sizeof(g_crypto_data));
}

static void load_crypto_state(void) {
    flash_read(CRYPTO_FLASH_ADDR, (uint8_t *)&g_crypto_data,
               sizeof(g_crypto_data));
}

static uint16_t read_le16(const uint8_t *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static void write_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static void write_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static uint8_t status_to_error_code(security_status_t status) {
    return (uint8_t)status;
}

static bool pin_is_lower_hex(const uint8_t *pin, size_t len) {
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

static bool authenticate_request_pin(const uint8_t *body, uint16_t body_len,
                                     uint8_t *err) {
    if (err == NULL)
        return false;
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

static bool serialize_file_list(const hsm_file_metadata_t *files,
                                uint32_t count, uint8_t *out, uint16_t out_cap,
                                uint16_t *out_len) {
    uint32_t i;
    uint32_t per_entry = (uint32_t)(1U + 2U + HSM_FILE_NAME_SIZE);
    uint32_t payload = 0U;
    uint32_t needed = 0U;

    if (files == NULL || out == NULL || out_len == NULL)
        return false;
    if (count > HSM_MAX_FILES)
        return false;
    if (count != 0U && per_entry > (UINT32_MAX / count))
        return false;
    if (!checked_add_u32(0U, count * per_entry, &payload))
        return false;
    if (!checked_add_u32(4U, payload, &needed))
        return false;
    if (needed > out_cap || needed > UINT16_MAX)
        return false;

    write_le32(out, count);

    for (i = 0; i < count; i++) {
        uint32_t base = 4U + i * (1U + 2U + HSM_FILE_NAME_SIZE);
        out[base] = files[i].slot;
        write_le16(&out[base + 1U], files[i].group_id);
        memcpy(&out[base + 3U], files[i].name, HSM_FILE_NAME_SIZE);
    }

    *out_len = (uint16_t)needed;
    return true;
}

static bool handle_list_cmd(const uint8_t *body, uint16_t body_len,
                            const hsm_file_ops_t *ops, uint8_t *response_body,
                            uint16_t response_capacity, uint16_t *response_len,
                            uint8_t *err) {
    hsm_file_metadata_t files[HSM_MAX_FILES];
    uint32_t count = HSM_MAX_FILES;

    if (response_body == NULL || response_len == NULL || err == NULL) {
        return false;
    }
    if (body_len != HOST_LIST_CMD_LEN) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }
    if (!authenticate_request_pin(body, body_len, err))
        return false;
    if (ops == NULL || ops->list_local_files == NULL) {
        *err = 0x70;
        return false;
    }

    if (!ops->list_local_files(files, &count)) {
        *err = 0x71;
        return false;
    }
    if (count > HSM_MAX_FILES) {
        *err = 0x72;
        return false;
    }

    if (!serialize_file_list(files, count, response_body, response_capacity,
                             response_len)) {
        *err = 0x73;
        return false;
    }

    return true;
}

static bool handle_read_cmd(const uint8_t *body, uint16_t body_len,
                            const hsm_file_ops_t *ops, uint8_t *response_body,
                            uint16_t response_capacity, uint16_t *response_len,
                            uint8_t *err) {
    uint8_t slot;
    hsm_file_record_t file;
    uint32_t needed;

    if (response_body == NULL || response_len == NULL || err == NULL) {
        return false;
    }
    if (body_len != HOST_READ_CMD_LEN) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }
    if (!authenticate_request_pin(body, body_len, err))
        return false;
    if (ops == NULL || ops->read_local_file == NULL) {
        *err = 0x74;
        return false;
    }

    slot = body[PIN_LENGTH];
    if (slot >= HSM_MAX_FILES) {
        *err = 0x85;
        return false;
    }
    if (!ops->read_local_file(slot, &file)) {
        *err = 0x75;
        return false;
    }

    if (!security_validate_permission(file.group_id, PERM_READ)) {
        *err = 0x76;
        return false;
    }

    needed = (uint32_t)HSM_FILE_NAME_SIZE + file.contents_len;
    if (needed > response_capacity) {
        *err = 0x77;
        return false;
    }

    memcpy(response_body, file.name, HSM_FILE_NAME_SIZE);
    if (file.contents_len > 0 && file.contents != NULL) {
        memcpy(response_body + HSM_FILE_NAME_SIZE, file.contents,
               file.contents_len);
    }
    *response_len = (uint16_t)needed;
    return true;
}

static bool parse_write_cmd(const uint8_t *body, uint16_t body_len,
                            hsm_file_record_t *file, uint8_t *err) {
    uint32_t fixed_len = (uint32_t)HOST_WRITE_MIN_CMD_LEN;
    uint32_t expected_len;
    uint16_t contents_len;

    if (body == NULL || file == NULL || err == NULL) {
        return false;
    }

    if (body_len < HOST_WRITE_MIN_CMD_LEN) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }

    file->slot = body[PIN_LENGTH];
    if (file->slot >= HSM_MAX_FILES) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }
    file->group_id = read_le16(&body[PIN_LENGTH + 1U]);
    memcpy(file->name, &body[PIN_LENGTH + 3U], HSM_FILE_NAME_SIZE);
    memcpy(file->uuid, &body[PIN_LENGTH + 3U + HSM_FILE_NAME_SIZE],
           HSM_FILE_UUID_SIZE);

    contents_len = read_le16(
        &body[PIN_LENGTH + 3U + HSM_FILE_NAME_SIZE + HSM_FILE_UUID_SIZE]);
    if (!checked_add_u32(fixed_len, (uint32_t)contents_len, &expected_len)) {
        *err = (uint8_t)SECURITY_ERR_BUFFER;
        return false;
    }
    if (expected_len > UINT16_MAX || body_len != (uint16_t)expected_len) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }

    file->contents_len = contents_len;
    file->contents = &body[HOST_WRITE_MIN_CMD_LEN];
    return true;
}

static bool handle_write_cmd(const uint8_t *body, uint16_t body_len,
                             const hsm_file_ops_t *ops, uint16_t *response_len,
                             uint8_t *err) {
    hsm_file_record_t file;

    if (response_len == NULL || err == NULL)
        return false;
    if (!authenticate_request_pin(body, body_len, err))
        return false;
    if (ops == NULL || ops->write_local_file == NULL) {
        *err = 0x78;
        return false;
    }
    if (!parse_write_cmd(body, body_len, &file, err))
        return false;

    if (!security_validate_permission(file.group_id, PERM_WRITE)) {
        *err = 0x79;
        return false;
    }

    if (!ops->write_local_file(&file)) {
        *err = 0x7A;
        return false;
    }

    *response_len = 0;
    return true;
}

static bool handle_listen_cmd(const uint8_t *body, uint16_t body_len,
                              const hsm_file_ops_t *ops, uint16_t *response_len,
                              uint8_t *err) {
    (void)body;

    if (response_len == NULL || err == NULL)
        return false;
    if (body_len != 0) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }
    if (ops == NULL || ops->listen_for_neighbor == NULL) {
        *err = 0x7B;
        return false;
    }

    if (!ops->listen_for_neighbor()) {
        *err = 0x7C;
        return false;
    }

    *response_len = 0;
    return true;
}

static bool handle_interrogate_cmd(const uint8_t *body, uint16_t body_len,
                                   const hsm_file_ops_t *ops,
                                   uint8_t *response_body,
                                   uint16_t response_capacity,
                                   uint16_t *response_len, uint8_t *err) {
    hsm_file_metadata_t all_files[HSM_MAX_FILES];
    hsm_file_metadata_t filtered_files[HSM_MAX_FILES];
    uint32_t total = HSM_MAX_FILES;
    uint32_t filtered = 0;
    uint32_t i;

    if (response_body == NULL || response_len == NULL || err == NULL) {
        return false;
    }
    if (body_len != HOST_INTERROGATE_CMD_LEN) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }
    if (!authenticate_request_pin(body, body_len, err))
        return false;
    if (ops == NULL || ops->interrogate_neighbor == NULL) {
        *err = 0x7D;
        return false;
    }

    if (!ops->interrogate_neighbor(all_files, &total)) {
        *err = 0x7E;
        return false;
    }
    if (total > HSM_MAX_FILES) {
        *err = 0x7F;
        return false;
    }

    for (i = 0; i < total; i++) {
        if (security_validate_permission(all_files[i].group_id, PERM_RECEIVE)) {
            filtered_files[filtered++] = all_files[i];
        }
    }

    if (!serialize_file_list(filtered_files, filtered, response_body,
                             response_capacity, response_len)) {
        *err = 0x80;
        return false;
    }

    return true;
}

static bool handle_receive_cmd(const uint8_t *body, uint16_t body_len,
                               const hsm_file_ops_t *ops,
                               uint16_t *response_len, uint8_t *err) {
    uint8_t read_slot;
    uint8_t write_slot;
    hsm_file_record_t file;

    if (response_len == NULL || err == NULL)
        return false;
    if (body_len != HOST_RECEIVE_CMD_LEN) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }
    if (!authenticate_request_pin(body, body_len, err))
        return false;

    if (ops == NULL || ops->receive_neighbor_file == NULL ||
        ops->write_local_file == NULL) {
        *err = 0x81;
        return false;
    }

    read_slot = body[PIN_LENGTH];
    write_slot = body[PIN_LENGTH + 1U];
    if (read_slot >= HSM_MAX_FILES || write_slot >= HSM_MAX_FILES) {
        *err = (uint8_t)SECURITY_ERR_INVALID_LENGTH;
        return false;
    }

    if (!ops->receive_neighbor_file(read_slot, &file)) {
        *err = 0x82;
        return false;
    }

    if (!security_validate_permission(file.group_id, PERM_RECEIVE)) {
        *err = 0x83;
        return false;
    }

    file.slot = write_slot;
    if (!ops->write_local_file(&file)) {
        *err = 0x84;
        return false;
    }

    *response_len = 0;
    return true;
}

/* -------------------- Initialization -------------------- */

void security_init(void) {
    uint64_t now;
    uint64_t tolerated_now;

    load_pin();
    load_permissions();
    load_timestamp_state();
    load_crypto_state();

    now = platform_get_time_ms();
    g_last_time_ms = now;

    if (!SECURITY_LOCK_CLOCK_CONFIG() || !SECURITY_IS_CLOCK_CONFIG_LOCKED()) {
        g_time_anomaly_detected = true;
        g_authenticated = false;
    }

    if (!pin_storage_valid(&g_pin_data)) {
        memset(&g_pin_data, 0, sizeof(g_pin_data));
        g_pin_data.magic = PIN_STORAGE_MAGIC;
        persist_pin();
    }

    if (!timestamp_storage_valid(&g_time_data)) {
        g_time_data.magic = TIMESTAMP_STORAGE_MAGIC;
        g_time_data.first_timestamp_ms = now;
        g_time_data.max_observed_timestamp_ms = now;
        persist_timestamp_state();
    } else {
        if (!checked_add_u64(now, TIMESTAMP_DRIFT_TOLERANCE_MS,
                             &tolerated_now)) {
            tolerated_now = UINT64_MAX;
        }
        if (tolerated_now < g_time_data.first_timestamp_ms ||
            tolerated_now < g_time_data.max_observed_timestamp_ms) {
            g_time_anomaly_detected = true;
            g_authenticated = false;
        } else if (now > g_time_data.max_observed_timestamp_ms) {
            g_time_data.max_observed_timestamp_ms = now;
            persist_timestamp_state();
        }
    }

    if (!crypto_storage_valid(&g_crypto_data)) {
        memset(&g_crypto_data, 0, sizeof(g_crypto_data));
        if (trng_generate(g_crypto_data.key, AES_GCM_KEY_SIZE) != 0) {
            g_time_anomaly_detected = true;
        }
        if (trng_generate(g_crypto_data.last_iv, AES_GCM_IV_SIZE) != 0) {
            g_time_anomaly_detected = true;
        }
        memset(g_crypto_data.last_tag, 0, AES_GCM_TAG_SIZE);
        persist_crypto_state();
    }

    if (g_time_anomaly_detected) {
        g_authenticated = false;
        g_pin_data.session_active = false;
        g_pin_data.session_expiration_ms = 0;
        persist_pin();
    } else if (g_pin_data.session_active) {
        g_authenticated = true;
        g_session_expiration_ms = g_pin_data.session_expiration_ms;
        if (!security_is_authenticated()) {
            g_pin_data.session_active = false;
            g_pin_data.session_expiration_ms = 0;
            persist_pin();
        }
    } else {
        g_authenticated = false;
        g_session_expiration_ms = 0;
    }
}

/* -------------------- Penalty -------------------- */

bool security_penalty_active(void) {
    if (g_time_anomaly_detected)
        return true;
    uint64_t now = monotonic_time_ms();
    return now < g_pin_data.penalty_expiration_ms;
}

/* -------------------- PIN Verification -------------------- */

security_status_t security_verify_pin(const uint8_t *pin, size_t len) {
    if (pin == NULL)
        return SECURITY_ERR_INVALID_LENGTH;
    if (len != PIN_LENGTH)
        return SECURITY_ERR_INVALID_LENGTH;
    if (g_time_anomaly_detected)
        return SECURITY_ERR_TIME_ANOMALY;
    if (security_penalty_active())
        return SECURITY_ERR_PENALTY_ACTIVE;
    if (g_pin_data.failed_attempts >= PIN_MAX_RETRIES)
        return SECURITY_ERR_MAX_RETRIES;
    if (!pin_is_lower_hex(pin, len))
        return register_failed_pin_attempt();

    uint8_t derived[PIN_HASH_SIZE];
    if (pbkdf2_sha256(pin, len, g_pin_data.salt, PIN_SALT_SIZE,
                      PIN_PBKDF2_ITERATIONS, derived, PIN_HASH_SIZE) != 0) {
        return SECURITY_ERR_CRYPTO_FAIL;
    }

    bool match = constant_time_compare(derived, g_pin_data.hash, PIN_HASH_SIZE);
    secure_zero(derived, sizeof(derived));

    if (!match)
        return register_failed_pin_attempt();

    g_authenticated = true;
    g_pin_data.failed_attempts = 0;
    g_pin_data.penalty_expiration_ms = 0;
    g_session_expiration_ms =
        safe_add_u64(monotonic_time_ms(), AUTH_SESSION_TIMEOUT_MS);
    g_pin_data.session_active = true;
    g_pin_data.session_expiration_ms = g_session_expiration_ms;
    flush_timestamp_state_if_needed();
    persist_pin();
    return SECURITY_OK;
}

security_status_t security_provision_pin(const uint8_t *pin, size_t len) {
    if (pin == NULL)
        return SECURITY_ERR_INVALID_LENGTH;
    if (len != PIN_LENGTH)
        return SECURITY_ERR_INVALID_LENGTH;
    if (!pin_is_lower_hex(pin, len))
        return SECURITY_ERR_INVALID_PIN;
    if (g_time_anomaly_detected)
        return SECURITY_ERR_TIME_ANOMALY;
    if (trng_generate(g_pin_data.salt, PIN_SALT_SIZE) != 0)
        return SECURITY_ERR_CRYPTO_FAIL;

    if (pbkdf2_sha256(pin, len, g_pin_data.salt, PIN_SALT_SIZE,
                      PIN_PBKDF2_ITERATIONS, g_pin_data.hash,
                      PIN_HASH_SIZE) != 0) {
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
    if (!g_authenticated || !g_pin_data.session_active)
        return false;
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

/* -------------------- Permission Checks -------------------- */

bool security_validate_permission(uint16_t group_id, permission_enum_t perm) {
    if (!security_is_authenticated())
        return false;
    return permission_allowed(group_id, perm);
}

/* -------------------- Remote HSM / File Transfer -------------------- */

bool security_verify_remote_hsm(const uint8_t *msg, size_t msg_len,
                                const uint8_t *signature, size_t sig_len,
                                const uint8_t *file, size_t file_len,
                                const uint8_t *tag, uint16_t sender_group,
                                permission_enum_t action) {
    if (!verify_sender_identity(msg, msg_len, signature, sig_len))
        return false;
    if (!verify_sender_permission(sender_group, action))
        return false;
    if (!verify_file_integrity(file, file_len, tag))
        return false;
    return true;
}

/* -------------------- Host Command Dispatch -------------------- */

bool security_process_host_command(uint8_t opcode, const uint8_t *body,
                                   uint16_t body_len, const hsm_file_ops_t *ops,
                                   uint8_t *response_opcode,
                                   uint8_t *response_body,
                                   uint16_t response_capacity,
                                   uint16_t *response_len) {
    bool ok = false;
    uint8_t err = 0xFF;
    uint16_t out_len = 0;
    uint16_t empty_len = 0;

    if (response_opcode == NULL || response_body == NULL ||
        response_len == NULL)
        return false;
    if (body_len > 0U && body == NULL)
        return false;
    if (g_time_anomaly_detected) {
        if (response_capacity < 1U)
            return false;
        *response_opcode = HSM_OPCODE_ERROR;
        response_body[0] = (uint8_t)SECURITY_ERR_TIME_ANOMALY;
        *response_len = 1U;
        return true;
    }

    switch (opcode) {
    case HSM_OPCODE_LIST:
        ok = handle_list_cmd(body, body_len, ops, response_body,
                             response_capacity, &out_len, &err);
        break;

    case HSM_OPCODE_READ:
        ok = handle_read_cmd(body, body_len, ops, response_body,
                             response_capacity, &out_len, &err);
        break;

    case HSM_OPCODE_WRITE:
        ok = handle_write_cmd(body, body_len, ops, &empty_len, &err);
        out_len = empty_len;
        break;

    case HSM_OPCODE_LISTEN:
        ok = handle_listen_cmd(body, body_len, ops, &empty_len, &err);
        out_len = empty_len;
        break;

    case HSM_OPCODE_INTERROGATE:
        ok = handle_interrogate_cmd(body, body_len, ops, response_body,
                                    response_capacity, &out_len, &err);
        break;

    case HSM_OPCODE_RECEIVE:
        ok = handle_receive_cmd(body, body_len, ops, &empty_len, &err);
        out_len = empty_len;
        break;

    default:
        ok = false;
        err = 0xFE;
        break;
    }

    if (!ok) {
        *response_opcode = HSM_OPCODE_ERROR;
        if (response_capacity < 1U)
            return false;
        response_body[0] = err;
        *response_len = 1U;
#if SECURITY_REQUIRE_PIN_EACH_COMMAND
        security_logout();
#endif
        return true;
    }

    *response_opcode = opcode;
    *response_len = out_len;
#if SECURITY_REQUIRE_PIN_EACH_COMMAND
    security_logout();
#endif
    return true;
}
