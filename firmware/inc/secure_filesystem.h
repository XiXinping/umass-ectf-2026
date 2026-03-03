#include "aes_gcm.h"
#include "filesystem.h"
#include "simple_flash.h"
#include <stdint.h>

#define SIGNATURE_SIZE 32
#define SHARED_SECRET_SIZE 32
#define METADATA_SIZE                                                          \
    NONCE_SIZE + AUTH_TAG_SIZE + SHARED_SECRET_SIZE + SIGNATURE_SIZE
#define MAX_ENC_SIZE MAX_CONTENTS_SIZE - METADATA_SIZE

typedef struct {
    uint32_t in_use;
    group_id_t group_id;
    char name[MAX_NAME_SIZE];
    uint16_t length;

    uint8_t nonce[NONCE_SIZE];
    uint8_t auth_tag[AUTH_TAG_SIZE];
    uint8_t shared_secret[SHARED_SECRET_SIZE];
    uint8_t encrypted_contents[MAX_ENC_SIZE];
    uint8_t signature[SIGNATURE_SIZE];
} protected_file_t;

// Read a file from a slot and output it to the buffer pointed to by dest.
// Secure read will do the following:
// 1. Check if the HSM has the valid permission to read the file.
// 2. Verify that the file was written with proper permissions.
// 3. Access the read permission key.
// 4. Decrypt the file contents and output them to the buffer.
int secure_read(slot_t slot, file_t *dest);

// Write the contents of the buffer pointed to by src to a slot.
// Secure write will do the following:
// 1. Encrypt the file with the read public key corresponding to the permission
// group.
// 2. Cryptographically sign the file contents using the write private key
// corresponding to the permission group.
int secure_write(slot_t slot, file_t *src, uint8_t *uuid);

// Read a protected file from persistent storage. Does not perform any
// decryption or verification.
int load_protected_file(slot_t slot, protected_file_t *dest);
