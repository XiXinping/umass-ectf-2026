#include "filesystem.h"
#include "simple_flash.h"

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
