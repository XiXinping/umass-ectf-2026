#include "filesystem.c"
#include "simple_flash.h"

// Read a file from a slot and output it to the buffer pointed to by dest.
// Secure read will do the following:
// 1. Check if the HSM has the valid permission to read the file.
// 2. Verify that the file was written with proper permissions.
// 3. Access the read permission key.
// 4. Decrypt the file contents and output them to the buffer.
int secure_read(slot_t slot, file_t *dest) {}
