#include "filesystem.h"
#include "simple_flash.h"
#include <stdlib.h>

/** @brief Read and decrypt a protected file from persistent storage into
 *  memory if the HSM has appropriate permissions.
 *
 *  Secure read will do the following:
 *  1. Check if the HSM has the valid permission to read the file.
 *  2. Verify that the file was written with proper permissions.
 *  3. Access the read permission key.
 *  4. Decrypt the file contents and output them to the buffer.
 *
 *  @param slot The slot to read
 *  @param dest The destination address to store the file
 *
 * @return 0 upon success. A negative value otherwise.
 */
int secure_read(slot_t slot, file_t *dest) {
    file_t file;
    if (read_file(slot, file) < 0) {
        print_error("Failed to read file!");
        return -1;
    }
}
