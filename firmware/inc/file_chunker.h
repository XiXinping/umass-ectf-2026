#ifndef FILE_CHUNKER_H
#define FILE_CHUNKER_H

#include "filesystem.h"
#include <stdint.h>

uint8_t *buffer_store_oldfile_contents(slot_t slot);

uint8_t *buffer_store_oldfile_metadata(slot_t slot);

uint8_t *buffer_store_newfile_contents(file_t *file, uint8_t *UUID);

uint8_t *buffer_store_newfile_metadata(file_t *file, uint8_t *UUID)

#endif // FILE_CHUNKER_H
