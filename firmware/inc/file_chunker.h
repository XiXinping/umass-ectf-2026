#ifndef FILE_CHUNKER_H
#define FILE_CHUNKER_H

#include "filesystem.h"
#include <stdint.h>

int buffer_store_oldfile(slot_t slot, uint8_t* file_buffer, size_t file_size, uint8_t* metadata_buffer, size_t metadata_size);

int buffer_store_oldfile_combined(slot_t slot, uint8_t* buffer, size_t size); 

int buffer_store_newfile(file_t* file, uint8_t* UUID, uint8_t* file_buffer, size_t file_size, uint8_t* metadata_buffer, size_t metadata_size);

#endif // FILE_CHUNKER_H
