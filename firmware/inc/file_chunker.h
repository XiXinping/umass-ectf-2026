#include <stdint.h>
#include "filesystem.h"


uint8_t* buffer_store_oldfile_contents(slot_t slot);

uint8_t* buffer_store_oldfile_metadata(slot_t slot);

uint8_t* buffer_store_newfile_contents(file_t* file, uint8_t* UUID);

uint8_t* buffer_store_newfile_metadata(file_t* file, uint8_t* UUID)