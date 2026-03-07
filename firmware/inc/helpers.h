#ifndef HELPERS_H
#define HELPERS_H
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

static void persist_timestamp_state(void);

static void secure_zero(void *buf, size_t len);

static bool constant_time_compare(const uint8_t *a, const uint8_t *b,
                                  size_t len);

static uint64_t safe_add_u64(uint64_t base, uint64_t delta);

static bool checked_add_u32(uint32_t a, uint32_t b, uint32_t *out);

static bool checked_add_u64(uint64_t a, uint64_t b, uint64_t *out);

static uint32_t simple_checksum32(const uint8_t *buf, size_t len);

#endif // HELPERS_H
