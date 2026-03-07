#include "host_messaging.h"
#include "simple_crypto.h"
#include "simple_flash.h"
#include "system.h"
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

void persist_timestamp_state(void);

void secure_zero(void *buf, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)buf;
    while (len--)
        *p++ = 0;
}

bool constant_time_compare(const uint8_t *a, const uint8_t *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++)
        diff |= a[i] ^ b[i];
    return diff == 0;
}

uint64_t safe_add_u64(uint64_t base, uint64_t delta) {
    if (UINT64_MAX - base < delta)
        return UINT64_MAX;
    return base + delta;
}

bool checked_add_u32(uint32_t a, uint32_t b, uint32_t *out) {
    if (out == NULL)
        return false;
    if (UINT32_MAX - a < b)
        return false;
    *out = a + b;
    return true;
}

bool checked_add_u64(uint64_t a, uint64_t b, uint64_t *out) {
    if (out == NULL)
        return false;
    if (UINT64_MAX - a < b)
        return false;
    *out = a + b;
    return true;
}

uint32_t simple_checksum32(const uint8_t *buf, size_t len) {
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
