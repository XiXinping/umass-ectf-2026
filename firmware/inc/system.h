#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_PERMS 8
#define PIN_LENGTH 6
#define PIN_SALT_SIZE 16
#define PIN_HASH_SIZE 32
#define PIN_PBKDF2_ITERATIONS 10000
#define PIN_FAILURE_DELAY_MS 5000
#define PIN_MAX_RETRIES 5
#define AUTH_SESSION_TIMEOUT_MS 5000 // 5 seconds
#define AES_GCM_TAG_SIZE 16
#define AES_GCM_IV_SIZE 12
#define AES_GCM_KEY_SIZE 32

/*
 * Flash regions intended for protected storage.
 * Platform should map these ranges to the most restrictive policy available.
 */
#define SECURITY_FLASH_REGION_PIN_ADDR 0x00000000U
#define SECURITY_FLASH_REGION_PERMS_ADDR 0x00001000U
#define SECURITY_FLASH_REGION_TIME_ADDR 0x00002000U
#define SECURITY_FLASH_REGION_CRYPTO_ADDR 0x00003000U

/* Keep PIN authentication scoped to one host command by default. */
#ifndef SECURITY_REQUIRE_PIN_EACH_COMMAND
#define SECURITY_REQUIRE_PIN_EACH_COMMAND 1
#endif

/*
 * Optional platform hooks to lock/check clock config after boot.
 * Override these macros with platform-specific implementations.
 */
#ifndef SECURITY_LOCK_CLOCK_CONFIG
#define SECURITY_LOCK_CLOCK_CONFIG() true
#endif

#ifndef SECURITY_IS_CLOCK_CONFIG_LOCKED
#define SECURITY_IS_CLOCK_CONFIG_LOCKED() true
#endif

#endif
