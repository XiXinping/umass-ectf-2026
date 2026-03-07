/**
 * @file security.h
 * @author Samuel Meyers
 * @brief Stub file to hold security checks
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF
 * (eCTF). This code is being provided only for educational purposes for the
 * 2026 MITRE eCTF competition, and may not meet MITRE standards for quality.
 * Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */
#ifndef SECURITY_H
#define SECURITY_H

#include <stdbool.h>
#include <stdint.h>

#define MAX_PERMS 8

#define TIME_FLASH_ADDR SECURITY_FLASH_REGION_TIME_ADDR
#define CRYPTO_FLASH_ADDR SECURITY_FLASH_REGION_CRYPTO_ADDR

#define TIMESTAMP_STORAGE_MAGIC 0x54534D50U /* TSMP */
#define CRYPTO_STORAGE_MAGIC 0x43525950U    /* CRYP */
#define PIN_STORAGE_MAGIC 0x50494E53U       /* PINS */
#define TIMESTAMP_DRIFT_TOLERANCE_MS 1000U

typedef enum {
    SECURITY_OK = 0,
    SECURITY_ERR_INVALID_PIN,
    SECURITY_ERR_PENALTY_ACTIVE,
    SECURITY_ERR_INVALID_LENGTH,
    SECURITY_ERR_CRYPTO_FAIL,
    SECURITY_ERR_MAX_RETRIES,
    SECURITY_ERR_TIME_ANOMALY,
    SECURITY_ERR_BUFFER,
} security_status_t;

/** @brief Validate a pin against the HSM's pin
 *
 *  @param pin Requested pin to validate.
 *
 *  @return True if the pin is valid. False if not.
 */
bool check_pin(unsigned char *pin);

void security_init(void);

#endif // SECURITY_H
