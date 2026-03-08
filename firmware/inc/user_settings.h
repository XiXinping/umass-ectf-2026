#ifndef USER_SETTINGS_H
#define USER_SETTINGS_H

/* ------------------------------------------------------------------------- */
/* Platform Settings */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_GENERAL_ALIGNMENT 4
#define SINGLE_THREADED            /* Fixes the pthread.h error */
#define WOLFSSL_IGNORE_FILE_SYSTEM /* Fixes the rtl.h / file errors */
#define NO_FILESYSTEM
#define NO_WRITEV
#define NO_MAIN_DRIVER
#define NO_DEV_RANDOM /* Microcontrollers don't have /dev/random */
#define NO_WOLFSSL_DIR
#define WOLFSSL_NO_FLOAT_FMT
#define WOLFSSL_NO_STDIO

/* ------------------------------------------------------------------------- */
/* Math & Architecture */
/* ------------------------------------------------------------------------- */
#define SIZEOF_LONG_LONG 8
#define TFM_ARM /* Optimized math for ARM */
#define USE_FAST_MATH
#define WOLFSSL_SMALL_STACK

/* ------------------------------------------------------------------------- */
/* eCTF Required Crypto (Typical) */
/* ------------------------------------------------------------------------- */
#define WOLFSSL_AES_GCM /* Common for authenticated encryption */
#define HAVE_AESGCM
#define WOLFSSL_SHA256 /* Common for hashing/signatures */
#define WOLFSSL_SHA512
#define HAVE_ECC /* If you're doing Elliptic Curve */
#define HAVE_SUPPORTED_CURVES

/* ------------------------------------------------------------------------- */
/* Side-Channel & Timing Attack Protection */
/* ------------------------------------------------------------------------- */
#define TFM_TIMING_RESISTANT       /* Constant-time math for RSA/ECC */
#define ECC_TIMING_RESISTANT       /* Constant-time Elliptic Curve */
#define WOLFSSL_AESGCM_SCA_PROTECT /* Side-channel protection for AES-GCM */

/* This next one silences that specific warning by acknowledging you've hardened
 * it */
#define WC_NO_HAS_OPTIONS
#define WOLFSSL_USER_SETTINGS
#define HAVE_X963_KDF

/* ------------------------------------------------------------------------- */
/* Debugging (Disable for final submission to save space) */
/* ------------------------------------------------------------------------- */
// #define DEBUG_WOLFSSL

#endif /* USER_SETTINGS_H */
