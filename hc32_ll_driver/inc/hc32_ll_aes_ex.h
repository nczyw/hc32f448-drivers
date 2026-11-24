/**
 *******************************************************************************
 * @file  hc32_ll_aes_ex.h
 * @brief This file contains the function prototypes of the AES extension
 *        driver. Provides context-based streaming AES APIs that can be safely
 *        used from multiple tasks simultaneously.
 *
 *        Supported modes: ECB, CBC, CTR.
 *        Padding: PKCS#7 (only for block modes ECB/CBC, handled automatically).
 *
 * @note  Unlike the base AES driver (which stores no state and can only do a
 *        single ECB batch), each AES context is held by the caller, making
 *        these APIs fully reentrant across tasks / ISRs.
 *******************************************************************************
 * Copyright (C) 2022-2025, Xiaohua Semiconductor Co., Ltd. All rights reserved.
 *
 * This software component is licensed by XHSC under BSD 3-Clause license
 * (the "License"); You may not use this file except in compliance with the
 * License. You may obtain a copy of the License at:
 *                    opensource.org/licenses/BSD-3-Clause
 *
 *******************************************************************************
 */
#ifndef __HC32_LL_AES_EX_H__
#define __HC32_LL_AES_EX_H__

/* C binding of definitions if building with C++ compiler */
#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * Include files
 ******************************************************************************/
#include "hc32_ll_aes.h"

/**
 * @addtogroup LL_Driver
 * @{
 */

/**
 * @addtogroup LL_AES_EX
 * @{
 */

#if (LL_AES_ENABLE == DDL_ON)

/*******************************************************************************
 * Global type definitions ('typedef')
 ******************************************************************************/

/**
 * @defgroup AES_EX_Global_Types AES_EX Global Types
 * @{
 */

/**
 * @brief  Cipher mode selection.
 *
 *         HC32F448's AES hardware only implements the bare ECB block cipher.
 *         All higher modes are composed in software on top of it — every
 *         16-byte block ultimately goes through the same hardware START cycle.
 */
typedef enum {
    AES_EX_MODE_ECB = 0U,   /*!< Electronic Codebook (no chaining) */
    AES_EX_MODE_CBC = 1U,   /*!< Cipher Block Chaining             */
    AES_EX_MODE_CTR = 2U,   /*!< Counter (stream cipher, uses encrypt only) */
} stc_aes_mode_t;

/**
 * @brief  Direction: encrypt or decrypt.
 *
 *         CTR mode always uses encrypt direction to generate the keystream;
 *         the 'dir' field is ignored for CTR.
 */
typedef enum {
    AES_EX_DIR_ENCRYPT = 0U,
    AES_EX_DIR_DECRYPT = 1U,
} stc_aes_dir_t;

/**
 * @brief  AES streaming context. Caller owns the storage (stack / heap / static).
 *         A single context handles exactly one open encryption/decryption
 *         session at a time; multiple independent sessions can run concurrently
 *         each with their own ctx.
 */
typedef struct {
    stc_aes_mode_t mode;

    /** Encrypt / decrypt. Ignored for CTR (CTR always uses encrypt hardware). */
    stc_aes_dir_t  dir;

    /** Cached key (16 / 24 / 32 bytes). Zeroed out in Final on success. */
    uint8_t  key[32];
    uint8_t  key_size;      /* 16 / 24 / 32 */

    /**
     * CBC  : last ciphertext block processed (= initial IV before first Update).
     * CTR  : current 128-bit counter value, big-endian. Incremented on every
     *        keystream generation. Caller supplies initial (nonce||ctr) via pIV
     *        in AES_Init_Ex.
     * ECB  : unused (ECB has no state between blocks).
     */
    uint8_t  iv_or_ctr[16];

    /** Accumulated partial block (len < 16). */
    uint8_t  buffer[16];
    uint8_t  buffer_len;

    /* ---------- CTR-only state ---------- */
    /** Leftover keystream bytes from a previously generated full block. */
    uint8_t  ks[16];
    uint8_t  ks_len;

    /** 0 = uninitialized, 1 = initialized (Update allowed), 2 = finalized. */
    uint8_t  state;
} stc_aes_ctx_t;

/**
 * @}
 */

/*******************************************************************************
  Global function prototypes (definition in C source)
 ******************************************************************************/
/**
 * @addtogroup AES_EX_Global_Functions
 * @{
 */

/**
 * @brief  Initialize an AES streaming context. Loads the key into the AES
 *         hardware, programs mode / direction, and seeds the chain state.
 *
 * @param  [out] pCtx       Caller-owned AES context to initialize.
 * @param  [in]  mode       Cipher mode (ECB / CBC / CTR).
 * @param  [in]  dir        Direction (ENCRYPT / DECRYPT). Ignored for CTR.
 * @param  [in]  pKey       AES key (16 / 24 / 32 bytes).
 * @param  [in]  key_size   @ref AES_Key_Size (16 / 24 / 32).
 * @param  [in]  pIV        16-byte IV / nonce||counter:
 *                            - CBC : initial IV (encrypt & decrypt MUST match).
 *                            - CTR : initial 128-bit counter (big-endian).
 *                            - ECB : pass NULL (no IV needed).
 *
 * @retval int32_t:
 *           - LL_OK:               Initialized successfully
 *           - LL_ERR_INVD_PARAM:   pCtx / pKey is NULL, key_size invalid,
 *                                  mode requires pIV but pIV is NULL
 *           - LL_ERR_TIMEOUT:      Hardware did not accept key in time
 */
int32_t AES_Init_Ex(stc_aes_ctx_t *pCtx,
                    stc_aes_mode_t mode,
                    stc_aes_dir_t  dir,
                    const uint8_t *pKey,
                    uint8_t        key_size,
                    const uint8_t *pIV);

/**
 * @brief  Feed arbitrary-length data into an AES streaming context and write
 *         out every complete block's worth of ciphertext / plaintext.
 *
 *         Encrypt (ECB/CBC): every full 16-byte input block is encrypted and
 *         written immediately. At most 15 trailing bytes stay buffered in pCtx
 *         until Final.
 *
 *         Decrypt (ECB/CBC): the **last complete ciphertext block is retained**
 *         inside pCtx. Output therefore lags input by one block; the retained
 *         block is only decrypted in Final, where PKCS#7 padding is verified.
 *         Callers just feed ciphertext; no special handling of the final block
 *         is required.
 *
 *         CTR: keystream blocks are generated on demand and XORed per byte, so
 *         output length always equals input length and no block alignment is
 *         needed.
 *
 * @param  [in,out] pCtx        AES context (must have been Init_Ex'd).
 * @param  [in]     pIn         Input data (plaintext for ENCRYPT, ciphertext
 *                              for DECRYPT).
 * @param  [in]     u32InLen    Input length in bytes (can be 0).
 * @param  [out]    pOut        Output buffer. Must be large enough to hold
 *                              (u32InLen + 16) bytes — worst case for CBC/CTR.
 * @param  [out]    pu32OutLen  Returns the number of bytes actually written
 *                              to pOut.
 *
 * @retval int32_t:
 *           - LL_OK:               Input consumed, pOut written
 *           - LL_ERR_INVD_PARAM:   pCtx is NULL / state != 1 /
 *                                  pIn is NULL when u32InLen > 0 /
 *                                  pOut is NULL / pu32OutLen is NULL
 *           - LL_ERR_TIMEOUT:      Hardware operation timed out
 */
int32_t AES_Update_Ex(stc_aes_ctx_t *pCtx,
                      const uint8_t *pIn,  uint32_t u32InLen,
                      uint8_t       *pOut, uint32_t *pu32OutLen);

/**
 * @brief  Finalize an AES streaming context. Uniform 3-parameter API for all
 *         modes and both directions.
 *
 *         - ECB/CBC **Encrypt** : pads the buffered remainder with PKCS#7 and
 *           writes exactly one 16-byte ciphertext block (a full 0x10 block when
 *           the plaintext length was already a multiple of 16).
 *         - ECB/CBC **Decrypt** : decrypts the last ciphertext block retained by
 *           Update, verifies and strips PKCS#7 padding, and writes the remaining
 *           plaintext (0 ~ 15 bytes). If the total ciphertext length was not a
 *           non-zero multiple of 16, or the padding is invalid, returns
 *           LL_ERR_INVD_PARAM.
 *         - CTR **Encrypt/Decrypt** : nothing left to do (Update emits output
 *           byte-for-byte), writes 0 bytes. No padding is used.
 *
 *         After Final returns successfully, the key stored in pCtx is zeroed
 *         (best-effort), and pCtx transitions to state=2 (cannot be reused).
 *
 * @param  [in,out] pCtx        AES context.
 * @param  [out]    pOut        Output buffer, at least 16 bytes.
 * @param  [out]    pu32OutLen  Number of bytes written to pOut
 *                              (ECB/CBC encrypt: always 16;
 *                               ECB/CBC decrypt: 0 ~ 15;
 *                               CTR: 0).
 *
 * @retval int32_t:
 *           - LL_OK:               Finalized successfully
 *           - LL_ERR_INVD_PARAM:   pCtx / pOut / pu32OutLen NULL,
 *                                  state != 1, ciphertext length invalid or
 *                                  PKCS#7 padding invalid on decrypt
 *           - LL_ERR_TIMEOUT:      Hardware operation timed out
 */
int32_t AES_Final_Ex(stc_aes_ctx_t *pCtx,
                     uint8_t       *pOut, uint32_t *pu32OutLen);

/**
 * @}
 */

#endif /* LL_AES_ENABLE */

/**
 * @}
 */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __HC32_LL_AES_EX_H__ */

/*******************************************************************************
 * EOF (not truncated)
 ******************************************************************************/
