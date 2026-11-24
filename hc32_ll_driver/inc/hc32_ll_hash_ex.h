/**
 *******************************************************************************
 * @file  hc32_ll_hash_ex.h
 * @brief This file contains the function prototypes of the HASH extension
 *        driver. Provides context-based streaming SHA256 and HMAC-SHA256
 *        APIs that can be safely used from multiple tasks simultaneously.
 *
 * @note  Unlike the base HASH driver which uses a file-global singleton state,
 *        each hash/hmac context is held by the caller, making these APIs fully
 *        reentrant.
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
#ifndef __HC32_LL_HASH_EX_H__
#define __HC32_LL_HASH_EX_H__

/* C binding of definitions if building with C++ compiler */
#ifdef __cplusplus
extern "C" {
#endif

/*******************************************************************************
 * Include files
 ******************************************************************************/
#include "hc32_ll_hash.h"

/**
 * @addtogroup LL_Driver
 * @{
 */

/**
 * @addtogroup LL_HASH_EX
 * @{
 */

#if (LL_HASH_ENABLE == DDL_ON)

/*******************************************************************************
 * Global type definitions ('typedef')
 ******************************************************************************/

/**
 * @defgroup HASH_EX_Global_Types HASH_EX Global Types
 * @{
 */

/**
 * @brief  SHA256 streaming context. Each SHA256 calculation must have its own
 *         instance of this structure. The caller owns the storage; it can be
 *         stack-, heap- or static-allocated.
 */
typedef struct {
    uint8_t  buffer[64];      /*!< Accumulation buffer for partial blocks */
    uint32_t buffer_len;      /*!< Valid bytes currently stored in buffer */
    uint64_t total_len;       /*!< Total bytes processed so far */
    uint8_t  started;         /*!< Whether the first group has been submitted */
    uint8_t  finished;        /*!< Whether HASH_Final_Ex has been called */
} stc_hash_ctx_t;

/**
 * @brief  HMAC-SHA256 streaming context. Same ownership semantics as
 *         stc_hash_ctx_t.
 */
typedef struct {
    stc_hash_ctx_t inner_ctx; /*!< Inner SHA256 context: H(key XOR ipad || message) */
    stc_hash_ctx_t outer_ctx; /*!< Outer SHA256 context: H(key XOR opad || inner_hash) */
    uint8_t k0[64];           /*!< Processed key: H(key) if key > 64 B, else key || zeros */
    uint8_t state;            /*!< 0 = uninitialized, 1 = initialized, 2 = finalized */
} stc_hmac_ctx_t;

/**
 * @}
 */

/*******************************************************************************
  Global function prototypes (definition in C source)
 ******************************************************************************/
/**
 * @addtogroup HASH_EX_Global_Functions
 * @{
 */

/* ==================== SHA256 streaming API ==================== */

/**
 * @brief  Initialize a SHA256 streaming context. Resets the HASH hardware to
 *         SHA256 mode and prepares the context for incremental feeding.
 * @param  [out] pCtx   Pointer to the SHA256 context structure.
 * @retval int32_t:
 *           - LL_OK:               Initialized successfully
 *           - LL_ERR_INVD_PARAM:   pCtx is NULL
 *           - LL_ERR_TIMEOUT:      Hardware did not become idle in time
 */
int32_t HASH_Init_Ex(stc_hash_ctx_t *pCtx);

/**
 * @brief  Feed arbitrary-length data into a SHA256 streaming context. Can be
 *         called repeatedly with any chunk size.
 * @param  [in,out] pCtx    Pointer to the SHA256 context structure.
 * @param  [in]     pData   Pointer to the input data buffer.
 * @param  [in]     u32Len  Length of input data in bytes.
 * @retval int32_t:
 *           - LL_OK:               Data fed successfully
 *           - LL_ERR_INVD_PARAM:   pCtx is NULL / pData is NULL when u32Len > 0
 *                                  / context is already finalized
 *           - LL_ERR_TIMEOUT:      Hardware operation timed out
 */
int32_t HASH_Update_Ex(stc_hash_ctx_t *pCtx, const uint8_t *pData, uint32_t u32Len);

/**
 * @brief  Finalize a SHA256 streaming context: perform padding, write the
 *         64-bit big-endian total bit-length, and read the 32-byte digest.
 * @param  [in,out] pCtx          Pointer to the SHA256 context structure.
 * @param  [out]    pu8MsgDigest   Output buffer, at least 32 bytes.
 * @retval int32_t:
 *           - LL_OK:               Digest computed successfully
 *           - LL_ERR_INVD_PARAM:   pCtx or pu8MsgDigest is NULL / context
 *                                  already finalized
 *           - LL_ERR_TIMEOUT:      Hardware operation timed out
 */
int32_t HASH_Final_Ex(stc_hash_ctx_t *pCtx, uint8_t *pu8MsgDigest);

/* ==================== HMAC-SHA256 streaming API ==================== */

/**
 * @brief  Initialize an HMAC-SHA256 streaming context with the given secret key.
 *         Performs RFC 2104 key processing and writes the key into the HASH
 *         hardware in HMAC mode.
 * @param  [out] pCtx       Pointer to the HMAC context structure.
 * @param  [in]  pKey       Pointer to the secret key buffer.
 * @param  [in]  u32KeyLen  Length of the secret key in bytes.
 * @retval int32_t:
 *           - LL_OK:               Initialized successfully
 *           - LL_ERR_INVD_PARAM:   pCtx / pKey is NULL, or u32KeyLen is 0
 *           - LL_ERR_TIMEOUT:      Hardware operation timed out
 */
int32_t HMAC_Init_Ex(stc_hmac_ctx_t *pCtx, const uint8_t *pKey, uint32_t u32KeyLen);

/**
 * @brief  Feed message data into an HMAC-SHA256 streaming context. Can be
 *         called repeatedly with any chunk size.
 * @param  [in,out] pCtx    Pointer to the HMAC context structure.
 * @param  [in]     pData   Pointer to the message data buffer.
 * @param  [in]     u32Len  Length of message data in bytes.
 * @retval int32_t:
 *           - LL_OK:               Data fed successfully
 *           - LL_ERR_INVD_PARAM:   pCtx is NULL / state != 1 /
 *                                  pData is NULL when u32Len > 0
 *           - LL_ERR_TIMEOUT:      Hardware operation timed out
 */
int32_t HMAC_Update_Ex(stc_hmac_ctx_t *pCtx, const uint8_t *pData, uint32_t u32Len);

/**
 * @brief  Finalize an HMAC-SHA256 streaming context: feed the final message
 *         block with SHA256 padding, then wait for the hardware to complete
 *         the inner→outer HMAC computation and read the 32-byte digest.
 * @param  [in,out] pCtx          Pointer to the HMAC context structure.
 * @param  [out]    pu8MsgDigest   Output buffer, at least 32 bytes.
 * @retval int32_t:
 *           - LL_OK:               HMAC computed successfully
 *           - LL_ERR_INVD_PARAM:   pCtx or pu8MsgDigest is NULL / state != 1
 *           - LL_ERR_TIMEOUT:      Hardware operation timed out
 */
int32_t HMAC_Final_Ex(stc_hmac_ctx_t *pCtx, uint8_t *pu8MsgDigest);

/**
 * @}
 */

#endif /* LL_HASH_ENABLE */

/**
 * @}
 */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* __HC32_LL_HASH_EX_H__ */

/*******************************************************************************
 * EOF (not truncated)
 ******************************************************************************/
