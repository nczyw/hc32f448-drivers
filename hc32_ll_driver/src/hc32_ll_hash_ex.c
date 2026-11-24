/**
 *******************************************************************************
 * @file  hc32_ll_hash_ex.c
 * @brief This file provides context-based streaming SHA256 and HMAC-SHA256
 *        functions for the HC32F448 HASH peripheral.
 *
 *        Unlike the base HASH driver which stores its streaming state in a
 *        file-global singleton, these APIs keep all state inside the caller-
 *        owned context structure, making them safe for concurrent use from
 *        multiple tasks / ISRs.
 *
 * @note  HC32F448's HASH hardware is intentionally minimal: the CR register
 *        exposes only START and FST_GRP bits. There is no hardware MODE,
 *        KMSG_END or HMAC support. Consequently:
 *          - SHA256 padding (0x80 + zeros + 64-bit big-endian length) is done
 *            entirely in software, mirroring what the base driver does.
 *          - HMAC-SHA256 is implemented purely as RFC 2104's two-pass SHA256.
 *
 *        The only hardware-visible distinction between "first block" and
 *        "continuation block" is the FST_GRP bit — set it exactly once, for
 *        the very first block of a hash computation.
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

/*******************************************************************************
 * Include files
 ******************************************************************************/
#include "hc32_ll_hash_ex.h"
#include "hc32_ll_utility.h"

/**
 * @addtogroup LL_Driver
 * @{
 */

/**
 * @defgroup LL_HASH_EX HASH Extension
 * @{
 */

#if (LL_HASH_ENABLE == DDL_ON)

/*******************************************************************************
 * Local pre-processor symbols/macros ('#define')
 ******************************************************************************/
/**
 * @defgroup HASH_EX_Local_Macros HASH_EX Local Macros
 * @{
 */
#define HASH_EX_GROUP_SIZE              (64U)
#define HASH_EX_GROUP_SIZE_WORD         (HASH_EX_GROUP_SIZE / 4U)
#define HASH_EX_LAST_GROUP_SIZE_MAX     (56U)   /* 512 - 64 - 448 = 56 */
#define HASH_EX_TIMEOUT                 (6000U)
#define HASH_EX_MSG_DIGEST_SIZE_WORD    (8U)    /* 32-byte digest / 4 */

#define HASH_EX_KEY_LONG_SIZE           (64U)   /* SHA256 block size */
#define HASH_EX_IPAD                    (0x36U)
#define HASH_EX_OPAD                    (0x5CU)
/**
 * @}
 */

/*******************************************************************************
 * Local function prototypes ('static')
 ******************************************************************************/
static int32_t  HASH_EX_WaitStart(void);
static void     HASH_EX_WriteBlock(const uint8_t *pu8Data);
static void     HASH_EX_MemSet(uint8_t *pDest, uint8_t val, uint32_t len);
static void     HASH_EX_MemCopy(uint8_t *pDest, const uint8_t *pSrc, uint32_t len);
static int32_t  HASH_EX_SubmitBlock(const uint8_t *pu8Data, uint8_t bFirst);
static int32_t  HASH_EX_PadAndFinalize(stc_hash_ctx_t *pCtx);
static void     HASH_EX_ReadDigest(uint8_t *pu8MsgDigest);

/*******************************************************************************
 * Function implementation - local ('static')
 ******************************************************************************/

/**
 * @brief  Poll until the HASH hardware finishes a START-triggered operation.
 *         Times out after HASH_EX_TIMEOUT iterations.
 * @retval int32_t:
 *           - LL_OK:           HASH_CR_START bit cleared (hardware idle)
 *           - LL_ERR_TIMEOUT:  Timeout
 */
static int32_t HASH_EX_WaitStart(void)
{
    uint32_t u32TimeOut = HASH_EX_TIMEOUT;
    while (READ_REG32_BIT(CM_HASH->CR, HASH_CR_START) != 0UL) {
        if (--u32TimeOut == 0UL) {
            return LL_ERR_TIMEOUT;
        }
    }
    return LL_OK;
}

/**
 * @brief  Write exactly one 64-byte block to the HASH data registers.
 *         Hardware stores big-endian 32-bit words, so __REV is applied.
 * @param  [in] pu8Data  Pointer to a 64-byte buffer.
 * @retval None
 */
static void HASH_EX_WriteBlock(const uint8_t *pu8Data)
{
    /* HC32F448 HASH: data words DR15..DR0 = word 0..15 */
    __IO uint32_t *regDR = &CM_HASH->DR15;
    const uint32_t *pu32Data = (const uint32_t *)pu8Data;
    for (uint8_t i = 0U; i < HASH_EX_GROUP_SIZE_WORD; i++) {
        regDR[i] = __REV(pu32Data[i]);
    }
}

static void HASH_EX_MemSet(uint8_t *pDest, uint8_t val, uint32_t len)
{
    while (len--) {
        *pDest++ = val;
    }
}

static void HASH_EX_MemCopy(uint8_t *pDest, const uint8_t *pSrc, uint32_t len)
{
    while (len--) {
        *pDest++ = *pSrc++;
    }
}

/**
 * @brief  Submit one ready-to-hash 64-byte block to the hardware.
 *         Handles FST_GRP (set once for the very first block of a new hash,
 *         cleared for all subsequent blocks) and waits for completion.
 * @param  [in] pu8Data  64-byte block already padded if this is the final one
 * @param  [in] bFirst   1 = this is the first block of a new hash run, 0 = continuation
 * @retval int32_t:
 *           - LL_OK:          Hardware consumed the block
 *           - LL_ERR_TIMEOUT: Hardware did not finish in time
 */
static int32_t HASH_EX_SubmitBlock(const uint8_t *pu8Data, uint8_t bFirst)
{
    HASH_EX_WriteBlock(pu8Data);

    if (bFirst != 0U) {
        /* Start brand-new hash from initial SHA256 state */
        WRITE_REG32(bCM_HASH->CR_b.FST_GRP, 1U);
    } else {
        /* Continue from previous running state in HR registers */
        WRITE_REG32(bCM_HASH->CR_b.FST_GRP, 0U);
    }

    WRITE_REG32(bCM_HASH->CR_b.START, 1U);
    return HASH_EX_WaitStart();
}

/**
 * @brief  Pad the given SHA256 context buffer per FIPS 180-4 and submit the
 *         final block(s) to the hardware. Updates pCtx->started accordingly
 *         so that FST_GRP is set correctly on first finalization of a single-
 *         block message.
 *
 *         Padding rule:
 *           - Append 0x80, then pad zeros until position 56 mod 64.
 *           - Append 64-bit BIG-ENDIAN total message length in bits.
 *           - If the message already occupies >= 56 bytes, we write TWO
 *             blocks: one with 0x80 + zeros (to avoid colliding with the
 *             length field), then one with zeros + 64-bit length.
 *
 * @param  [in,out] pCtx  SHA256 context whose current buffer will be padded
 *                        and flushed. On return, pCtx->finished is set.
 * @retval int32_t:
 *           - LL_OK:          Finalization complete; HR registers hold digest
 *           - LL_ERR_TIMEOUT: Hardware failed to finish
 */
static int32_t HASH_EX_PadAndFinalize(stc_hash_ctx_t *pCtx)
{
    uint8_t  fillBuf[HASH_EX_GROUP_SIZE];
    uint32_t len = pCtx->buffer_len;
    int32_t  ret;

    /* total bit-length, big-endian */
    uint64_t bitLen = pCtx->total_len << 3;

    if (len < HASH_EX_LAST_GROUP_SIZE_MAX) {
        /* One padded block is enough */
        HASH_EX_MemSet(fillBuf, 0U, HASH_EX_GROUP_SIZE);
        if (len > 0U) {
            HASH_EX_MemCopy(fillBuf, pCtx->buffer, len);
        }
        fillBuf[len] = 0x80U;

        for (uint8_t i = 0U; i < 8U; i++) {
            /* byte 56+i holds bits (63-(i*8)) down to (56-(i*8)) */
            fillBuf[HASH_EX_LAST_GROUP_SIZE_MAX + i] =
                (uint8_t)(bitLen >> ((7U - i) * 8U));
        }

        ret = HASH_EX_SubmitBlock(fillBuf, (pCtx->started == 0U) ? 1U : 0U);
        if (ret != LL_OK) {
            return ret;
        }
    } else {
        /* len >= 56: 0x80 lands in the length-field region, so we need TWO
           blocks: block-1 ends with 0x80 + zeros, block-2 is all zeros except
           for the 8-byte big-endian length field at the tail. */

        /* Block 1: data + 0x80 + zeros */
        HASH_EX_MemSet(fillBuf, 0U, HASH_EX_GROUP_SIZE);
        HASH_EX_MemCopy(fillBuf, pCtx->buffer, len);
        fillBuf[len] = 0x80U;

        ret = HASH_EX_SubmitBlock(fillBuf, (pCtx->started == 0U) ? 1U : 0U);
        if (ret != LL_OK) {
            return ret;
        }

        /* Block 2: zeros + 64-bit big-endian length */
        HASH_EX_MemSet(fillBuf, 0U, HASH_EX_GROUP_SIZE);
        for (uint8_t i = 0U; i < 8U; i++) {
            fillBuf[HASH_EX_LAST_GROUP_SIZE_MAX + i] =
                (uint8_t)(bitLen >> ((7U - i) * 8U));
        }

        ret = HASH_EX_SubmitBlock(fillBuf, 0U);
        if (ret != LL_OK) {
            return ret;
        }
    }

    pCtx->finished = 1U;
    return LL_OK;
}

/**
 * @brief  Read the 32-byte message digest from HASH hardware registers.
 *         HC32F448 stores the digest in HR7..HR0 (8 x 32-bit words, big-endian).
 * @param  [out] pu8MsgDigest  Pointer to at least 32 bytes of output buffer.
 * @retval None
 */
static void HASH_EX_ReadDigest(uint8_t *pu8MsgDigest)
{
    __IO uint32_t *regHR = &CM_HASH->HR7;
    uint32_t *pDigest = (uint32_t *)pu8MsgDigest;
    for (uint8_t i = 0U; i < HASH_EX_MSG_DIGEST_SIZE_WORD; i++) {
        pDigest[i] = __REV(regHR[i]);
    }
}

/*******************************************************************************
 * Function implementation - global ('extern')
 ******************************************************************************/

/**
 * @defgroup HASH_EX_Global_Functions HASH Extension Global Functions
 * @{
 */

/* ==================== SHA256 streaming API ==================== */

int32_t HASH_Init_Ex(stc_hash_ctx_t *pCtx)
{
    if (pCtx == NULL) {
        return LL_ERR_INVD_PARAM;
    }

    /* Reset HASH hardware completely */
    if (HASH_DeInit() != LL_OK) {
        return LL_ERR_TIMEOUT;
    }

    /* Zero the context */
    pCtx->buffer_len = 0U;
    pCtx->total_len  = 0UL;
    pCtx->started    = 0U;
    pCtx->finished   = 0U;
    HASH_EX_MemSet(pCtx->buffer, 0U, HASH_EX_GROUP_SIZE);

    /* Hardware is already in SHA256 mode (this chip has no HMAC mode bit).
       FST_GRP will be set on the first SubmitBlock call. */
    return LL_OK;
}

int32_t HASH_Update_Ex(stc_hash_ctx_t *pCtx, const uint8_t *pData, uint32_t u32Len)
{
    int32_t  ret;
    uint32_t offset = 0U;

    if ((pCtx == NULL) || (pData == NULL) || (u32Len == 0U)) {
        return LL_ERR_INVD_PARAM;
    }
    if (pCtx->finished != 0U) {
        return LL_ERR_INVD_PARAM;
    }

    pCtx->total_len += u32Len;

    while (offset < u32Len) {
        uint32_t space = HASH_EX_GROUP_SIZE - pCtx->buffer_len;
        uint32_t copy  = ((u32Len - offset) < space) ? (u32Len - offset) : space;

        HASH_EX_MemCopy(&pCtx->buffer[pCtx->buffer_len], &pData[offset], copy);
        pCtx->buffer_len += copy;
        offset += copy;

        if (pCtx->buffer_len == HASH_EX_GROUP_SIZE) {
            ret = HASH_EX_SubmitBlock(pCtx->buffer, (pCtx->started == 0U) ? 1U : 0U);
            if (ret != LL_OK) {
                return ret;
            }
            pCtx->started    = 1U;
            pCtx->buffer_len = 0U;
        }
    }

    return LL_OK;
}

int32_t HASH_Final_Ex(stc_hash_ctx_t *pCtx, uint8_t *pu8MsgDigest)
{
    int32_t ret;

    if ((pCtx == NULL) || (pu8MsgDigest == NULL)) {
        return LL_ERR_INVD_PARAM;
    }
    if (pCtx->finished != 0U) {
        return LL_ERR_INVD_PARAM;
    }

    ret = HASH_EX_PadAndFinalize(pCtx);
    if (ret != LL_OK) {
        return ret;
    }

    HASH_EX_ReadDigest(pu8MsgDigest);
    return LL_OK;
}

/* ==================== HMAC-SHA256 streaming API (RFC 2104) ==================== */

/*
 * HMAC(K, m) = H( (K' XOR opad) || H( (K' XOR ipad) || m ) )
 *
 * On HC32F448 the HASH hardware has no HMAC mode, so HMAC is implemented as
 * two streaming SHA256 rounds:
 *   Phase 1 (inner): feed ipad_key || message → inner_hash  (streamed)
 *   Phase 2 (outer): feed opad_key || inner_hash → final HMAC digest
 */

int32_t HMAC_Init_Ex(stc_hmac_ctx_t *pCtx, const uint8_t *pKey, uint32_t u32KeyLen)
{
    int32_t ret;

    if ((pCtx == NULL) || (pKey == NULL) || (u32KeyLen == 0U)) {
        return LL_ERR_INVD_PARAM;
    }

    /* Step 1: RFC 2104 key preprocessing → k0[64] */
    if (u32KeyLen > HASH_EX_KEY_LONG_SIZE) {
        /* k0 = H(key), right-padded with zeros to 64 B */
        ret = HASH_Calculate(pKey, u32KeyLen, pCtx->k0);
        if (ret != LL_OK) {
            return ret;
        }
        HASH_EX_MemSet(pCtx->k0 + 32U, 0U, HASH_EX_KEY_LONG_SIZE - 32U);
    } else {
        /* k0 = key || zeros */
        HASH_EX_MemCopy(pCtx->k0, pKey, u32KeyLen);
        HASH_EX_MemSet(pCtx->k0 + u32KeyLen, 0U, HASH_EX_KEY_LONG_SIZE - u32KeyLen);
    }

    /* Step 2: reset HASH hardware */
    if (HASH_DeInit() != LL_OK) {
        return LL_ERR_TIMEOUT;
    }

    /* Step 3: send the first inner block = k0 XOR ipad (= k0 ^ 0x36 repeated) */
    {
        uint8_t ipadBlock[HASH_EX_GROUP_SIZE];
        for (uint8_t i = 0U; i < HASH_EX_GROUP_SIZE; i++) {
            ipadBlock[i] = (uint8_t)(pCtx->k0[i] ^ HASH_EX_IPAD);
        }

        ret = HASH_EX_SubmitBlock(ipadBlock, 1U);
        if (ret != LL_OK) {
            return ret;
        }
    }

    /* Step 4: initialize inner hash state.
       total_len = 64 accounts for the ipad block we just sent; message bytes
       added later by HMAC_Update_Ex bump this further. */
    pCtx->inner_ctx.buffer_len = 0U;
    pCtx->inner_ctx.total_len  = HASH_EX_GROUP_SIZE;
    pCtx->inner_ctx.started    = 1U;   /* ipad block already submitted */
    pCtx->inner_ctx.finished   = 0U;
    HASH_EX_MemSet(pCtx->inner_ctx.buffer, 0U, HASH_EX_GROUP_SIZE);

    /* outer_ctx is not used; we compute the outer hash inline in Final */
    pCtx->state = 1U;
    return LL_OK;
}

int32_t HMAC_Update_Ex(stc_hmac_ctx_t *pCtx, const uint8_t *pData, uint32_t u32Len)
{
    int32_t  ret;
    uint32_t offset = 0U;

    if (pCtx == NULL) {
        return LL_ERR_INVD_PARAM;
    }
    if (pCtx->state != 1U) {
        return LL_ERR_INVD_PARAM;
    }
    if ((pData == NULL) && (u32Len != 0U)) {
        return LL_ERR_INVD_PARAM;
    }
    if (u32Len == 0U) {
        return LL_OK;
    }

    /* total_len tracks inner hash input length = 64 (ipad) + message */
    pCtx->inner_ctx.total_len += u32Len;

    while (offset < u32Len) {
        uint32_t space = HASH_EX_GROUP_SIZE - pCtx->inner_ctx.buffer_len;
        uint32_t copy  = ((u32Len - offset) < space) ? (u32Len - offset) : space;

        HASH_EX_MemCopy(&pCtx->inner_ctx.buffer[pCtx->inner_ctx.buffer_len],
                        &pData[offset],
                        copy);
        pCtx->inner_ctx.buffer_len += copy;
        offset += copy;

        if (pCtx->inner_ctx.buffer_len == HASH_EX_GROUP_SIZE) {
            ret = HASH_EX_SubmitBlock(pCtx->inner_ctx.buffer, 0U);
            if (ret != LL_OK) {
                return ret;
            }
            pCtx->inner_ctx.buffer_len = 0U;
        }
    }

    return LL_OK;
}

int32_t HMAC_Final_Ex(stc_hmac_ctx_t *pCtx, uint8_t *pu8MsgDigest)
{
    int32_t  ret;
    uint8_t  innerHash[32];
    uint8_t  opadBlock[HASH_EX_GROUP_SIZE];

    if ((pCtx == NULL) || (pu8MsgDigest == NULL)) {
        return LL_ERR_INVD_PARAM;
    }
    if (pCtx->state != 1U) {
        return LL_ERR_INVD_PARAM;
    }

    /* =========================================================
       Phase 1: finalize inner hash → inner_hash[32]
       ========================================================= */
    ret = HASH_EX_PadAndFinalize(&pCtx->inner_ctx);
    if (ret != LL_OK) {
        return ret;
    }
    HASH_EX_ReadDigest(innerHash);

    /* =========================================================
       Phase 2: compute outer hash = H( (k0 XOR opad) || inner_hash )
       ========================================================= */

    /* 2a. reset hardware for a brand-new hash run */
    if (HASH_DeInit() != LL_OK) {
        return LL_ERR_TIMEOUT;
    }

    /* 2b. first outer block = k0 XOR opad (= k0 ^ 0x5C repeated) */
    for (uint8_t i = 0U; i < HASH_EX_GROUP_SIZE; i++) {
        opadBlock[i] = (uint8_t)(pCtx->k0[i] ^ HASH_EX_OPAD);
    }
    ret = HASH_EX_SubmitBlock(opadBlock, 1U);
    if (ret != LL_OK) {
        return ret;
    }

    /* 2c. inner_hash is 32 bytes — feed it into a temp ctx so we can use
       HASH_EX_PadAndFinalize's logic */
    {
        stc_hash_ctx_t outerCtx;
        outerCtx.buffer_len = 32U;
        outerCtx.total_len  = HASH_EX_GROUP_SIZE + 32U;   /* 64 (opad) + 32 (inner_hash) */
        outerCtx.started    = 1U;                         /* opad block already sent */
        outerCtx.finished   = 0U;
        HASH_EX_MemCopy(outerCtx.buffer, innerHash, 32U);
        HASH_EX_MemSet(outerCtx.buffer + 32U, 0U, HASH_EX_GROUP_SIZE - 32U);

        ret = HASH_EX_PadAndFinalize(&outerCtx);
        if (ret != LL_OK) {
            return ret;
        }
    }

    /* 2d. read final HMAC digest */
    HASH_EX_ReadDigest(pu8MsgDigest);

    pCtx->state = 2U;
    return LL_OK;
}

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
/*******************************************************************************
 * EOF (not truncated)
 ******************************************************************************/
