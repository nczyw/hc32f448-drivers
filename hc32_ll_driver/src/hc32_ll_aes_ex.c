/**
 *******************************************************************************
 * @file  hc32_ll_aes_ex.c
 * @brief Context-based streaming AES (ECB / CBC / CTR) for HC32F448.
 *
 *        HC32F448's AES hardware implements only the bare ECB block cipher
 *        (START + MODE + KEYSIZE in CR). ECB / CBC / CTR are composed in
 *        software over the same hardware START cycle — every 16-byte block
 *        of the plain chain ultimately goes through a single hardware AES
 *        encryption or decryption.
 *
 *        All session state (key, IV/CTR, partial block buffer, CTR keystream
 *        leftovers) lives in caller-owned @ref stc_aes_ctx_t. Each ctx is
 *        independent, so multiple AES sessions may coexist concurrently as
 *        long as the caller serialises hardware access (e.g. with a mutex
 *        around Init_Ex / Update_Ex / Final_Ex).
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
#include "hc32_ll_aes_ex.h"
#include "hc32_ll_utility.h"

/**
 * @addtogroup LL_Driver
 * @{
 */

/**
 * @defgroup LL_AES_EX AES Extension
 * @{
 */

#if (LL_AES_ENABLE == DDL_ON)

/*******************************************************************************
 * Local pre-processor symbols/macros ('#define')
 ******************************************************************************/
/**
 * @defgroup AES_EX_Local_Macros AES_EX Local Macros
 * @{
 */
#define AES_EX_BLOCK_SIZE               (16U)
#define AES_EX_BLOCK_SIZE_WORD          (AES_EX_BLOCK_SIZE / 4U)   /* 4 */
#define AES_EX_TIMEOUT                  (30000UL)

#define AES_EX_KEY_SIZE_128_CODE        (0U)
#define AES_EX_KEY_SIZE_192_CODE        (1U)
#define AES_EX_KEY_SIZE_256_CODE        (2U)
/**
 * @}
 */

/*******************************************************************************
 * Local function prototypes ('static')
 ******************************************************************************/
static int32_t  AES_EX_WriteKeyAndMode(const uint8_t *pu8Key, uint8_t key_size,
                                        stc_aes_dir_t dir);
static int32_t  AES_EX_RunBlock(const uint8_t *pu8In, uint8_t *pu8Out);
static int32_t  AES_EX_RunBlockEnc(const uint8_t *pu8In, uint8_t *pu8Out);
static int32_t  AES_EX_RunBlockDec(const uint8_t *pu8In, uint8_t *pu8Out);
static void     AES_EX_XorBlocks(const uint8_t *a, const uint8_t *b, uint8_t *out);
static void     AES_EX_CtrIncrement(uint8_t *ctr);
static void     AES_EX_MemSet(uint8_t *pDest, uint8_t val, uint32_t len);
static void     AES_EX_MemCopy(uint8_t *pDest, const uint8_t *pSrc, uint32_t len);
static void     AES_EX_ZeroKey(stc_aes_ctx_t *pCtx);
static uint8_t  AES_EX_PadPKCS7(const uint8_t *pBlock, uint8_t block_size);

/*******************************************************************************
 * Function implementation - local ('static')
 ******************************************************************************/

/**
 * @brief  Program the AES hardware with the current key and direction.
 *
 *         Must be called once before the first RunBlock of a session.
 *         Hardware does not cache this state across AES_DeInit, so this
 *         also has to be re-issued after DeInit or after another context
 *         has overwritten the key/registers.
 *
 * @retval LL_OK or LL_ERR_TIMEOUT (hardware still busy).
 */
static int32_t AES_EX_WriteKeyAndMode(const uint8_t *pu8Key, uint8_t key_size,
                                       stc_aes_dir_t dir)
{
    uint8_t  u8KeyWordSize;
    uint32_t u32KeyCode;
    __IO uint32_t *regKR = &CM_AES->KR0;
    const uint32_t *pu32Key = (const uint32_t *)pu8Key;

    u8KeyWordSize = key_size / 4U;
    for (uint8_t i = 0U; i < u8KeyWordSize; i++) {
        regKR[i] = pu32Key[i];
    }

    switch (key_size) {
        case AES_KEY_SIZE_16BYTE: u32KeyCode = AES_EX_KEY_SIZE_128_CODE; break;
        case AES_KEY_SIZE_24BYTE: u32KeyCode = AES_EX_KEY_SIZE_192_CODE; break;
        case AES_KEY_SIZE_32BYTE: u32KeyCode = AES_EX_KEY_SIZE_256_CODE; break;
        default:                  return LL_ERR_INVD_PARAM;
    }

    /* KEYSIZE + MODE.  Start bit must remain 0 when programming register. */
    MODIFY_REG32(CM_AES->CR,
                 AES_CR_KEYSIZE | AES_CR_MODE,
                 (u32KeyCode << AES_CR_KEYSIZE_POS) | ((uint32_t)dir << AES_CR_MODE_POS));

    /* Wait any in-flight run to settle */
    uint32_t t = AES_EX_TIMEOUT;
    while (READ_REG32_BIT(CM_AES->CR, AES_CR_START) != 0UL) {
        if (--t == 0UL) return LL_ERR_TIMEOUT;
    }
    return LL_OK;
}

/**
 * @brief  Wait hardware idle, then write 16B to DR0..DR3, START, wait done,
 *         read 16B from DR0..DR3. Direction depends on the previously programmed
 *         AES_CR_MODE bit.
 *
 * @retval LL_OK or LL_ERR_TIMEOUT
 */
static int32_t AES_EX_RunBlock(const uint8_t *pu8In, uint8_t *pu8Out)
{
    uint32_t t;

    /* Wait previous operation to finish */
    t = AES_EX_TIMEOUT;
    while (READ_REG32_BIT(CM_AES->CR, AES_CR_START) != 0UL) {
        if (--t == 0UL) return LL_ERR_TIMEOUT;
    }

    /* Write 16B input block */
    __IO uint32_t *regDR = &CM_AES->DR0;
    const uint32_t *pu32In = (const uint32_t *)pu8In;
    for (uint8_t i = 0U; i < AES_EX_BLOCK_SIZE_WORD; i++) {
        regDR[i] = pu32In[i];
    }

    /* START */
    SET_REG32_BIT(CM_AES->CR, AES_CR_START);

    /* Wait finish */
    t = AES_EX_TIMEOUT;
    while (READ_REG32_BIT(CM_AES->CR, AES_CR_START) != 0UL) {
        if (--t == 0UL) return LL_ERR_TIMEOUT;
    }

    /* Read 16B output */
    uint32_t *pu32Out = (uint32_t *)pu8Out;
    regDR = &CM_AES->DR0;
    for (uint8_t i = 0U; i < AES_EX_BLOCK_SIZE_WORD; i++) {
        pu32Out[i] = regDR[i];
    }

    return LL_OK;
}

static int32_t AES_EX_RunBlockEnc(const uint8_t *pu8In, uint8_t *pu8Out)
{
    return AES_EX_RunBlock(pu8In, pu8Out);
}

static int32_t AES_EX_RunBlockDec(const uint8_t *pu8In, uint8_t *pu8Out)
{
    return AES_EX_RunBlock(pu8In, pu8Out);
}

static void AES_EX_XorBlocks(const uint8_t *a, const uint8_t *b, uint8_t *out)
{
    for (uint8_t i = 0U; i < AES_EX_BLOCK_SIZE; i++) {
        out[i] = (uint8_t)(a[i] ^ b[i]);
    }
}

/**
 * @brief  Increment a 128-bit counter in big-endian order. Overflow from byte[15]
 *         propagates towards byte[0]; all-zero wraps back to all-ones in a
 *         well-defined way. Caller decides what each word means — we just add
 *         1 to the 128-bit integer.
 */
static void AES_EX_CtrIncrement(uint8_t *ctr)
{
    for (int8_t i = (int8_t)(AES_EX_BLOCK_SIZE - 1U); i >= 0; i--) {
        ctr[i]++;
        if (ctr[i] != 0U) break;
    }
}

static void AES_EX_MemSet(uint8_t *pDest, uint8_t val, uint32_t len)
{
    while (len--) *pDest++ = val;
}

static void AES_EX_MemCopy(uint8_t *pDest, const uint8_t *pSrc, uint32_t len)
{
    while (len--) *pDest++ = *pSrc++;
}

/**
 * @brief  Zero the key buffer inside a finished context.  Helper that makes
 *         it easy to audit "keys never linger in RAM" across all exit paths.
 */
static void AES_EX_ZeroKey(stc_aes_ctx_t *pCtx)
{
    AES_EX_MemSet(pCtx->key, 0U, 32U);
    AES_EX_MemSet(pCtx->iv_or_ctr, 0U, AES_EX_BLOCK_SIZE);
    AES_EX_MemSet(pCtx->buffer, 0U, AES_EX_BLOCK_SIZE);
    AES_EX_MemSet(pCtx->ks, 0U, AES_EX_BLOCK_SIZE);
    pCtx->key_size  = 0U;
    pCtx->buffer_len = 0U;
    pCtx->ks_len    = 0U;
}

/**
 * @brief  Check PKCS#7 padding on the LAST decrypted 16-byte block.
 *
 *         Returns the number of valid *unpadded* bytes (= block_size - pad) on
 *         success, or 0 if padding is malformed (invalid pad value or mismatched
 *         trailing bytes).
 */
static uint8_t AES_EX_PadPKCS7(const uint8_t *pBlock, uint8_t block_size)
{
    uint8_t pad = pBlock[block_size - 1U];
    if ((pad == 0U) || (pad > block_size)) {
        return 0U;
    }
    for (uint8_t i = 0U; i < pad; i++) {
        if (pBlock[block_size - 1U - i] != pad) {
            return 0U;
        }
    }
    return (uint8_t)(block_size - pad);
}

/*******************************************************************************
 * Function implementation - global ('extern')
 ******************************************************************************/

/**
 * @defgroup AES_EX_Global_Functions AES Extension Global Functions
 * @{
 */

int32_t AES_Init_Ex(stc_aes_ctx_t *pCtx,
                    stc_aes_mode_t mode,
                    stc_aes_dir_t  dir,
                    const uint8_t *pKey,
                    uint8_t        key_size,
                    const uint8_t *pIV)
{
    int32_t ret;

    if ((pCtx == NULL) || (pKey == NULL)) {
        return LL_ERR_INVD_PARAM;
    }
    if ((key_size != AES_KEY_SIZE_16BYTE) &&
        (key_size != AES_KEY_SIZE_24BYTE) &&
        (key_size != AES_KEY_SIZE_32BYTE)) {
        return LL_ERR_INVD_PARAM;
    }
    if ((mode == AES_EX_MODE_CBC) || (mode == AES_EX_MODE_CTR)) {
        if (pIV == NULL) return LL_ERR_INVD_PARAM;
    }

    /* Hardware must be idle before we start touching it. AES_DeInit resets the
       peripheral; if it times out we cannot proceed. */
    if (AES_DeInit() != LL_OK) {
        return LL_ERR_TIMEOUT;
    }

    /* Persist session state into the caller-owned ctx */
    pCtx->mode = mode;
    /* CTR always uses encrypt direction to generate keystream */
    pCtx->dir  = (mode == AES_EX_MODE_CTR) ? AES_EX_DIR_ENCRYPT : dir;

    AES_EX_MemCopy(pCtx->key, pKey, key_size);
    pCtx->key_size = key_size;

    if (pIV != NULL) {
        AES_EX_MemCopy(pCtx->iv_or_ctr, pIV, AES_EX_BLOCK_SIZE);
    } else {
        AES_EX_MemSet(pCtx->iv_or_ctr, 0U, AES_EX_BLOCK_SIZE);
    }

    pCtx->buffer_len = 0U;
    pCtx->ks_len     = 0U;
    pCtx->state      = 1U;

    /* Program key + direction into hardware */
    ret = AES_EX_WriteKeyAndMode(pCtx->key, key_size, pCtx->dir);
    if (ret != LL_OK) {
        AES_EX_ZeroKey(pCtx);
        pCtx->state = 0U;
        return ret;
    }

    return LL_OK;
}

/* ---------- ECB encrypt ---------- */
static int32_t AES_Update_ECB_Enc(stc_aes_ctx_t *pCtx,
                                   const uint8_t *pIn, uint32_t u32InLen,
                                   uint8_t *pOut, uint32_t *pu32OutLen)
{
    int32_t ret;
    uint32_t out_off = 0U;

    for (uint32_t i = 0U; i < u32InLen; i++) {
        pCtx->buffer[pCtx->buffer_len++] = pIn[i];
        if (pCtx->buffer_len == AES_EX_BLOCK_SIZE) {
            ret = AES_EX_RunBlockEnc(pCtx->buffer, &pOut[out_off]);
            if (ret != LL_OK) return ret;
            out_off += AES_EX_BLOCK_SIZE;
            pCtx->buffer_len = 0U;
        }
    }
    *pu32OutLen = out_off;
    return LL_OK;
}

/* ---------- ECB decrypt ---------- */
static int32_t AES_Update_ECB_Dec(stc_aes_ctx_t *pCtx,
                                   const uint8_t *pIn, uint32_t u32InLen,
                                   uint8_t *pOut, uint32_t *pu32OutLen)
{
    int32_t ret;
    uint32_t out_off = 0U;

    for (uint32_t i = 0U; i < u32InLen; i++) {
        pCtx->buffer[pCtx->buffer_len++] = pIn[i];
        if (pCtx->buffer_len == AES_EX_BLOCK_SIZE) {
            ret = AES_EX_RunBlockDec(pCtx->buffer, &pOut[out_off]);
            if (ret != LL_OK) return ret;
            out_off += AES_EX_BLOCK_SIZE;
            pCtx->buffer_len = 0U;
        }
    }
    *pu32OutLen = out_off;
    return LL_OK;
}

/* ---------- CBC encrypt ---------- */
static int32_t AES_Update_CBC_Enc(stc_aes_ctx_t *pCtx,
                                   const uint8_t *pIn, uint32_t u32InLen,
                                   uint8_t *pOut, uint32_t *pu32OutLen)
{
    int32_t ret;
    uint32_t out_off = 0U;
    uint8_t tmp[AES_EX_BLOCK_SIZE];

    for (uint32_t i = 0U; i < u32InLen; i++) {
        pCtx->buffer[pCtx->buffer_len++] = pIn[i];
        if (pCtx->buffer_len == AES_EX_BLOCK_SIZE) {
            /* plaintext XOR chain_state -> encrypt */
            AES_EX_XorBlocks(pCtx->buffer, pCtx->iv_or_ctr, tmp);
            ret = AES_EX_RunBlockEnc(tmp, &pOut[out_off]);
            if (ret != LL_OK) return ret;
            /* ciphertext becomes next chain state */
            AES_EX_MemCopy(pCtx->iv_or_ctr, &pOut[out_off], AES_EX_BLOCK_SIZE);
            out_off += AES_EX_BLOCK_SIZE;
            pCtx->buffer_len = 0U;
        }
    }
    *pu32OutLen = out_off;
    return LL_OK;
}

/* ---------- CBC decrypt ---------- */
static int32_t AES_Update_CBC_Dec(stc_aes_ctx_t *pCtx,
                                   const uint8_t *pIn, uint32_t u32InLen,
                                   uint8_t *pOut, uint32_t *pu32OutLen)
{
    int32_t ret;
    uint32_t out_off = 0U;
    uint8_t decBlock[AES_EX_BLOCK_SIZE];
    uint8_t chainCopy[AES_EX_BLOCK_SIZE];

    for (uint32_t i = 0U; i < u32InLen; i++) {
        pCtx->buffer[pCtx->buffer_len++] = pIn[i];
        if (pCtx->buffer_len == AES_EX_BLOCK_SIZE) {
            /* Remember this ciphertext block BEFORE decrypting it */
            AES_EX_MemCopy(chainCopy, pCtx->buffer, AES_EX_BLOCK_SIZE);

            ret = AES_EX_RunBlockDec(pCtx->buffer, decBlock);
            if (ret != LL_OK) return ret;

            /* plaintext = decrypted XOR previous ciphertext (chain state) */
            AES_EX_XorBlocks(decBlock, pCtx->iv_or_ctr, &pOut[out_off]);

            /* advance chain state to ciphertext we just processed */
            AES_EX_MemCopy(pCtx->iv_or_ctr, chainCopy, AES_EX_BLOCK_SIZE);
            out_off += AES_EX_BLOCK_SIZE;
            pCtx->buffer_len = 0U;
        }
    }
    *pu32OutLen = out_off;
    return LL_OK;
}

/* ---------- CTR shared encrypt / decrypt (same math: XOR plaintext with keystream) ---------- */
static int32_t AES_Update_CTR(stc_aes_ctx_t *pCtx,
                              const uint8_t *pIn, uint32_t u32InLen,
                              uint8_t *pOut, uint32_t *pu32OutLen)
{
    int32_t ret;
    uint32_t out_off = 0U;

    for (uint32_t i = 0U; i < u32InLen; i++) {
        if (pCtx->ks_len == 0U) {
            /* generate next keystream block */
            ret = AES_EX_RunBlockEnc(pCtx->iv_or_ctr, pCtx->ks);
            if (ret != LL_OK) return ret;
            pCtx->ks_len = AES_EX_BLOCK_SIZE;
            AES_EX_CtrIncrement(pCtx->iv_or_ctr);
        }
        pOut[out_off++] = (uint8_t)(pIn[i] ^ pCtx->ks[AES_EX_BLOCK_SIZE - pCtx->ks_len]);
        pCtx->ks_len--;
    }
    *pu32OutLen = out_off;
    return LL_OK;
}

int32_t AES_Update_Ex(stc_aes_ctx_t *pCtx,
                       const uint8_t *pIn,  uint32_t u32InLen,
                       uint8_t       *pOut, uint32_t *pu32OutLen)
{
    if (pCtx == NULL)       return LL_ERR_INVD_PARAM;
    if (pCtx->state != 1U)  return LL_ERR_INVD_PARAM;
    if (pOut == NULL)       return LL_ERR_INVD_PARAM;
    if (pu32OutLen == NULL) return LL_ERR_INVD_PARAM;

    *pu32OutLen = 0U;

    if (u32InLen == 0U)     return LL_OK;
    if (pIn == NULL)        return LL_ERR_INVD_PARAM;

    switch (pCtx->mode) {
        case AES_EX_MODE_ECB:
            return (pCtx->dir == AES_EX_DIR_ENCRYPT)
                ? AES_Update_ECB_Enc(pCtx, pIn, u32InLen, pOut, pu32OutLen)
                : AES_Update_ECB_Dec(pCtx, pIn, u32InLen, pOut, pu32OutLen);

        case AES_EX_MODE_CBC:
            return (pCtx->dir == AES_EX_DIR_ENCRYPT)
                ? AES_Update_CBC_Enc(pCtx, pIn, u32InLen, pOut, pu32OutLen)
                : AES_Update_CBC_Dec(pCtx, pIn, u32InLen, pOut, pu32OutLen);

        case AES_EX_MODE_CTR:
            return AES_Update_CTR(pCtx, pIn, u32InLen, pOut, pu32OutLen);

        default:
            return LL_ERR_INVD_PARAM;
    }
}

/* ---------- Final helpers ---------- */

/** ECB / CBC encrypt final: PKCS#7 pad the partial block and emit 1 or 2 blocks. */
static int32_t AES_Final_BlockEnc(stc_aes_ctx_t *pCtx,
                                   uint8_t *pOut, uint32_t *pu32OutLen)
{
    int32_t ret;
    uint32_t out_off = 0U;
    uint8_t pad, tmp[AES_EX_BLOCK_SIZE];

    pad = (uint8_t)(AES_EX_BLOCK_SIZE - pCtx->buffer_len);

    /* first block = partial data + PKCS#7 pad */
    for (uint8_t i = 0U; i < AES_EX_BLOCK_SIZE; i++) {
        tmp[i] = (i < pCtx->buffer_len) ? pCtx->buffer[i] : pad;
    }

    if (pCtx->mode == AES_EX_MODE_CBC) {
        AES_EX_XorBlocks(tmp, pCtx->iv_or_ctr, tmp);
    }

    ret = AES_EX_RunBlockEnc(tmp, &pOut[out_off]);
    if (ret != LL_OK) return ret;
    out_off += AES_EX_BLOCK_SIZE;

    /* If pad == 16, we just emitted a full pad block — standard PKCS#7 requires
       a *second* full padding block to signal "the last plaintext byte was already
       in a block and we need a marker block". */
    if (pad == AES_EX_BLOCK_SIZE) {
        AES_EX_MemSet(tmp, AES_EX_BLOCK_SIZE, AES_EX_BLOCK_SIZE);
        if (pCtx->mode == AES_EX_MODE_CBC) {
            AES_EX_XorBlocks(tmp, &pOut[out_off - AES_EX_BLOCK_SIZE], tmp);
        }
        ret = AES_EX_RunBlockEnc(tmp, &pOut[out_off]);
        if (ret != LL_OK) return ret;
        out_off += AES_EX_BLOCK_SIZE;
    }

    *pu32OutLen = out_off;
    return LL_OK;
}

/** ECB / CBC decrypt final: must end on a complete 16B block; verify and strip PKCS#7. */
static int32_t AES_Final_BlockDec(stc_aes_ctx_t *pCtx,
                                   uint8_t *pOut, uint32_t *pu32OutLen)
{
    int32_t ret;
    uint8_t decBlock[AES_EX_BLOCK_SIZE];
    uint8_t plain[AES_EX_BLOCK_SIZE];
    uint8_t validBytes;

    /* Decrypt the last buffered block */
    ret = AES_EX_RunBlockDec(pCtx->buffer, decBlock);
    if (ret != LL_OK) return ret;

    if (pCtx->mode == AES_EX_MODE_CBC) {
        AES_EX_XorBlocks(decBlock, pCtx->iv_or_ctr, plain);
    } else {
        AES_EX_MemCopy(plain, decBlock, AES_EX_BLOCK_SIZE);
    }

    validBytes = AES_EX_PadPKCS7(plain, AES_EX_BLOCK_SIZE);
    if (validBytes == 0U) {
        return LL_ERR_INVD_PARAM;   /* malformed PKCS#7 */
    }

    AES_EX_MemCopy(pOut, plain, validBytes);
    *pu32OutLen = validBytes;
    return LL_OK;
}

int32_t AES_Final_Ex(stc_aes_ctx_t *pCtx, uint8_t *pOut, uint32_t *pu32OutLen)
{
    int32_t ret;
    uint32_t out_len = 0U;

    if ((pCtx == NULL) || (pOut == NULL) || (pu32OutLen == NULL)) {
        return LL_ERR_INVD_PARAM;
    }
    if (pCtx->state != 1U) {
        return LL_ERR_INVD_PARAM;
    }

    ret = LL_OK;

    switch (pCtx->mode) {
        case AES_EX_MODE_ECB:
        case AES_EX_MODE_CBC:
            if (pCtx->dir == AES_EX_DIR_ENCRYPT) {
                ret = AES_Final_BlockEnc(pCtx, pOut, &out_len);
            } else {
                /* Decrypt: MUST have exactly one final block buffered,
                   and Update_Ex must have been feeding multiples of 16 B. */
                if (pCtx->buffer_len != AES_EX_BLOCK_SIZE) {
                    /* Protocol violation: ciphertext is not a multiple of 16 B. */
                    ret = LL_ERR_INVD_PARAM;
                } else {
                    ret = AES_Final_BlockDec(pCtx, pOut, &out_len);
                }
            }
            break;

        case AES_EX_MODE_CTR:
            /* CTR has no padding semantics. Any bytes the caller fed via
               Update were already XORed and written. Just zero out ctx and
               return 0 bytes here. */
            out_len = 0U;
            break;

        default:
            ret = LL_ERR_INVD_PARAM;
            break;
    }

    if (ret == LL_OK) {
        AES_EX_ZeroKey(pCtx);
        pCtx->state = 2U;
        *pu32OutLen = out_len;
    } else {
        /* On error we still try to zero the key so nothing lingers, but do NOT
           mark ctx as finalized — caller might retry after correcting input. */
        AES_EX_ZeroKey(pCtx);
    }

    return ret;
}

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
/*******************************************************************************
 * EOF (not truncated)
 ******************************************************************************/
