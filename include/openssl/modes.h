/*
 * Copyright 2008-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_MODES_H
#define OPENSSL_MODES_H
#pragma once

#include <openssl/macros.h>
#ifndef OPENSSL_NO_DEPRECATED_3_0
#define HEADER_MODES_H
#endif

#include <stddef.h>
#include <openssl/types.h>

#ifdef __cplusplus
extern "C" {
#endif
typedef void (*block128_f)(const unsigned char in[16],
    unsigned char out[16], const void *key);

typedef void (*cbc128_f)(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], int enc);

typedef void (*ecb128_f)(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    int enc);

typedef void (*ctr128_f)(const unsigned char *in, unsigned char *out,
    size_t blocks, const void *key,
    const unsigned char ivec[16]);

typedef void (*ccm128_f)(const unsigned char *in, unsigned char *out,
    size_t blocks, const void *key,
    const unsigned char ivec[16],
    unsigned char cmac[16]);

void CRYPTO_cbc128_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], block128_f block);
void CRYPTO_cbc128_decrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], block128_f block);

void CRYPTO_ctr128_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16],
    unsigned char ecount_buf[16], unsigned int *num,
    block128_f block);

void CRYPTO_ctr128_encrypt_ctr32(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16],
    unsigned char ecount_buf[16],
    unsigned int *num, ctr128_f ctr);

void CRYPTO_ofb128_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], int *num,
    block128_f block);

void CRYPTO_cfb128_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], int *num,
    int enc, block128_f block);
void CRYPTO_cfb128_8_encrypt(const unsigned char *in, unsigned char *out,
    size_t length, const void *key,
    unsigned char ivec[16], int *num,
    int enc, block128_f block);
void CRYPTO_cfb128_1_encrypt(const unsigned char *in, unsigned char *out,
    size_t bits, const void *key,
    unsigned char ivec[16], int *num,
    int enc, block128_f block);

size_t CRYPTO_cts128_encrypt_block(const unsigned char *in,
    unsigned char *out, size_t len,
    const void *key, unsigned char ivec[16],
    block128_f block);
size_t CRYPTO_cts128_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], cbc128_f cbc);
size_t CRYPTO_cts128_decrypt_block(const unsigned char *in,
    unsigned char *out, size_t len,
    const void *key, unsigned char ivec[16],
    block128_f block);
size_t CRYPTO_cts128_decrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], cbc128_f cbc);

size_t CRYPTO_nistcts128_encrypt_block(const unsigned char *in,
    unsigned char *out, size_t len,
    const void *key,
    unsigned char ivec[16],
    block128_f block);
size_t CRYPTO_nistcts128_encrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], cbc128_f cbc);
size_t CRYPTO_nistcts128_decrypt_block(const unsigned char *in,
    unsigned char *out, size_t len,
    const void *key,
    unsigned char ivec[16],
    block128_f block);
size_t CRYPTO_nistcts128_decrypt(const unsigned char *in, unsigned char *out,
    size_t len, const void *key,
    unsigned char ivec[16], cbc128_f cbc);

typedef struct gcm128_context GCM128_CONTEXT;

GCM128_CONTEXT *CRYPTO_gcm128_new(void *key, block128_f block);
#if !defined(OPENSSL_NO_DEPRECATED_4_2)
/**
 * @brief Initialise a GCM context with a key and block cipher, deriving the
 * GHASH key.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 void CRYPTO_gcm128_init(GCM128_CONTEXT *ctx, void *key, block128_f block);
#endif /* !defined(OPENSSL_NO_DEPRECATED_4_2) */
void CRYPTO_gcm128_setiv(GCM128_CONTEXT *ctx, const unsigned char *iv,
    size_t len);
int CRYPTO_gcm128_aad(GCM128_CONTEXT *ctx, const unsigned char *aad,
    size_t len);
#if !defined(OPENSSL_NO_DEPRECATED_4_2)
/**
 * @brief Encrypt data in GCM mode and absorb the ciphertext into GHASH.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_gcm128_encrypt(GCM128_CONTEXT *ctx,
    const unsigned char *in, unsigned char *out,
    size_t len);
#endif /* !defined(OPENSSL_NO_DEPRECATED_4_2) */
int CRYPTO_gcm128_decrypt(GCM128_CONTEXT *ctx,
    const unsigned char *in, unsigned char *out,
    size_t len);
#if !defined(OPENSSL_NO_DEPRECATED_4_2)
/**
 * @brief Encrypt data in GCM mode, handing whole blocks to a stream function
 * with a 32-bit counter.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_gcm128_encrypt_ctr32(GCM128_CONTEXT *ctx,
    const unsigned char *in, unsigned char *out,
    size_t len, ctr128_f stream);
/**
 * @brief Decrypt data in GCM mode, handing whole blocks to a stream function
 * with a 32-bit counter.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_gcm128_decrypt_ctr32(GCM128_CONTEXT *ctx,
    const unsigned char *in, unsigned char *out,
    size_t len, ctr128_f stream);
#endif /* !defined(OPENSSL_NO_DEPRECATED_4_2) */
int CRYPTO_gcm128_finish(GCM128_CONTEXT *ctx, const unsigned char *tag,
    size_t len);
#if !defined(OPENSSL_NO_DEPRECATED_4_2)
/**
 * @brief Finalise GHASH and copy the GCM tag out of the context.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 void CRYPTO_gcm128_tag(GCM128_CONTEXT *ctx, unsigned char *tag, size_t len);
#endif /* !defined(OPENSSL_NO_DEPRECATED_4_2) */
void CRYPTO_gcm128_release(GCM128_CONTEXT *ctx);

typedef struct ccm128_context CCM128_CONTEXT;

#if !defined(OPENSSL_NO_DEPRECATED_4_2)
/**
 * @brief Initialise a CCM context with tag length, length-field size, key and
 * block cipher.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 void CRYPTO_ccm128_init(CCM128_CONTEXT *ctx,
    unsigned int M, unsigned int L, void *key,
    block128_f block);
/**
 * @brief Set the nonce and message length for the next CCM operation and clear
 * the AAD flag.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_ccm128_setiv(CCM128_CONTEXT *ctx, const unsigned char *nonce,
    size_t nlen, size_t mlen);
/**
 * @brief Feed the complete additional authenticated data into the CCM CBC-MAC
 * in one call.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 void CRYPTO_ccm128_aad(CCM128_CONTEXT *ctx, const unsigned char *aad,
    size_t alen);
/**
 * @brief Encrypt a complete CCM message and accumulate its CBC-MAC.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_ccm128_encrypt(CCM128_CONTEXT *ctx, const unsigned char *inp,
    unsigned char *out, size_t len);
/**
 * @brief Decrypt a complete CCM message and accumulate its CBC-MAC.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_ccm128_decrypt(CCM128_CONTEXT *ctx, const unsigned char *inp,
    unsigned char *out, size_t len);
/**
 * @brief Encrypt a complete CCM message, handing whole blocks to a stream
 * function with a 64-bit counter.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_ccm128_encrypt_ccm64(CCM128_CONTEXT *ctx, const unsigned char *inp,
    unsigned char *out, size_t len,
    ccm128_f stream);
/**
 * @brief Decrypt a complete CCM message, handing whole blocks to a stream
 * function with a 64-bit counter.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_ccm128_decrypt_ccm64(CCM128_CONTEXT *ctx, const unsigned char *inp,
    unsigned char *out, size_t len,
    ccm128_f stream);
/**
 * @brief Copy the computed CCM tag out of the context.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 size_t CRYPTO_ccm128_tag(CCM128_CONTEXT *ctx, unsigned char *tag, size_t len);
#endif /* !defined(OPENSSL_NO_DEPRECATED_4_2) */

typedef struct xts128_context XTS128_CONTEXT;

#if !defined(OPENSSL_NO_DEPRECATED_4_2)
/**
 * @brief Encrypt or decrypt one XTS data unit, with ciphertext stealing for a
 * trailing partial block.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_xts128_encrypt(const XTS128_CONTEXT *ctx,
    const unsigned char iv[16],
    const unsigned char *inp, unsigned char *out,
    size_t len, int enc);

/**
 * @brief Wrap key data with the RFC 3394 key wrap algorithm.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 size_t CRYPTO_128_wrap(void *key, const unsigned char *iv,
    unsigned char *out,
    const unsigned char *in, size_t inlen,
    block128_f block);

/**
 * @brief Unwrap RFC 3394 wrapped key data and check the recovered IV.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 size_t CRYPTO_128_unwrap(void *key, const unsigned char *iv,
    unsigned char *out,
    const unsigned char *in, size_t inlen,
    block128_f block);
/**
 * @brief Wrap key data of any length with the RFC 5649 key wrap with padding
 * algorithm.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 size_t CRYPTO_128_wrap_pad(void *key, const unsigned char *icv,
    unsigned char *out, const unsigned char *in,
    size_t inlen, block128_f block);
/**
 * @brief Unwrap RFC 5649 wrapped key data and check its alternative initial
 * value and padding.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 size_t CRYPTO_128_unwrap_pad(void *key, const unsigned char *icv,
    unsigned char *out, const unsigned char *in,
    size_t inlen, block128_f block);
#endif /* !defined(OPENSSL_NO_DEPRECATED_4_2) */

#ifndef OPENSSL_NO_OCB
typedef struct ocb128_context OCB128_CONTEXT;

typedef void (*ocb128_f)(const unsigned char *in, unsigned char *out,
    size_t blocks, const void *key,
    size_t start_block_num,
    unsigned char offset_i[16],
    const unsigned char L_[][16],
    unsigned char checksum[16]);

OCB128_CONTEXT *CRYPTO_ocb128_new(void *keyenc, void *keydec,
    block128_f encrypt, block128_f decrypt,
    ocb128_f stream);
#if !defined(OPENSSL_NO_DEPRECATED_4_2)
/**
 * @brief Initialise an OCB context with key schedules and cipher functions,
 * precomputing the first offset table entries.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_ocb128_init(OCB128_CONTEXT *ctx, void *keyenc, void *keydec,
    block128_f encrypt, block128_f decrypt,
    ocb128_f stream);
/**
 * @brief Copy an OCB context, duplicating its offset table and optionally
 * replacing its key schedules.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_ocb128_copy_ctx(OCB128_CONTEXT *dest, OCB128_CONTEXT *src,
    void *keyenc, void *keydec);
/**
 * @brief Set the nonce and tag length for the next OCB message, resetting all
 * per-message state.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_ocb128_setiv(OCB128_CONTEXT *ctx, const unsigned char *iv,
    size_t len, size_t taglen);
/**
 * @brief Absorb additional authenticated data into the OCB hash.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_ocb128_aad(OCB128_CONTEXT *ctx, const unsigned char *aad,
    size_t len);
/**
 * @brief Encrypt data in OCB mode and update the plaintext checksum.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_ocb128_encrypt(OCB128_CONTEXT *ctx, const unsigned char *in,
    unsigned char *out, size_t len);
/**
 * @brief Decrypt data in OCB mode and update the plaintext checksum.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_ocb128_decrypt(OCB128_CONTEXT *ctx, const unsigned char *in,
    unsigned char *out, size_t len);
/**
 * @brief Compute the OCB tag and compare it in constant time with an expected
 * tag.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_ocb128_finish(OCB128_CONTEXT *ctx, const unsigned char *tag,
    size_t len);
/**
 * @brief Compute the OCB tag and write it out.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 int CRYPTO_ocb128_tag(OCB128_CONTEXT *ctx, unsigned char *tag, size_t len);
/**
 * @brief Free the offset table of an OCB context and cleanse the context.
 */
/* doc-exempt: in util/missingcrypto.txt */
OSSL_DEPRECATEDIN_4_2 void CRYPTO_ocb128_cleanup(OCB128_CONTEXT *ctx);
#endif /* !defined(OPENSSL_NO_DEPRECATED_4_2) */
#endif /* OPENSSL_NO_OCB */

#ifdef __cplusplus
}
#endif

#endif
