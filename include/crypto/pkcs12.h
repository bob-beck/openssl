/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_CRYPTO_PKCS12_H)
#define OSSL_CRYPTO_PKCS12_H

#include <openssl/pkcs12.h>

/**
 * @brief Encode an object into a new safe bag.
 */
/* doc-exempt: in util/missingcrypto.txt */
PKCS12_SAFEBAG *ossl_PKCS12_item_pack_safebag(void *obj, const ASN1_ITEM *it,
    int nid1, int nid2);
/**
 * @brief Get the value of the attribute with a given NID from an attribute
 * stack.
 * @see PKCS12_get_attr_gen(3)
 */
const ASN1_TYPE *ossl_PKCS12_get_attr_gen(const STACK_OF(X509_ATTRIBUTE) *attrs,
    int attr_nid);
/**
 * @brief Add a key usage attribute to a PKCS#8 private key structure.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_PKCS8_add_keyusage(PKCS8_PRIV_KEY_INFO *p8, int usage);
/**
 * @brief Derive a key and IV with the PKCS#12 algorithm and initialise a cipher
 * context.
 * @see PKCS12_PBE_keyivgen(3)
 */
int ossl_PKCS12_PBE_keyivgen(EVP_CIPHER_CTX *ctx, const char *pass, int passlen,
    ASN1_TYPE *param, const EVP_CIPHER *cipher,
    const EVP_MD *md, int en_de);
/**
 * @brief Add a certificate bag to a stack of safe bags.
 * @see PKCS12_add_cert(3)
 */
PKCS12_SAFEBAG *ossl_PKCS12_add_cert(STACK_OF(PKCS12_SAFEBAG) **pbags, X509 *cert);
/**
 * @brief Encrypt or decrypt a buffer with a PKCS#12 password-based algorithm.
 * @see PKCS12_pbe_crypt(3)
 */
unsigned char *ossl_PKCS12_pbe_crypt(const X509_ALGOR *algor,
    const char *pass, int passlen,
    const unsigned char *in, int inlen,
    unsigned char **data, int *datalen, int en_de);
/**
 * @brief Set the MAC parameters of a PKCS#12 structure.
 * @see PKCS12_setup_mac(3)
 */
int ossl_PKCS12_setup_mac(PKCS12 *p12, int iter, unsigned char *salt, int saltlen,
    const EVP_MD *md_type);
/**
 * @brief Generate the MAC of a PKCS#12 structure.
 * @see PKCS12_gen_mac(3)
 */
int ossl_PKCS12_gen_mac(PKCS12 *p12, const char *pass, int passlen,
    unsigned char *mac, unsigned int *maclen);
/**
 * @brief Create a shrouded key bag holding an encrypted PKCS#8 key.
 * @see PKCS12_SAFEBAG_create0_pkcs8(3)
 */
PKCS12_SAFEBAG *ossl_PKCS12_SAFEBAG_create0_pkcs8(X509_SIG *p8);
/**
 * @brief Convert a UTF-8 string to a NUL-terminated big-endian UTF-16 string.
 */
/* doc-exempt: in util/missingcrypto.txt */
unsigned char *ossl_OPENSSL_utf82uni(const char *asc, int asclen,
    unsigned char **uni, int *unilen);

#endif /* defined(OSSL_CRYPTO_PKCS12_H) */
