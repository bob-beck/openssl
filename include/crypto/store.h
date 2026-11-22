/*
 * Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_STORE_H
#define OSSL_CRYPTO_STORE_H
#pragma once

#include <openssl/bio.h>
#include <openssl/store.h>
#include <openssl/ui.h>

void ossl_store_cleanup_int(void);
int ossl_store_loader_get_number(const OSSL_STORE_LOADER *loader);
int ossl_store_loader_store_cache_flush(OSSL_LIB_CTX *libctx);
int ossl_store_loader_store_remove_all_provided(const OSSL_PROVIDER *prov);

/**
 * @brief Set the description of a NAME OSSL_STORE_INFO, taking ownership of it.
 * @see OSSL_STORE_INFO_set0_NAME_description(3)
 */
int ossl_OSSL_STORE_INFO_set0_NAME_description(OSSL_STORE_INFO *info, char *desc);
/**
 * @brief Create an OSSL_STORE_INFO holding key parameters.
 * @see OSSL_STORE_INFO_new_PARAMS(3)
 */
OSSL_STORE_INFO *ossl_OSSL_STORE_INFO_new_PARAMS(EVP_PKEY *params);
/**
 * @brief Create an OSSL_STORE_INFO holding a name.
 * @see OSSL_STORE_INFO_new_NAME(3)
 */
OSSL_STORE_INFO *ossl_OSSL_STORE_INFO_new_NAME(char *name);
/**
 * @brief Create an OSSL_STORE_INFO holding a private key.
 * @see OSSL_STORE_INFO_new_PKEY(3)
 */
OSSL_STORE_INFO *ossl_OSSL_STORE_INFO_new_PKEY(EVP_PKEY *pkey);
/**
 * @brief Create an OSSL_STORE_INFO holding a certificate.
 * @see OSSL_STORE_INFO_new_CERT(3)
 */
OSSL_STORE_INFO *ossl_OSSL_STORE_INFO_new_CERT(X509 *x509);
/**
 * @brief Create an OSSL_STORE_INFO holding a CRL.
 * @see OSSL_STORE_INFO_new_CRL(3)
 */
OSSL_STORE_INFO *ossl_OSSL_STORE_INFO_new_CRL(X509_CRL *crl);

#endif
