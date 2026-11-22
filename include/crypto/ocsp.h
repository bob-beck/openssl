/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_CRYPTO_OCSP_H)
#define OSSL_CRYPTO_OCSP_H

#include <openssl/ocsp.h>

/**
 * @brief Add a certificate to the signature of an OCSP request.
 * @see OCSP_request_add1_cert(3)
 */
int ossl_OCSP_request_add1_cert(OCSP_REQUEST *req, X509 *cert);
/**
 * @brief Find the next request extension of an OCSP request with a given NID.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_OCSP_REQUEST_get_ext_by_NID(OCSP_REQUEST *x, int nid, int lastpos);
/**
 * @brief Insert a copy of an extension into the response extensions of a basic
 * OCSP response.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_OCSP_BASICRESP_add_ext(OCSP_BASICRESP *x, const X509_EXTENSION *ex, int loc);
/**
 * @brief Get the request extension at a given position of an OCSP request.
 */
/* doc-exempt: in util/missingcrypto.txt */
const X509_EXTENSION *ossl_OCSP_REQUEST_get_ext(OCSP_REQUEST *x, int loc);
/**
 * @brief Set a responder ID to a certificate's subject name.
 * @see OCSP_RESPID_set_by_name(3)
 */
int ossl_OCSP_RESPID_set_by_name(OCSP_RESPID *respid, X509 *cert);
/**
 * @brief Set a responder ID to the SHA-1 hash of a certificate's public key.
 * @see OCSP_RESPID_set_by_key(3)
 */
int ossl_OCSP_RESPID_set_by_key(OCSP_RESPID *respid, X509 *cert);

#endif /* defined(OSSL_CRYPTO_OCSP_H) */
