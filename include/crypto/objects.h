/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_CRYPTO_OBJECTS_H)
#define OSSL_CRYPTO_OBJECTS_H

#include <openssl/objects.h>

void ossl_obj_cleanup_int(void);

/**
 * @brief Remove object names of a given type, or all names and the name table.
 */
/* doc-exempt: in util/missingcrypto.txt */
void ossl_OBJ_NAME_cleanup(int type);
/**
 * @brief Initialise the object name table once.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_OBJ_NAME_init(void);
/**
 * @brief Free the application-added signature algorithm tables.
 */
/* doc-exempt: in util/missingcrypto.txt */
void ossl_OBJ_sigid_free(void);

#endif /* !defined(OSSL_CRYPTO_OBJECTS_H) */
