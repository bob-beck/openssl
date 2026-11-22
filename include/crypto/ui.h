/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_CRYPTO_UI_H)
#define OSSL_CRYPTO_UI_H

#include <openssl/ui.h>

/**
 * @brief Get the length of the result of a UI_STRING.
 * @see UI_get_result_string_length(3)
 */
int ossl_UI_get_result_string_length(UI_STRING *uis);
/**
 * @brief Get the length of the result of one prompt of a UI.
 * @see UI_get_result_length(3)
 */
int ossl_UI_get_result_length(UI *ui, int i);
/**
 * @brief Get the string a verification prompt's result is compared against.
 * @see UI_get0_test_string(3)
 */
const char *ossl_UI_get0_test_string(UI_STRING *uis);
/**
 * @brief Set the UI method of a UI.
 * @see UI_set_method(3)
 */
const UI_METHOD *ossl_UI_set_method(UI *ui, const UI_METHOD *meth);

#endif /* defined(OSSL_CRYPTO_UI_H) */
