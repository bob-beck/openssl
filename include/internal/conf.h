/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_CONF_H
#define OSSL_INTERNAL_CONF_H
#pragma once

#include "internal/dso.h"
#include "internal/thread_once.h"

#include <openssl/conf.h>

#define DEFAULT_CONF_MFLAGS \
    (CONF_MFLAGS_DEFAULT_SECTION | CONF_MFLAGS_IGNORE_MISSING_FILE | CONF_MFLAGS_IGNORE_RETURN_CODES)

struct ossl_init_settings_st {
    char *filename;
    char *appname;
    unsigned long flags;
};

/*
 * This structure contains a data about supported modules. entries in this
 * table correspond to either dynamic or static modules.
 */

struct conf_module_st {
    /* DSO of this module or NULL if static */
    DSO *dso;
    /* Name of the module */
    char *name;
    /* Init function */
    conf_init_func *init;
    /* Finish function */
    conf_finish_func *finish;
    /* Number of successfully initialized modules */
    int links;
    void *usr_data;
};

/*
 * This structure contains information about modules that have been
 * successfully initialized. There may be more than one entry for a given
 * module.
 */

struct conf_imodule_st {
    CONF_MODULE *pmod;
    OSSL_LIB_CTX *libctx;
    char *name;
    char *value;
    unsigned long flags;
    void *usr_data;
};

int ossl_config_int(const OPENSSL_INIT_SETTINGS *);
void ossl_no_config_int(void);
void ossl_config_modules_free(void);
int ossl_conf_parse_bool(const char *value, int *result);

/**
 * @brief Return the default configuration method.
 * @see NCONF_default(3)
 */
CONF_METHOD *ossl_NCONF_default(void);
/**
 * @brief Look up a configuration value by group and name, or an environment
 * variable if conf is NULL.
 */
/* doc-exempt: in util/missingcrypto.txt */
char *ossl_CONF_get_string(LHASH_OF(CONF_VALUE) *conf, const char *group,
    const char *name);
/**
 * @brief Free the data of a configuration, keeping the CONF itself.
 */
/* doc-exempt: in util/missingcrypto.txt */
void ossl_NCONF_free_data(CONF *conf);
/**
 * @brief Initialise a CONF with the default method and attach a configuration
 * hash to it.
 */
/* doc-exempt: in util/missingcrypto.txt */
void ossl_CONF_set_nconf(CONF *conf, LHASH_OF(CONF_VALUE) *hash);
/**
 * @brief Write every value in a configuration to a BIO.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_NCONF_dump_bio(const CONF *conf, BIO *out);
/**
 * @brief Parse configuration data from a BIO into a configuration hash.
 */
/* doc-exempt: in util/missingcrypto.txt */
LHASH_OF(CONF_VALUE) *ossl_CONF_load_bio(LHASH_OF(CONF_VALUE) *conf, BIO *bp,
    long *eline);
/**
 * @brief Write every value in a configuration hash to a BIO.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_CONF_dump_bio(LHASH_OF(CONF_VALUE) *conf, BIO *out);
/**
 * @brief Get the user data of an initialised configuration module.
 */
/* doc-exempt: in util/missingcrypto.txt */
void *ossl_CONF_imodule_get_usr_data(const CONF_IMODULE *md);
/**
 * @brief Set the user data of an initialised configuration module.
 */
/* doc-exempt: in util/missingcrypto.txt */
void ossl_CONF_imodule_set_usr_data(CONF_IMODULE *md, void *usr_data);
/**
 * @brief Get the configuration value of an initialised configuration module.
 */
/* doc-exempt: in util/missingcrypto.txt */
const char *ossl_CONF_imodule_get_value(const CONF_IMODULE *md);
/**
 * @brief Get the name of an initialised configuration module.
 */
/* doc-exempt: in util/missingcrypto.txt */
const char *ossl_CONF_imodule_get_name(const CONF_IMODULE *md);
/**
 * @brief Register a configuration module by name.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_CONF_module_add(const char *name, conf_init_func *ifunc,
    conf_finish_func *ffunc);

#endif
