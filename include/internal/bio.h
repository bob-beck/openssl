/*
 * Copyright 2016-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_BIO_H
#define OSSL_INTERNAL_BIO_H
#pragma once

#include <openssl/core.h>
#include <openssl/bio.h>

struct bio_method_st {
    int type;
    char *name;
    int (*bwrite)(BIO *, const char *, size_t, size_t *);
    int (*bwrite_old)(BIO *, const char *, int);
    int (*bread)(BIO *, char *, size_t, size_t *);
    int (*bread_old)(BIO *, char *, int);
    int (*bputs)(BIO *, const char *);
    int (*bgets)(BIO *, char *, int);
    long (*ctrl)(BIO *, int, long, void *);
    int (*create)(BIO *);
    int (*destroy)(BIO *);
    long (*callback_ctrl)(BIO *, int, BIO_info_cb *);
    int (*bsendmmsg)(BIO *, BIO_MSG *, size_t, size_t, uint64_t, size_t *);
    int (*brecvmmsg)(BIO *, BIO_MSG *, size_t, size_t, uint64_t, size_t *);
};

void bio_free_ex_data(BIO *bio);
void bio_cleanup(void);

/* Old style to new style BIO_METHOD conversion functions */
int bwrite_conv(BIO *bio, const char *data, size_t datal, size_t *written);
int bread_conv(BIO *bio, char *data, size_t datal, size_t *read);

/* Changes to these internal BIOs must also update include/openssl/bio.h */
#define BIO_CTRL_SET_KTLS 72
#define BIO_CTRL_SET_KTLS_TX_SEND_CTRL_MSG 74
#define BIO_CTRL_CLEAR_KTLS_TX_CTRL_MSG 75
#define BIO_CTRL_SET_KTLS_TX_ZEROCOPY_SENDFILE 90

/* Internal BIO flags */

#define BIO_FLAGS_AUTO_EOF 0x80

/*
 * This is used with memory BIOs:
 * BIO_FLAGS_MEM_LEGACY_EOF means legacy behaviour of BIO_eof()
 */
#define BIO_FLAGS_MEM_LEGACY_EOF 0x1000

/*
 * This is used with socket BIOs:
 * BIO_FLAGS_KTLS_TX means we are using ktls with this BIO for sending.
 * BIO_FLAGS_KTLS_TX_CTRL_MSG means we are about to send a ctrl message next.
 * BIO_FLAGS_KTLS_RX means we are using ktls with this BIO for receiving.
 * BIO_FLAGS_KTLS_TX_ZEROCOPY_SENDFILE means we are using the zerocopy mode with
 * this BIO for sending using sendfile.
 */
#define BIO_FLAGS_KTLS_TX_CTRL_MSG 0x1000
#define BIO_FLAGS_KTLS_RX 0x2000
#define BIO_FLAGS_KTLS_TX 0x4000
#define BIO_FLAGS_KTLS_TX_ZEROCOPY_SENDFILE 0x8000

/* KTLS related controls and flags */
#define BIO_set_ktls_flag(b, is_tx) \
    BIO_set_flags(b, (is_tx) ? BIO_FLAGS_KTLS_TX : BIO_FLAGS_KTLS_RX)
#define BIO_should_ktls_flag(b, is_tx) \
    BIO_test_flags(b, (is_tx) ? BIO_FLAGS_KTLS_TX : BIO_FLAGS_KTLS_RX)
#define BIO_set_ktls_ctrl_msg_flag(b) \
    BIO_set_flags(b, BIO_FLAGS_KTLS_TX_CTRL_MSG)
#define BIO_should_ktls_ctrl_msg_flag(b) \
    BIO_test_flags(b, BIO_FLAGS_KTLS_TX_CTRL_MSG)
#define BIO_clear_ktls_ctrl_msg_flag(b) \
    BIO_clear_flags(b, BIO_FLAGS_KTLS_TX_CTRL_MSG)
#define BIO_set_ktls_zerocopy_sendfile_flag(b) \
    BIO_set_flags(b, BIO_FLAGS_KTLS_TX_ZEROCOPY_SENDFILE)

#define BIO_set_ktls(b, keyblob, is_tx) \
    BIO_ctrl(b, BIO_CTRL_SET_KTLS, is_tx, keyblob)
#define BIO_set_ktls_ctrl_msg(b, record_type) \
    BIO_ctrl(b, BIO_CTRL_SET_KTLS_TX_SEND_CTRL_MSG, record_type, NULL)
#define BIO_clear_ktls_ctrl_msg(b) \
    BIO_ctrl(b, BIO_CTRL_CLEAR_KTLS_TX_CTRL_MSG, 0, NULL)
#define BIO_set_ktls_tx_zerocopy_sendfile(b) \
    BIO_ctrl(b, BIO_CTRL_SET_KTLS_TX_ZEROCOPY_SENDFILE, 0, NULL)

/* Functions to allow the core to offer the CORE_BIO type to providers */
OSSL_CORE_BIO *ossl_core_bio_new_from_bio(BIO *bio);
OSSL_CORE_BIO *ossl_core_bio_new_file(const char *filename, const char *mode);
OSSL_CORE_BIO *ossl_core_bio_new_mem_buf(const void *buf, int len);
int ossl_core_bio_read_ex(OSSL_CORE_BIO *cb, void *data, size_t dlen,
    size_t *readbytes);
int ossl_core_bio_write_ex(OSSL_CORE_BIO *cb, const void *data, size_t dlen,
    size_t *written);
int ossl_core_bio_gets(OSSL_CORE_BIO *cb, char *buf, int size);
int ossl_core_bio_puts(OSSL_CORE_BIO *cb, const char *buf);
long ossl_core_bio_ctrl(OSSL_CORE_BIO *cb, int cmd, long larg, void *parg);
int ossl_core_bio_up_ref(OSSL_CORE_BIO *cb);
int ossl_core_bio_free(OSSL_CORE_BIO *cb);
int ossl_core_bio_vprintf(OSSL_CORE_BIO *cb, const char *format, va_list args);

int ossl_bio_init_core(OSSL_LIB_CTX *libctx, const OSSL_DISPATCH *fns);

#if !defined(OPENSSL_NO_SOCK)
/**
 * @brief Look up a host and service and return the matching addresses as a
 * BIO_ADDRINFO list.
 * @see BIO_lookup(3)
 */
int ossl_BIO_lookup(const char *host, const char *service,
    enum BIO_lookup_type lookup_type,
    int family, int socktype, BIO_ADDRINFO **res);
/**
 * @brief Perform an ioctl on a socket, raising a system error on failure.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BIO_socket_ioctl(int fd, long type, void *arg);
/**
 * @brief Get and clear the pending error on a socket.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BIO_sock_error(int sock);
#endif /* !defined(OPENSSL_NO_SOCK) */

/**
 * @brief Format data as an indented hex and ASCII dump, passing each line to a
 * callback.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BIO_dump_indent_cb(int (*cb)(const void *data, size_t len, void *u),
    void *u, const void *v, int len, int indent);
/**
 * @brief Write data to a BIO as colon-separated uppercase hex bytes, wrapping
 * lines.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BIO_hex_string(BIO *out, int indent, int width, const void *data,
    int datalen);
/**
 * @brief Format data as a hex and ASCII dump, passing each line to a callback.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BIO_dump_cb(int (*cb)(const void *data, size_t len, void *u),
    void *u, const void *s, int len);
/**
 * @brief Duplicate a chain of BIOs, including state, flags, callbacks and
 * ex_data.
 */
/* doc-exempt: in util/missingcrypto.txt */
BIO *ossl_BIO_dup_chain(BIO *in);
/**
 * @brief Return the BIO pair method.
 * @see BIO_s_bio(3)
 */
const BIO_METHOD *ossl_BIO_s_bio(void);
/**
 * @brief Report whether an fd BIO I/O result is retryable; always reports no.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BIO_fd_should_retry(int i);

#if !defined(OPENSSL_NO_DGRAM)
/**
 * @brief Report whether a socket error code is transient for a datagram BIO.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BIO_dgram_non_fatal_error(int err);
#endif /* !defined(OPENSSL_NO_DGRAM) */

#if !defined(OPENSSL_NO_DGRAM)
#if !defined(OPENSSL_NO_SCTP)
/**
 * @brief Return the SCTP datagram socket BIO method.
 */
/* doc-exempt: in util/missingcrypto.txt */
const BIO_METHOD *ossl_BIO_s_datagram_sctp(void);
#endif /* !defined(OPENSSL_NO_SCTP) */
#endif /* !defined(OPENSSL_NO_DGRAM) */

#endif
