/*
 * Copyright 2014-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_BN_H
#define OSSL_CRYPTO_BN_H
#pragma once

#include <openssl/bn.h>
#include <limits.h>

BIGNUM *bn_wexpand(BIGNUM *a, int words);
BIGNUM *bn_expand2(BIGNUM *a, int words);

void bn_correct_top(BIGNUM *a);
int bn_set_top_fixed(BIGNUM *a, int words);

/*
 * Determine the modified width-(w+1) Non-Adjacent Form (wNAF) of 'scalar'.
 * This is an array r[] of values that are either zero or odd with an
 * absolute value less than 2^w satisfying scalar = \sum_j r[j]*2^j where at
 * most one of any w+1 consecutive digits is non-zero with the exception that
 * the most significant digit may be only w-1 zeros away from that next
 * non-zero digit.
 */
signed char *bn_compute_wNAF(const BIGNUM *scalar, int w, size_t *ret_len);

int bn_get_top(const BIGNUM *a);

int bn_get_dmax(const BIGNUM *a);

/* Set all words to zero */
void bn_set_all_zero(BIGNUM *a);

/*
 * Copy the internal BIGNUM words into out which holds size elements (and size
 * must be bigger than top)
 */
int bn_copy_words(BN_ULONG *out, const BIGNUM *in, int size);

BN_ULONG *bn_get_words(const BIGNUM *a);

/*
 * Set the internal data words in a to point to words which contains size
 * elements. The BN_FLG_STATIC_DATA flag is set
 */
void bn_set_static_words(BIGNUM *a, const BN_ULONG *words, int size);

/*
 * Copy words into the BIGNUM |a|, reallocating space as necessary.
 * The negative flag of |a| is not modified.
 * Returns 1 on success and 0 on failure.
 */
/*
 * |num_words| is int because bn_expand2 takes an int. This is an internal
 * function so we simply trust callers not to pass negative values.
 */
int bn_set_words(BIGNUM *a, const BN_ULONG *words, int num_words);

/*
 * Some BIGNUM functions assume most significant limb to be non-zero, which
 * is customarily arranged by bn_correct_top. Output from below functions
 * is not processed with bn_correct_top, and for this reason it may not be
 * returned out of public API. It may only be passed internally into other
 * functions known to support non-minimal or zero-padded BIGNUMs. Even
 * though the goal is to facilitate constant-time-ness, not each subroutine
 * is constant-time by itself. They all have pre-conditions, consult source
 * code...
 */
int bn_mul_mont_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    BN_MONT_CTX *mont, BN_CTX *ctx);
int bn_mod_exp_mont_fixed_top(BIGNUM *rr, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx,
    BN_MONT_CTX *in_mont);
int bn_to_mont_fixed_top(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
    BN_CTX *ctx);
int bn_from_mont_fixed_top(BIGNUM *r, const BIGNUM *a, BN_MONT_CTX *mont,
    BN_CTX *ctx);
int bn_mod_add_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *m);
int bn_mod_sub_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *m);
int bn_mul_fixed_top(BIGNUM *r, const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
int bn_sqr_fixed_top(BIGNUM *r, const BIGNUM *a, BN_CTX *ctx);
int bn_lshift_fixed_top(BIGNUM *r, const BIGNUM *a, int n);
int bn_rshift_fixed_top(BIGNUM *r, const BIGNUM *a, int n);
int bn_div_fixed_top(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
    const BIGNUM *d, BN_CTX *ctx);
int ossl_bn_mask_bits_fixed_top(BIGNUM *a, int n);
int ossl_bn_is_word_fixed_top(const BIGNUM *a, const BN_ULONG w);
int ossl_bn_priv_rand_range_fixed_top(BIGNUM *r, const BIGNUM *range,
    unsigned int strength, BN_CTX *ctx);
int ossl_bn_gen_dsa_nonce_fixed_top(BIGNUM *out, const BIGNUM *range,
    const BIGNUM *priv,
    const unsigned char *message,
    size_t message_len, BN_CTX *ctx);

#define BN_PRIMETEST_COMPOSITE 0
#define BN_PRIMETEST_COMPOSITE_WITH_FACTOR 1
#define BN_PRIMETEST_COMPOSITE_NOT_POWER_OF_PRIME 2
#define BN_PRIMETEST_PROBABLY_PRIME 3

int ossl_bn_miller_rabin_is_prime(const BIGNUM *w, int iterations, BN_CTX *ctx,
    BN_GENCB *cb, int enhanced, int *status);
int ossl_bn_check_generated_prime(const BIGNUM *w, int checks, BN_CTX *ctx,
    BN_GENCB *cb);

const BIGNUM *ossl_bn_get0_small_factors(void);

int ossl_bn_rsa_fips186_5_gen_prob_primes(BIGNUM *p, BIGNUM *Xpout,
    BIGNUM *p1, BIGNUM *p2,
    const BIGNUM *Xp, const BIGNUM *Xp1,
    const BIGNUM *Xp2, int nlen,
    const BIGNUM *e, BN_CTX *ctx,
    BN_GENCB *cb, uint32_t c);

int ossl_bn_rsa_fips186_5_derive_prime(BIGNUM *Y, BIGNUM *X, const BIGNUM *Xin,
    const BIGNUM *r1, const BIGNUM *r2,
    int nlen, const BIGNUM *e, BN_CTX *ctx,
    BN_GENCB *cb, uint32_t c);

OSSL_LIB_CTX *ossl_bn_get_libctx(BN_CTX *ctx);

extern const BIGNUM ossl_bn_inv_sqrt_2;

#if defined(OPENSSL_SYS_LINUX) && !defined(FIPS_MODULE) && defined(__s390x__) \
    && !defined(OPENSSL_NO_ASM)
#define S390X_MOD_EXP
#endif

int s390x_mod_exp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx, BN_MONT_CTX *m_ctx);
int s390x_crt(BIGNUM *r, const BIGNUM *i, const BIGNUM *p, const BIGNUM *q,
    const BIGNUM *dmp, const BIGNUM *dmq, const BIGNUM *iqmp, const BIGNUM *n);

/**
 * @brief Subtract the magnitude of b from the magnitude of a, assuming |a| >=
 * |b|.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_usub(BIGNUM *r, const BIGNUM *a, const BIGNUM *b);
/**
 * @brief Record the calling thread as the owner of a blinding object.
 * @see BN_BLINDING_set_current_thread(3)
 */
void ossl_BN_BLINDING_set_current_thread(BN_BLINDING *b);
/**
 * @brief Create or reinitialise a blinding object with fresh random blinding
 * values for modulus m and exponent e.
 * @see BN_BLINDING_create_param(3)
 */
BN_BLINDING *ossl_BN_BLINDING_create_param(BN_BLINDING *b,
    const BIGNUM *e, BIGNUM *m, BN_CTX *ctx,
    int (*bn_mod_exp)(BIGNUM *r,
        const BIGNUM *a,
        const BIGNUM *p,
        const BIGNUM *m,
        BN_CTX *ctx,
        BN_MONT_CTX *m_ctx),
    BN_MONT_CTX *m_ctx);
/**
 * @brief Advance the blinding values, regenerating them after a fixed number of
 * uses.
 * @see BN_BLINDING_update(3)
 */
int ossl_BN_BLINDING_update(BN_BLINDING *b, BN_CTX *ctx);
/**
 * @brief Allocate a blinding object holding copies of the blinding value, its
 * inverse and the modulus.
 * @see BN_BLINDING_new(3)
 */
BN_BLINDING *ossl_BN_BLINDING_new(const BIGNUM *A, const BIGNUM *Ai, BIGNUM *mod);
/**
 * @brief Compute a^p modulo m by sliding-window exponentiation with
 * BN_mod_mul().
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx);
/**
 * @brief Compute a^p modulo m using reciprocal (Barrett) reduction.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_mod_exp_recp(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
    const BIGNUM *m, BN_CTX *ctx);
/**
 * @brief Compute a1^p1 * a2^p2 modulo an odd m using Montgomery multiplication.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_mod_exp2_mont(BIGNUM *rr, const BIGNUM *a1, const BIGNUM *p1,
    const BIGNUM *a2, const BIGNUM *p2, const BIGNUM *m,
    BN_CTX *ctx, BN_MONT_CTX *in_mont);
/**
 * @brief Compute the Kronecker symbol (a | b).
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_kronecker(const BIGNUM *a, const BIGNUM *b, BN_CTX *ctx);
/**
 * @brief Swap two BIGNUMs in constant time when condition is nonzero.
 */
/* doc-exempt: in util/missingcrypto.txt */
void ossl_BN_consttime_swap(BN_ULONG condition, BIGNUM *a, BIGNUM *b, int nwords);
/**
 * @brief Return the security strength in bits of a finite-field group with
 * modulus size L and subgroup size N.
 * @see BN_security_bits(3)
 */
int ossl_BN_security_bits(int L, int N);
/**
 * @brief Compute 2a modulo m for a non-negative a less than m.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_mod_lshift1_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *m);
/**
 * @brief Compute a * 2^n modulo m for a non-negative a less than m.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_mod_lshift_quick(BIGNUM *r, const BIGNUM *a, int n, const BIGNUM *m);
/**
 * @brief Compute a - b modulo m for a and b in the range [0, m).
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_mod_sub_quick(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *m);
/**
 * @brief Return the Montgomery context cached at *pmont, creating and storing
 * it under lock on first use.
 */
/* doc-exempt: in util/missingcrypto.txt */
BN_MONT_CTX *ossl_BN_MONT_CTX_set_locked(BN_MONT_CTX **pmont, CRYPTO_RWLOCK *lock,
    const BIGNUM *mod, BN_CTX *ctx);
/**
 * @brief Return the NIST P-192 prime as a static BIGNUM.
 * @see BN_get0_nist_prime_192(3)
 */
const BIGNUM *ossl_BN_get0_nist_prime_192(void);
/**
 * @brief Return the NIST P-224 prime as a static BIGNUM.
 * @see BN_get0_nist_prime_224(3)
 */
const BIGNUM *ossl_BN_get0_nist_prime_224(void);
/**
 * @brief Return the NIST P-256 prime as a static BIGNUM.
 * @see BN_get0_nist_prime_256(3)
 */
const BIGNUM *ossl_BN_get0_nist_prime_256(void);
/**
 * @brief Return the NIST P-384 prime as a static BIGNUM.
 * @see BN_get0_nist_prime_384(3)
 */
const BIGNUM *ossl_BN_get0_nist_prime_384(void);
/**
 * @brief Return the NIST P-521 prime as a static BIGNUM.
 * @see BN_get0_nist_prime_521(3)
 */
const BIGNUM *ossl_BN_get0_nist_prime_521(void);
/**
 * @brief Look up the NIST fast-reduction function for a prime.
 */
/* doc-exempt: in util/missingcrypto.txt */
int (*ossl_BN_nist_mod_func(const BIGNUM *p))(BIGNUM *r, const BIGNUM *a,
    const BIGNUM *field, BN_CTX *ctx);
/**
 * @brief Reduce a modulo the NIST P-192 prime.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
    BN_CTX *ctx);
/**
 * @brief Reduce a modulo the NIST P-224 prime.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
    BN_CTX *ctx);
/**
 * @brief Reduce a modulo the NIST P-256 prime.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
    BN_CTX *ctx);
/**
 * @brief Reduce a modulo the NIST P-384 prime.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
    BN_CTX *ctx);
/**
 * @brief Reduce a modulo the NIST P-521 prime.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
    BN_CTX *ctx);
/**
 * @brief Compute x * y modulo the divisor held in a reciprocal context.
 * @see BN_mod_mul_reciprocal(3)
 */
int ossl_BN_mod_mul_reciprocal(BIGNUM *r, const BIGNUM *x, const BIGNUM *y,
    BN_RECP_CTX *recp, BN_CTX *ctx);
/**
 * @brief Free a reciprocal context and the values it holds.
 * @see BN_RECP_CTX_free(3)
 */
void ossl_BN_RECP_CTX_free(BN_RECP_CTX *recp);
/**
 * @brief Store the divisor d and its reciprocal in a reciprocal context.
 * @see BN_RECP_CTX_set(3)
 */
int ossl_BN_RECP_CTX_set(BN_RECP_CTX *recp, const BIGNUM *d, BN_CTX *ctx);
/**
 * @brief Compute floor(2^len / m).
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_reciprocal(BIGNUM *r, const BIGNUM *m, int len, BN_CTX *ctx);
/**
 * @brief Divide m by the divisor held in a reciprocal context, producing
 * quotient and remainder.
 * @see BN_div_recp(3)
 */
int ossl_BN_div_recp(BIGNUM *dv, BIGNUM *rem, const BIGNUM *m,
    BN_RECP_CTX *recp, BN_CTX *ctx);

#if !defined(OPENSSL_NO_EC2M)
/**
 * @brief Find a solution z of z^2 + z = a_ modulo p over GF(2).
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_GF2m_mod_solve_quad_arr(BIGNUM *r, const BIGNUM *a_, const int p[],
    BN_CTX *ctx);
/**
 * @brief Compute the square root of a modulo p over GF(2) as a^(2^(m-1)), where
 * m is p[0].
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_GF2m_mod_sqrt_arr(BIGNUM *r, const BIGNUM *a, const int p[],
    BN_CTX *ctx);
/**
 * @brief Compute a * b modulo p over GF(2), with p given as an array of term
 * degrees.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_GF2m_mod_mul_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const int p[], BN_CTX *ctx);
/**
 * @brief Compute a^2 modulo p over GF(2), with p given as an array of term
 * degrees.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_GF2m_mod_sqr_arr(BIGNUM *r, const BIGNUM *a, const int p[],
    BN_CTX *ctx);
/**
 * @brief Compute a^b modulo p over GF(2), with p given as an array of term
 * degrees.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_GF2m_mod_exp_arr(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const int p[], BN_CTX *ctx);
/**
 * @brief Convert a polynomial over GF(2) into an array of its term degrees in
 * decreasing order, terminated by -1.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_GF2m_poly2arr(const BIGNUM *a, int p[], int max);
/**
 * @brief Convert an array of term degrees into the polynomial it represents
 * over GF(2).
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_GF2m_arr2poly(const int p[], BIGNUM *a);
/**
 * @brief Reduce a polynomial over GF(2) modulo the polynomial given as an array
 * of term degrees.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_GF2m_mod_arr(BIGNUM *r, const BIGNUM *a, const int p[]);
/**
 * @brief Compute a * b modulo p over GF(2).
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_GF2m_mod_mul(BIGNUM *r, const BIGNUM *a, const BIGNUM *b,
    const BIGNUM *p, BN_CTX *ctx);
/**
 * @brief Compute the inverse of a modulo p over GF(2), blinding the computation
 * with a random multiplier.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_GF2m_mod_inv(BIGNUM *r, const BIGNUM *a, const BIGNUM *p, BN_CTX *ctx);
/**
 * @brief Compute y/x modulo p over GF(2).
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_GF2m_mod_div(BIGNUM *r, const BIGNUM *y, const BIGNUM *x,
    const BIGNUM *p, BN_CTX *ctx);
/**
 * @brief Reduce a polynomial over GF(2) modulo p.
 */
/* doc-exempt: in util/missingcrypto.txt */
int ossl_BN_GF2m_mod(BIGNUM *r, const BIGNUM *a, const BIGNUM *p);
#endif /* !defined(OPENSSL_NO_EC2M) */

#endif

int ossl_bn_mont_ctx_set(BN_MONT_CTX *ctx, const BIGNUM *modulus, int ri,
    const unsigned char *rr, int rrlen,
    uint32_t nlo, uint32_t nhi);

int ossl_bn_mont_ctx_eq(const BN_MONT_CTX *m1, const BN_MONT_CTX *m2);
