/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/crypto.h>

#include "crypto/mtc.h"
#include "internal/nelem.h"
#include "testutil.h"

/* Number of leaves used by the exhaustive round-trip test. */
#define MTC_TEST_LIMIT 65

/**
 * @brief Build an in-memory tree of n distinct leaves.
 *
 * Each leaf is the bytes "label" followed by a little-endian 8-byte index,
 * matching the pattern used by the reference implementation's tests.
 *
 * @param n the number of leaves to append
 * @returns the new tree, or NULL on failure.
 */
static OSSL_MTC_TREE *build_tree(uint64_t n)
{
    OSSL_MTC_TREE *tree = ossl_mtc_tree_new();
    uint64_t i;
    size_t j;
    uint8_t entry[5 + 8];

    if (tree == NULL)
        return NULL;
    memcpy(entry, "label", 5);
    for (i = 0; i < n; i++) {
        for (j = 0; j < 8; j++)
            entry[5 + j] = (uint8_t)(i >> (j * 8));
        if (!ossl_mtc_tree_append(tree, entry, sizeof(entry))) {
            ossl_mtc_tree_free(tree);
            return NULL;
        }
    }
    return tree;
}

static int test_subtree_is_valid(void)
{
    OSSL_MTC_SUBTREE s;

    /* An empty subtree is invalid. */
    s.start = 0;
    s.end = 0;
    if (!TEST_false(ossl_mtc_subtree_is_valid(s)))
        return 0;
    /* An inverted interval is invalid. */
    s.start = 1;
    s.end = 0;
    if (!TEST_false(ossl_mtc_subtree_is_valid(s)))
        return 0;
    /* The maximum expressible subtree is valid. */
    s.start = 0;
    s.end = UINT64_MAX;
    if (!TEST_true(ossl_mtc_subtree_is_valid(s)))
        return 0;
    /* Subtrees need not start at zero. */
    s.start = 4;
    s.end = 8;
    if (!TEST_true(ossl_mtc_subtree_is_valid(s)))
        return 0;
    /* But a non-zero start bounds the size. */
    s.start = 4;
    s.end = 9;
    if (!TEST_false(ossl_mtc_subtree_is_valid(s)))
        return 0;
    /* A ragged right edge is allowed. */
    s.start = 4;
    s.end = 6;
    if (!TEST_true(ossl_mtc_subtree_is_valid(s)))
        return 0;
    s.start = 0;
    s.end = 6;
    if (!TEST_true(ossl_mtc_subtree_is_valid(s)))
        return 0;
    return 1;
}

static int test_subtree_split(void)
{
    OSSL_MTC_SUBTREE s;

    s.start = 24601;
    s.end = 24601; /* empty */
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), 24601))
        return 0;
    s.start = 1336;
    s.end = 1337; /* single leaf */
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), 1337))
        return 0;
    s.start = 42;
    s.end = 44; /* two leaves */
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), 43))
        return 0;
    s.start = 0;
    s.end = 31; /* one less than a power of two */
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), 16))
        return 0;
    s.start = 64;
    s.end = 128; /* a power of two */
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), 96))
        return 0;
    s.start = 0;
    s.end = 257; /* one more than a power of two */
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), 256))
        return 0;
    s.start = 0;
    s.end = UINT64_MAX;
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), UINT64_C(1) << 63))
        return 0;
    s.start = UINT64_MAX - 3;
    s.end = UINT64_MAX;
    if (!TEST_uint64_t_eq(ossl_mtc_subtree_split(s), UINT64_MAX - 1))
        return 0;
    return 1;
}

/* Build the {index, index + 1} single-leaf subtree hash. */
static int leaf_hash(const OSSL_MTC_TREE *tree, uint64_t index,
    uint8_t out[OSSL_MTC_HASH_LEN])
{
    OSSL_MTC_SUBTREE leaf;

    leaf.start = index;
    leaf.end = index + 1;
    return ossl_mtc_tree_subtree_hash(tree, leaf, out);
}

static int test_inclusion_roundtrip(void)
{
    OSSL_MTC_TREE *tree = build_tree(847);
    uint8_t node_hash[OSSL_MTC_HASH_LEN];
    uint8_t want[OSSL_MTC_HASH_LEN];
    uint8_t got[OSSL_MTC_HASH_LEN];
    uint8_t *proof = NULL;
    size_t proof_len = 0;
    OSSL_MTC_SUBTREE subtree;
    int ret = 0;

    if (!TEST_ptr(tree))
        goto err;

    /* A subtree starting at zero. */
    subtree.start = 0;
    subtree.end = 16;
    if (!TEST_true(leaf_hash(tree, 0, node_hash))
        || !TEST_true(ossl_mtc_tree_subtree_hash(tree, subtree, want))
        || !TEST_true(ossl_mtc_tree_inclusion_proof(tree, 0, subtree,
            &proof, &proof_len))
        || !TEST_true(ossl_mtc_eval_subtree_inclusion_proof(
            proof, proof_len, 0, node_hash, subtree, got))
        || !TEST_mem_eq(got, OSSL_MTC_HASH_LEN, want, OSSL_MTC_HASH_LEN))
        goto err;
    OPENSSL_free(proof);
    proof = NULL;

    /* A subtree that does not start at zero, with a ragged edge. */
    subtree.start = 840;
    subtree.end = 847;
    if (!TEST_true(leaf_hash(tree, 845, node_hash))
        || !TEST_true(ossl_mtc_tree_subtree_hash(tree, subtree, want))
        || !TEST_true(ossl_mtc_tree_inclusion_proof(tree, 845, subtree,
            &proof, &proof_len))
        || !TEST_true(ossl_mtc_eval_subtree_inclusion_proof(
            proof, proof_len, 845, node_hash, subtree, got))
        || !TEST_mem_eq(got, OSSL_MTC_HASH_LEN, want, OSSL_MTC_HASH_LEN))
        goto err;

    ret = 1;
err:
    OPENSSL_free(proof);
    ossl_mtc_tree_free(tree);
    return ret;
}

static int test_inclusion_invalid_args(void)
{
    OSSL_MTC_TREE *tree = build_tree(847);
    uint8_t node_hash[OSSL_MTC_HASH_LEN];
    uint8_t wrong_hash[OSSL_MTC_HASH_LEN];
    uint8_t want[OSSL_MTC_HASH_LEN];
    uint8_t got[OSSL_MTC_HASH_LEN];
    uint8_t *proof = NULL;
    size_t proof_len = 0;
    OSSL_MTC_SUBTREE subtree, bad;
    int ret = 0;

    if (!TEST_ptr(tree))
        goto err;
    subtree.start = 840;
    subtree.end = 847;
    if (!TEST_true(leaf_hash(tree, 845, node_hash))
        || !TEST_true(ossl_mtc_tree_subtree_hash(tree, subtree, want))
        || !TEST_true(ossl_mtc_tree_inclusion_proof(tree, 845, subtree,
            &proof, &proof_len)))
        goto err;

    /* A wrong node hash still evaluates, but to the wrong root. */
    if (!TEST_true(leaf_hash(tree, 846, wrong_hash))
        || !TEST_true(ossl_mtc_eval_subtree_inclusion_proof(
            proof, proof_len, 845, wrong_hash, subtree, got)))
        goto err;
    if (!TEST_mem_ne(got, OSSL_MTC_HASH_LEN, want, OSSL_MTC_HASH_LEN))
        goto err;

    /* An invalid subtree fails. */
    bad.start = 840;
    bad.end = 849;
    if (!TEST_false(ossl_mtc_eval_subtree_inclusion_proof(
            proof, proof_len, 845, node_hash, bad, got)))
        goto err;

    /* An index outside the subtree fails. */
    if (!TEST_false(ossl_mtc_eval_subtree_inclusion_proof(
            proof, proof_len, 848, node_hash, subtree, got)))
        goto err;

    ret = 1;
err:
    OPENSSL_free(proof);
    ossl_mtc_tree_free(tree);
    return ret;
}

/*
 * Check that generated proofs match the structural examples in RFC 9162
 * section 2.1.5, computed over this implementation's own tree of 7 leaves.
 */
static int test_rfc9162_structure(void)
{
    OSSL_MTC_TREE *tree = build_tree(7);
    OSSL_MTC_SUBTREE full = { 0, 7 };
    struct {
        uint64_t start, end;
    } parts[] = {
        { 1, 2 }, /* 0: b */
        { 2, 3 }, /* 1: c */
        { 3, 4 }, /* 2: d */
        { 5, 6 }, /* 3: f */
        { 0, 2 }, /* 4: g */
        { 2, 4 }, /* 5: h */
        { 4, 6 }, /* 6: i */
        { 6, 7 }, /* 7: j */
        { 0, 4 }, /* 8: k */
        { 4, 7 } /* 9: l */
    };
    enum { B,
        C,
        D,
        F,
        G,
        H,
        I,
        J,
        K,
        L };
    uint8_t part[10][OSSL_MTC_HASH_LEN];
    uint8_t expected[4 * OSSL_MTC_HASH_LEN];
    uint8_t *proof = NULL;
    size_t proof_len = 0, i;
    OSSL_MTC_SUBTREE sub;
    int ret = 0;

    if (!TEST_ptr(tree))
        goto err;
    for (i = 0; i < OSSL_NELEM(parts); i++) {
        sub.start = parts[i].start;
        sub.end = parts[i].end;
        if (!TEST_true(ossl_mtc_tree_subtree_hash(tree, sub, part[i])))
            goto err;
    }

    /* Inclusion proof for d0 is [b, h, l]. */
    memcpy(expected, part[B], OSSL_MTC_HASH_LEN);
    memcpy(expected + OSSL_MTC_HASH_LEN, part[H], OSSL_MTC_HASH_LEN);
    memcpy(expected + 2 * OSSL_MTC_HASH_LEN, part[L], OSSL_MTC_HASH_LEN);
    if (!TEST_true(ossl_mtc_tree_inclusion_proof(tree, 0, full, &proof,
            &proof_len))
        || !TEST_mem_eq(proof, proof_len, expected, 3 * OSSL_MTC_HASH_LEN))
        goto err;
    OPENSSL_free(proof);
    proof = NULL;

    /* Inclusion proof for d3 is [c, g, l]. */
    memcpy(expected, part[C], OSSL_MTC_HASH_LEN);
    memcpy(expected + OSSL_MTC_HASH_LEN, part[G], OSSL_MTC_HASH_LEN);
    memcpy(expected + 2 * OSSL_MTC_HASH_LEN, part[L], OSSL_MTC_HASH_LEN);
    if (!TEST_true(ossl_mtc_tree_inclusion_proof(tree, 3, full, &proof,
            &proof_len))
        || !TEST_mem_eq(proof, proof_len, expected, 3 * OSSL_MTC_HASH_LEN))
        goto err;
    OPENSSL_free(proof);
    proof = NULL;

    /* Inclusion proof for d6 is [i, k]. */
    memcpy(expected, part[I], OSSL_MTC_HASH_LEN);
    memcpy(expected + OSSL_MTC_HASH_LEN, part[K], OSSL_MTC_HASH_LEN);
    if (!TEST_true(ossl_mtc_tree_inclusion_proof(tree, 6, full, &proof,
            &proof_len))
        || !TEST_mem_eq(proof, proof_len, expected, 2 * OSSL_MTC_HASH_LEN))
        goto err;
    OPENSSL_free(proof);
    proof = NULL;

    /* Consistency proof between hash0 [0, 3) and the tree is [c, d, g, l]. */
    memcpy(expected, part[C], OSSL_MTC_HASH_LEN);
    memcpy(expected + OSSL_MTC_HASH_LEN, part[D], OSSL_MTC_HASH_LEN);
    memcpy(expected + 2 * OSSL_MTC_HASH_LEN, part[G], OSSL_MTC_HASH_LEN);
    memcpy(expected + 3 * OSSL_MTC_HASH_LEN, part[L], OSSL_MTC_HASH_LEN);
    sub.start = 0;
    sub.end = 3;
    if (!TEST_true(ossl_mtc_tree_consistency_proof(tree, sub, full, &proof,
            &proof_len))
        || !TEST_mem_eq(proof, proof_len, expected, 4 * OSSL_MTC_HASH_LEN))
        goto err;
    OPENSSL_free(proof);
    proof = NULL;

    /* Consistency proof between hash2 [0, 6) and the tree is [i, j, k]. */
    memcpy(expected, part[I], OSSL_MTC_HASH_LEN);
    memcpy(expected + OSSL_MTC_HASH_LEN, part[J], OSSL_MTC_HASH_LEN);
    memcpy(expected + 2 * OSSL_MTC_HASH_LEN, part[K], OSSL_MTC_HASH_LEN);
    sub.start = 0;
    sub.end = 6;
    if (!TEST_true(ossl_mtc_tree_consistency_proof(tree, sub, full, &proof,
            &proof_len))
        || !TEST_mem_eq(proof, proof_len, expected, 3 * OSSL_MTC_HASH_LEN))
        goto err;

    ret = 1;
err:
    OPENSSL_free(proof);
    ossl_mtc_tree_free(tree);
    return ret;
}

/*
 * Exhaustively generate and verify inclusion and consistency proofs for all
 * valid subtrees of all tree sizes up to MTC_TEST_LIMIT.
 */
static int test_exhaustive(void)
{
    OSSL_MTC_TREE *tree = build_tree(MTC_TEST_LIMIT);
    uint8_t subtree_hash[OSSL_MTC_HASH_LEN];
    uint8_t entry_hash[OSSL_MTC_HASH_LEN];
    uint8_t tree_hash[OSSL_MTC_HASH_LEN];
    uint8_t got[OSSL_MTC_HASH_LEN];
    uint8_t *proof = NULL;
    size_t proof_len = 0;
    uint64_t n, start, end, index;
    OSSL_MTC_SUBTREE subtree, full;
    int ret = 0;

    if (!TEST_ptr(tree))
        goto err;

    /* Consistency proofs against every prefix tree size. */
    for (n = 1; n < MTC_TEST_LIMIT; n++) {
        full.start = 0;
        full.end = n;
        if (!TEST_true(ossl_mtc_tree_subtree_hash(tree, full, tree_hash)))
            goto err;
        for (end = 1; end <= n; end++) {
            for (start = 0; start < end; start++) {
                subtree.start = start;
                subtree.end = end;
                if (!ossl_mtc_subtree_is_valid(subtree))
                    continue;
                if (!TEST_true(ossl_mtc_tree_subtree_hash(tree, subtree,
                        subtree_hash))
                    || !TEST_true(ossl_mtc_tree_consistency_proof(
                        tree, subtree, full, &proof, &proof_len))
                    || !TEST_true(ossl_mtc_eval_subtree_consistency_proof(
                        n, subtree, proof, proof_len, subtree_hash,
                        got))
                    || !TEST_mem_eq(got, OSSL_MTC_HASH_LEN, tree_hash,
                        OSSL_MTC_HASH_LEN))
                    goto err;
                OPENSSL_free(proof);
                proof = NULL;
            }
        }
    }

    /* Inclusion proofs for every leaf of every valid subtree. */
    for (end = 1; end <= MTC_TEST_LIMIT; end++) {
        for (start = 0; start < end; start++) {
            subtree.start = start;
            subtree.end = end;
            if (!ossl_mtc_subtree_is_valid(subtree))
                continue;
            if (!TEST_true(ossl_mtc_tree_subtree_hash(tree, subtree,
                    subtree_hash)))
                goto err;
            for (index = start; index < end; index++) {
                if (!TEST_true(leaf_hash(tree, index, entry_hash))
                    || !TEST_true(ossl_mtc_tree_inclusion_proof(
                        tree, index, subtree, &proof, &proof_len))
                    || !TEST_true(ossl_mtc_eval_subtree_inclusion_proof(
                        proof, proof_len, index, entry_hash, subtree,
                        got))
                    || !TEST_mem_eq(got, OSSL_MTC_HASH_LEN, subtree_hash,
                        OSSL_MTC_HASH_LEN))
                    goto err;
                OPENSSL_free(proof);
                proof = NULL;
            }
        }
    }

    ret = 1;
err:
    OPENSSL_free(proof);
    ossl_mtc_tree_free(tree);
    return ret;
}

/*
 * Assert that proof equals the concatenation of the hashes of the given
 * subtrees, computed over tree.  Used to check generated proofs against the
 * worked examples in the specification.
 */
static int check_proof_parts(const uint8_t *proof, size_t proof_len,
    const OSSL_MTC_TREE *tree, const OSSL_MTC_SUBTREE *parts, size_t nparts)
{
    uint8_t want[8 * OSSL_MTC_HASH_LEN];
    size_t i;

    if (!TEST_size_t_le(nparts, OSSL_NELEM(want) / OSSL_MTC_HASH_LEN))
        return 0;
    for (i = 0; i < nparts; i++)
        if (!TEST_true(ossl_mtc_tree_subtree_hash(tree, parts[i],
                want + i * OSSL_MTC_HASH_LEN)))
            return 0;
    return TEST_mem_eq(proof, proof_len, want, nparts * OSSL_MTC_HASH_LEN);
}

/*
 * The specific worked examples from section 4 of
 * draft-ietf-plants-merkle-tree-certs-04.  The subtree [4, 8) is full and
 * [8, 13) is partial (Figures 3-5); both are checked for validity and
 * containment, then the inclusion proof of Figure 6 and the consistency
 * proofs of Figures 7 and 8 are reproduced exactly and evaluated.
 *
 * The arbitrary-interval covering of section 4.5 (Figures 9 and 10) is
 * exercised separately in test_find_subtrees.
 */
static int test_plants_section4_examples(void)
{
    OSSL_MTC_TREE *t13 = build_tree(13);
    OSSL_MTC_TREE *t14 = build_tree(14);
    OSSL_MTC_SUBTREE full13 = { 0, 13 };
    OSSL_MTC_SUBTREE full14 = { 0, 14 };
    OSSL_MTC_SUBTREE s48 = { 4, 8 }; /* full subtree */
    OSSL_MTC_SUBTREE s813 = { 8, 13 }; /* partial subtree */
    uint8_t node_hash[OSSL_MTC_HASH_LEN];
    uint8_t entry_hash[OSSL_MTC_HASH_LEN];
    uint8_t want[OSSL_MTC_HASH_LEN];
    uint8_t got[OSSL_MTC_HASH_LEN];
    uint8_t *proof = NULL;
    size_t proof_len = 0;
    int ret = 0;

    if (!TEST_ptr(t13) || !TEST_ptr(t14))
        goto err;

    /* Section 4.1/4.2: [4, 8) and [8, 13) are valid, in a size-13 tree. */
    if (!TEST_true(ossl_mtc_subtree_is_valid(s48))
        || !TEST_uint64_t_eq(ossl_mtc_subtree_leaf_count(s48), 4)
        || !TEST_true(ossl_mtc_subtree_is_valid(s813))
        || !TEST_uint64_t_eq(ossl_mtc_subtree_leaf_count(s813), 5)
        || !TEST_true(ossl_mtc_subtree_contains_subtree(full13, s48))
        || !TEST_true(ossl_mtc_subtree_contains_subtree(full13, s813)))
        goto err;

    /*
     * Figure 6: the inclusion proof for entry 10 of subtree [8, 13) is
     * [MTH({d[11]}), MTH(D[8:10]), MTH({d[12]})].
     */
    {
        OSSL_MTC_SUBTREE parts[] = { { 11, 12 }, { 8, 10 }, { 12, 13 } };

        if (!TEST_true(ossl_mtc_tree_inclusion_proof(t13, 10, s813, &proof,
                &proof_len))
            || !check_proof_parts(proof, proof_len, t13, parts,
                OSSL_NELEM(parts))
            || !TEST_true(leaf_hash(t13, 10, entry_hash))
            || !TEST_true(ossl_mtc_tree_subtree_hash(t13, s813, want))
            || !TEST_true(ossl_mtc_eval_subtree_inclusion_proof(proof,
                proof_len, 10, entry_hash, s813, got))
            || !TEST_mem_eq(got, OSSL_MTC_HASH_LEN, want, OSSL_MTC_HASH_LEN))
            goto err;
        OPENSSL_free(proof);
        proof = NULL;
    }

    /*
     * Figure 7: the consistency proof for [4, 8) in a size-14 tree is
     * [MTH(D[0:4]), MTH(D[8:14])].
     */
    {
        OSSL_MTC_SUBTREE parts[] = { { 0, 4 }, { 8, 14 } };

        if (!TEST_true(ossl_mtc_tree_consistency_proof(t14, s48, full14, &proof,
                &proof_len))
            || !check_proof_parts(proof, proof_len, t14, parts,
                OSSL_NELEM(parts))
            || !TEST_true(ossl_mtc_tree_subtree_hash(t14, s48, node_hash))
            || !TEST_true(ossl_mtc_tree_subtree_hash(t14, full14, want))
            || !TEST_true(ossl_mtc_eval_subtree_consistency_proof(14, s48,
                proof, proof_len, node_hash, got))
            || !TEST_mem_eq(got, OSSL_MTC_HASH_LEN, want, OSSL_MTC_HASH_LEN))
            goto err;
        OPENSSL_free(proof);
        proof = NULL;
    }

    /*
     * Figure 8: the consistency proof for the partial subtree [8, 13) in a
     * size-14 tree is [MTH({d[12]}), MTH({d[13]}), MTH(D[8:12]), MTH(D[0:8])].
     * [8, 13) is not directly contained in the size-14 tree, yet the proof
     * still recomputes the root, demonstrating the consistent elements.
     */
    {
        OSSL_MTC_SUBTREE parts[] = { { 12, 13 }, { 13, 14 }, { 8, 12 },
            { 0, 8 } };

        if (!TEST_true(ossl_mtc_tree_consistency_proof(t14, s813, full14, &proof,
                &proof_len))
            || !check_proof_parts(proof, proof_len, t14, parts,
                OSSL_NELEM(parts))
            || !TEST_true(ossl_mtc_tree_subtree_hash(t14, s813, node_hash))
            || !TEST_true(ossl_mtc_tree_subtree_hash(t14, full14, want))
            || !TEST_true(ossl_mtc_eval_subtree_consistency_proof(14, s813,
                proof, proof_len, node_hash, got))
            || !TEST_mem_eq(got, OSSL_MTC_HASH_LEN, want, OSSL_MTC_HASH_LEN))
            goto err;
    }

    ret = 1;
err:
    OPENSSL_free(proof);
    ossl_mtc_tree_free(t13);
    ossl_mtc_tree_free(t14);
    return ret;
}

/* Report whether x is a power of two. */
static int is_power_of_two(uint64_t x)
{
    return x != 0 && (x & (x - 1)) == 0;
}

/*
 * Section 4.5: covering an arbitrary interval with up to two subtrees,
 * including the worked examples of Figures 9 ([5, 13)) and 10 ([7, 9)), plus
 * an exhaustive check of the covering properties for all small intervals.
 */
static int test_find_subtrees(void)
{
    OSSL_MTC_SUBTREE out[2];
    OSSL_MTC_SUBTREE iv;
    uint64_t start, end;

    /* Figure 9: [5, 13) is covered by [4, 8) and [8, 13). */
    iv.start = 5;
    iv.end = 13;
    if (!TEST_size_t_eq(ossl_mtc_find_subtrees(iv, out), 2)
        || !TEST_uint64_t_eq(out[0].start, 4)
        || !TEST_uint64_t_eq(out[0].end, 8)
        || !TEST_uint64_t_eq(out[1].start, 8)
        || !TEST_uint64_t_eq(out[1].end, 13))
        return 0;

    /* Figure 10: [7, 9) is covered by [7, 8) and [8, 9). */
    iv.start = 7;
    iv.end = 9;
    if (!TEST_size_t_eq(ossl_mtc_find_subtrees(iv, out), 2)
        || !TEST_uint64_t_eq(out[0].start, 7)
        || !TEST_uint64_t_eq(out[0].end, 8)
        || !TEST_uint64_t_eq(out[1].start, 8)
        || !TEST_uint64_t_eq(out[1].end, 9))
        return 0;

    /* A one-leaf interval returns itself as a single subtree. */
    iv.start = 5;
    iv.end = 6;
    if (!TEST_size_t_eq(ossl_mtc_find_subtrees(iv, out), 1)
        || !TEST_uint64_t_eq(out[0].start, 5)
        || !TEST_uint64_t_eq(out[0].end, 6))
        return 0;

    /* Exhaustively check the section 4.5 covering properties. */
    for (end = 1; end <= 64; end++) {
        for (start = 0; start < end; start++) {
            size_t k;

            iv.start = start;
            iv.end = end;
            k = ossl_mtc_find_subtrees(iv, out);

            if (k == 1) {
                if (!TEST_true(ossl_mtc_subtree_is_valid(out[0]))
                    || !TEST_uint64_t_eq(out[0].start, start)
                    || !TEST_uint64_t_eq(out[0].end, end))
                    return 0;
                continue;
            }

            if (!TEST_size_t_eq(k, 2)
                || !TEST_true(ossl_mtc_subtree_is_valid(out[0]))
                || !TEST_true(ossl_mtc_subtree_is_valid(out[1]))
                || !TEST_uint64_t_eq(out[0].end, out[1].start)
                || !TEST_true(out[0].start <= start)
                || !TEST_uint64_t_eq(out[1].end, end)
                || !TEST_true(
                    is_power_of_two(ossl_mtc_subtree_leaf_count(out[0])))
                || !TEST_true(
                    ossl_mtc_subtree_leaf_count(out[0]) < 2 * (end - start))
                || !TEST_true(
                    ossl_mtc_subtree_leaf_count(out[1]) <= end - start))
                return 0;
        }
    }
    return 1;
}

int setup_tests(void)
{
    ADD_TEST(test_subtree_is_valid);
    ADD_TEST(test_subtree_split);
    ADD_TEST(test_inclusion_roundtrip);
    ADD_TEST(test_inclusion_invalid_args);
    ADD_TEST(test_rfc9162_structure);
    ADD_TEST(test_plants_section4_examples);
    ADD_TEST(test_find_subtrees);
    ADD_TEST(test_exhaustive);
    return 1;
}
