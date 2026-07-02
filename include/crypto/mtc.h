/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Internal Merkle Tree Certificate (MTC) subtree support.  Not for
 * application use.
 *
 * This implements the Merkle-tree subtree operations from section 4 of
 * draft-ietf-plants-merkle-tree-certs-04: the definition of a subtree, the
 * verification of subtree inclusion proofs (section 4.3), and the
 * verification of subtree consistency proofs (section 4.4).  For the
 * whole-tree case these degenerate to the inclusion and consistency proofs
 * of RFC 9162.
 *
 * An in-memory Merkle tree builder is also provided so that tests and
 * tooling can generate the proofs that the evaluators verify.
 *
 * These are internal interfaces: callers are expected to pass valid, non-NULL
 * pointers.  The functions do not check for NULL and are explicitly not
 * NULL-safe, the sole exception being ossl_mtc_tree_free(), which accepts a
 * NULL tree.
 */

#if !defined(OSSL_CRYPTO_MTC_H)
#define OSSL_CRYPTO_MTC_H

#include <stddef.h>
#include <stdint.h>

/** Length in bytes of a Merkle tree node hash (SHA-256). */
#define OSSL_MTC_HASH_LEN 32

/**
 * @struct ossl_mtc_subtree_st
 * @brief A range of leaves in a Merkle tree, the half-open interval
 * [start, end).
 *
 * This corresponds to a "subtree" as defined in section 4.1 of
 * draft-ietf-plants-merkle-tree-certs-04.  A subtree is valid only when it is
 * non-empty and its left edge is suitably aligned; see
 * ossl_mtc_subtree_is_valid().
 */
typedef struct ossl_mtc_subtree_st {
    uint64_t start; /**< index of the first leaf in the range */
    uint64_t end; /**< index one past the last leaf in the range */
} OSSL_MTC_SUBTREE;

/**
 * @brief Report whether a subtree is well-formed.
 *
 * A subtree is valid when it is a non-empty interval whose left edge does
 * not have a "ragged" alignment: writing k for the largest power of two that
 * divides start, the size must not exceed k (this always holds when start is
 * zero).  This is the section 4.1 rule that start be a multiple of the
 * smallest power of two not less than the size.
 *
 * @returns 1 if subtree is valid, 0 otherwise.
 */
int ossl_mtc_subtree_is_valid(OSSL_MTC_SUBTREE subtree);

/**
 * @brief Return the number of leaves in a subtree (end - start).
 *
 * This count is what section 4.1 of the draft calls the subtree's "size".
 */
uint64_t ossl_mtc_subtree_leaf_count(OSSL_MTC_SUBTREE subtree);

/**
 * @brief Return the split point of a subtree.
 *
 * The split point k is the index at which the subtree divides into its left
 * child [start, k) and right child [k, end), sharing no interior nodes.
 * Neither child is empty unless the subtree has fewer than two leaves, in
 * which case end is returned.
 *
 * @returns the split index.
 */
uint64_t ossl_mtc_subtree_split(OSSL_MTC_SUBTREE subtree);

/**
 * @brief Return the left child [start, split) of a subtree, or the subtree
 * itself if it has fewer than two leaves.
 */
OSSL_MTC_SUBTREE ossl_mtc_subtree_left(OSSL_MTC_SUBTREE subtree);

/**
 * @brief Return the right child [split, end) of a subtree, or an empty
 * (invalid) subtree if it has fewer than two leaves.
 */
OSSL_MTC_SUBTREE ossl_mtc_subtree_right(OSSL_MTC_SUBTREE subtree);

/**
 * @brief Report whether a subtree contains a given leaf index.
 * @returns 1 if start <= index < end, 0 otherwise.
 */
int ossl_mtc_subtree_contains_index(OSSL_MTC_SUBTREE subtree, uint64_t index);

/**
 * @brief Report whether the outer subtree contains the inner one.
 * @returns 1 if inner lies within outer, 0 otherwise.
 */
int ossl_mtc_subtree_contains_subtree(OSSL_MTC_SUBTREE outer,
    OSSL_MTC_SUBTREE inner);

/**
 * @brief Cover an arbitrary interval with up to two subtrees, per section 4.5
 * of draft-ietf-plants-merkle-tree-certs-04.
 *
 * Given any half-open interval [start, end) with start < end, this returns
 * one or two valid subtrees that efficiently cover it.  A single subtree is
 * returned only for a one-leaf interval, in which case it is the interval
 * itself.  When two are returned they are adjacent (out[0].end ==
 * out[1].start) and together cover the interval (out[0].start <= start and
 * out[1].end == end, possibly with a few extra leaves before start); out[0]
 * is full and out[1] may be partial.
 *
 * @param interval the interval [start, end) to cover; start must be < end
 * @param out array of length two receiving the covering subtrees
 * @returns the number of subtrees written to out, 1 or 2.
 */
size_t ossl_mtc_find_subtrees(OSSL_MTC_SUBTREE interval,
    OSSL_MTC_SUBTREE out[2]);

/**
 * @brief Compute the hash of a Merkle tree leaf, HASH(0x00 || entry).
 * @param entry pointer to the leaf's bytes
 * @param entry_len the number of bytes in entry
 * @param out buffer receiving the OSSL_MTC_HASH_LEN byte hash
 * @returns 1 on success, 0 on error.
 */
int ossl_mtc_hash_leaf(const uint8_t *entry, size_t entry_len,
    uint8_t out[OSSL_MTC_HASH_LEN]);

/**
 * @brief Compute the hash of an interior node, HASH(0x01 || left || right).
 *
 * out may alias left or right.
 *
 * @param out buffer receiving the OSSL_MTC_HASH_LEN byte hash
 * @returns 1 on success, 0 on error.
 */
int ossl_mtc_hash_node(const uint8_t left[OSSL_MTC_HASH_LEN],
    const uint8_t right[OSSL_MTC_HASH_LEN],
    uint8_t out[OSSL_MTC_HASH_LEN]);

/**
 * @brief Evaluate a subtree consistency proof, per section 4.4.3 of
 * draft-ietf-plants-merkle-tree-certs-04.
 *
 * Given a Merkle tree over n leaves, a subtree with hash node_hash, and a
 * consistency proof, this recomputes the root hash of the full tree.  Unlike
 * the procedure in the draft, the expected root hash is not an input: the
 * computed root hash is returned and the caller must compare it against the
 * value it trusts.  The proof is a concatenation of OSSL_MTC_HASH_LEN byte
 * node hashes.
 *
 * The internal cursors fn, sn, and tn mirror the "first", "second", and
 * "third" numbers of the draft's procedure.
 *
 * @param n the number of leaves in the full tree
 * @param subtree the subtree the proof is relative to
 * @param proof pointer to the proof bytes
 * @param proof_len the number of proof bytes
 * @param node_hash the trusted hash of subtree
 * @param out_root_hash buffer receiving the computed root hash
 * @returns 1 if the proof was well-formed and consistent with node_hash
 * (out_root_hash is then set), 0 otherwise.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-04/
 */
int ossl_mtc_eval_subtree_consistency_proof(
    uint64_t n, OSSL_MTC_SUBTREE subtree, const uint8_t *proof,
    size_t proof_len, const uint8_t node_hash[OSSL_MTC_HASH_LEN],
    uint8_t out_root_hash[OSSL_MTC_HASH_LEN]);

/**
 * @brief Evaluate a subtree inclusion proof, per section 4.3.2 of
 * draft-ietf-plants-merkle-tree-certs-04.
 *
 * Given the hash of the leaf at index and an inclusion proof, this
 * recomputes the hash of subtree, which the caller must compare against the
 * value it trusts.  An inclusion proof is the special case of a consistency
 * proof for the single-leaf range [index, index + 1).
 *
 * @param inclusion_proof pointer to the proof bytes
 * @param proof_len the number of proof bytes
 * @param index the leaf index being proven, in whole-tree coordinates
 * @param entry_hash the hash of the leaf at index
 * @param subtree the subtree the leaf is claimed to belong to
 * @param out_root_hash buffer receiving the computed subtree hash
 * @returns 1 if the proof was well-formed (out_root_hash is then set),
 * 0 otherwise.
 * @see https://datatracker.ietf.org/doc/draft-ietf-plants-merkle-tree-certs-04/
 */
int ossl_mtc_eval_subtree_inclusion_proof(
    const uint8_t *inclusion_proof, size_t proof_len, uint64_t index,
    const uint8_t entry_hash[OSSL_MTC_HASH_LEN],
    OSSL_MTC_SUBTREE subtree, uint8_t out_root_hash[OSSL_MTC_HASH_LEN]);

/**
 * @struct ossl_mtc_tree_st
 * An in-memory Merkle tree, used to generate proofs for tests and tooling.
 * Opaque; created with ossl_mtc_tree_new().
 */
typedef struct ossl_mtc_tree_st OSSL_MTC_TREE;

/**
 * @brief Allocate a new, empty in-memory Merkle tree.
 * @returns the new tree, or NULL on allocation failure.
 */
OSSL_MTC_TREE *ossl_mtc_tree_new(void);

/** @brief Free an in-memory Merkle tree; tree may be NULL. */
void ossl_mtc_tree_free(OSSL_MTC_TREE *tree);

/**
 * @brief Append a leaf to an in-memory Merkle tree.
 * @param entry pointer to the new leaf's bytes
 * @param entry_len the number of bytes in entry
 * @returns 1 on success, 0 on error.
 */
int ossl_mtc_tree_append(OSSL_MTC_TREE *tree, const uint8_t *entry,
    size_t entry_len);

/**
 * @brief Return the number of leaves in an in-memory Merkle tree.
 *
 * The draft refers to this count as the tree's "size" (n).
 */
uint64_t ossl_mtc_tree_leaf_count(const OSSL_MTC_TREE *tree);

/**
 * @brief Compute the hash of a subtree of an in-memory Merkle tree.
 * @param subtree the subtree to hash; must be valid with end <= size
 * @param out buffer receiving the OSSL_MTC_HASH_LEN byte hash
 * @returns 1 on success, 0 on error.
 */
int ossl_mtc_tree_subtree_hash(const OSSL_MTC_TREE *tree,
    OSSL_MTC_SUBTREE subtree,
    uint8_t out[OSSL_MTC_HASH_LEN]);

/**
 * @brief Generate an inclusion proof for a leaf within a subtree.
 *
 * The returned proof is a heap-allocated concatenation of node hashes,
 * suitable for ossl_mtc_eval_subtree_inclusion_proof().  The caller must
 * free it with OPENSSL_free().
 *
 * @param index the leaf index to prove; must be contained in subtree
 * @param subtree the subtree to prove membership of; must be valid with
 * end <= size
 * @param out_proof set to the allocated proof buffer on success
 * @param out_proof_len set to the length of the proof buffer on success
 * @returns 1 on success, 0 on error.
 */
int ossl_mtc_tree_inclusion_proof(const OSSL_MTC_TREE *tree, uint64_t index,
    OSSL_MTC_SUBTREE subtree,
    uint8_t **out_proof,
    size_t *out_proof_len);

/**
 * @brief Generate a consistency proof for a subtree within a larger tree.
 *
 * The returned proof is a heap-allocated concatenation of node hashes,
 * suitable for ossl_mtc_eval_subtree_consistency_proof().  The caller must
 * free it with OPENSSL_free().
 *
 * @param subtree the subtree the proof is relative to; must be valid and
 * contained in tree_range
 * @param tree_range the larger tree the subtree is proven consistent with;
 * must be valid with end <= size
 * @param out_proof set to the allocated proof buffer on success
 * @param out_proof_len set to the length of the proof buffer on success
 * @returns 1 on success, 0 on error.
 */
int ossl_mtc_tree_consistency_proof(const OSSL_MTC_TREE *tree,
    OSSL_MTC_SUBTREE subtree,
    OSSL_MTC_SUBTREE tree_range,
    uint8_t **out_proof,
    size_t *out_proof_len);

#endif /* defined(OSSL_CRYPTO_MTC_H) */
