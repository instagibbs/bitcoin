// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_POLICY_V3_POLICY_H
#define BITCOIN_POLICY_V3_POLICY_H

#include <consensus/amount.h>
#include <policy/packages.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <txmempool.h>

#include <string>

// This module enforces rules for transactions with nVersion=3 ("V3 transactions") which help make
// RBF abilities more robust.

// V3 only allows 1 parent and 1 child.
/** Maximum number of transactions including an unconfirmed tx and its descendants. */
static constexpr unsigned int V3_DESCENDANT_LIMIT{2};
/** Maximum number of transactions including a V3 tx and all its mempool ancestors. */
static constexpr unsigned int V3_ANCESTOR_LIMIT{2};

/** Maximum weight of a tx which spends from an unconfirmed V3 transaction. */
static constexpr int64_t V3_CHILD_MAX_WEIGHT{4000};
// Since these limits are within the default ancestor/descendant limits, there is no need to
// additionally check ancestor/descendant limits for V3 transactions.
static_assert(V3_CHILD_MAX_WEIGHT + MAX_STANDARD_TX_WEIGHT <= DEFAULT_ANCESTOR_SIZE_LIMIT_KVB * WITNESS_SCALE_FACTOR * 1000);
static_assert(V3_CHILD_MAX_WEIGHT + MAX_STANDARD_TX_WEIGHT <= DEFAULT_DESCENDANT_SIZE_LIMIT_KVB * WITNESS_SCALE_FACTOR * 1000);

/** Any two unconfirmed transactions with a dependency relationship must either both be V3 or both
 * non-V3. Check this rule for any list of unconfirmed transactions.
 * @returns a tuple (parent wtxid, child wtxid, bool) where one is V3 but the other is not, if at
 * least one such pair exists. The bool represents whether the child is v3 or not. There may be
 * other such pairs that are not returned.
 * Otherwise std::nullopt.
 */
std::optional<std::tuple<uint256, uint256, bool>> CheckV3Inheritance(const Package& package);

/** Every transaction that spends an unconfirmed V3 transaction must also be V3. */
std::optional<std::string> CheckV3Inheritance(const CTransactionRef& ptx,
                                              const CTxMemPool::setEntries& ancestors);

/** The following rules apply to V3 transactions:
 * 1. Tx with all of its ancestors (including non-nVersion=3) must be within V3_ANCESTOR_SIZE_LIMIT_KVB.
 * 2. Tx with all of its ancestors must be within V3_ANCESTOR_LIMIT.
 *
 * If a V3 tx has V3 ancestors,
 * 1. Each V3 ancestor and its descendants must be within V3_DESCENDANT_LIMIT.
 * 2. The tx must be within V3_CHILD_MAX_SIZE.
 *
 * @returns an error string if any V3 rule was violated, otherwise std::nullopt.
 */
std::optional<std::string> ApplyV3Rules(const CTransactionRef& ptx,
                                        const CTxMemPool::setEntries& ancestors,
                                        const std::set<uint256>& direct_conflicts);

#endif // BITCOIN_POLICY_V3_POLICY_H
