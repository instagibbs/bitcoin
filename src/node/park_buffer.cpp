// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/park_buffer.h>

#include <algorithm>
#include <cassert>
#include <utility>

namespace node {

// Every outpoint the package's transactions spend -- including outputs created and then
// spent within the package (parent->child links). The contended outpoint an attacker cycles
// may be such an internal link (e.g. a CPFP anchor spent by the child), and it must be
// indexed so that (a) the package is reinstatable when it frees and (b) disjointness covers
// the whole package.
static std::vector<COutPoint> ComputeFootprint(const std::vector<CTransactionRef>& txns)
{
    std::vector<COutPoint> footprint;
    for (const auto& tx : txns) {
        for (const auto& in : tx->vin) footprint.push_back(in.prevout);
    }
    return footprint;
}

bool ParkBuffer::Park(ParkedPackage package)
{
    const auto footprint = ComputeFootprint(package.txns);

    // Disjointness: reject if the footprint conflicts with any parked package.
    for (const auto& op : footprint) {
        if (m_index.count(op)) return false;
    }

    const uint64_t id = m_next_id++;
    for (const auto& op : footprint) m_index.emplace(op, id);
    m_total_weight += package.weight;
    m_packages.emplace(id, Entry{std::move(package), footprint});

    // Enforce the weight cap by evicting the lowest-value package (possibly this one).
    while (m_total_weight > m_max_weight && !m_packages.empty()) {
        auto lowest = std::min_element(m_packages.begin(), m_packages.end(),
            [](const auto& a, const auto& b) { return a.second.package.value < b.second.package.value; });
        EraseEntry(lowest);
        ++m_evicted_over_cap;
    }
    return true;
}

std::vector<ParkBuffer::ParkedPackage> ParkBuffer::Packages() const
{
    std::vector<ParkedPackage> out;
    out.reserve(m_packages.size());
    for (const auto& [id, entry] : m_packages) out.push_back(entry.package);
    return out;
}

void ParkBuffer::EraseEntry(std::map<uint64_t, Entry>::iterator it)
{
    m_total_weight -= it->second.package.weight;
    for (const auto& op : it->second.footprint) m_index.erase(op);
    m_packages.erase(it);
}

const ParkBuffer::ParkedPackage* ParkBuffer::FindByInput(const COutPoint& outpoint) const
{
    auto it = m_index.find(outpoint);
    if (it == m_index.end()) return nullptr;
    return &m_packages.at(it->second).package;
}

bool ParkBuffer::Remove(const COutPoint& outpoint)
{
    auto idx = m_index.find(outpoint);
    if (idx == m_index.end()) return false;
    EraseEntry(m_packages.find(idx->second));
    return true;
}

size_t ParkBuffer::Size() const { return m_packages.size(); }

int64_t ParkBuffer::TotalWeight() const { return m_total_weight; }

void ParkBuffer::SanityCheck() const
{
    int64_t total = 0;
    std::map<COutPoint, uint64_t> rebuilt_index;
    for (const auto& [id, entry] : m_packages) {
        total += entry.package.weight;
        for (const auto& op : entry.footprint) {
            // Disjointness: every footprint outpoint belongs to exactly one package.
            assert(rebuilt_index.emplace(op, id).second);
        }
    }
    assert(total == m_total_weight);
    assert(rebuilt_index == m_index);
    assert(m_packages.empty() || m_total_weight <= m_max_weight);
}

} // namespace node
