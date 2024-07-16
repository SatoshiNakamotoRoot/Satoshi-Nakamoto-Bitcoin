// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CLUSTER_LINEARIZE_H
#define BITCOIN_CLUSTER_LINEARIZE_H

#include <algorithm>
#include <numeric>
#include <optional>
#include <stdint.h>
#include <vector>
#include <utility>

#include <random.h>
#include <util/feefrac.h>
#include <util/vecdeque.h>

namespace cluster_linearize {

/** Data type to represent cluster input.
 *
 * cluster[i].first is tx_i's fee and size.
 * cluster[i].second[j] is true iff tx_i spends one or more of tx_j's outputs.
 */
template<typename SetType>
using Cluster = std::vector<std::pair<FeeFrac, SetType>>;

/** Data type to represent transaction indices in clusters. */
using ClusterIndex = uint32_t;

/** Data structure that holds a transaction graph's preprocessed data (fee, size, ancestors,
 *  descendants). */
template<typename SetType>
class DepGraph
{
    /** Information about a single transaction. */
    struct Entry
    {
        /** Fee and size of transaction itself. */
        FeeFrac feerate;
        /** All ancestors of the transaction (including itself). */
        SetType ancestors;
        /** All descendants of the transaction (including itself). */
        SetType descendants;

        /** Equality operator. */
        friend bool operator==(const Entry&, const Entry&) noexcept = default;

        /** Construct an empty entry. */
        Entry() noexcept = default;
        /** Construct an entry with a given feerate, ancestor set, descendant set. */
        Entry(const FeeFrac& f, const SetType& a, const SetType& d) noexcept : feerate(f), ancestors(a), descendants(d) {}
    };

    /** Data for each transaction, in the same order as the Cluster it was constructed from. */
    std::vector<Entry> entries;

public:
    /** Equality operator (primarily for testing purposes). */
    friend bool operator==(const DepGraph&, const DepGraph&) noexcept = default;

    // Default constructors.
    DepGraph() noexcept = default;
    DepGraph(const DepGraph&) noexcept = default;
    DepGraph(DepGraph&&) noexcept = default;
    DepGraph& operator=(const DepGraph&) noexcept = default;
    DepGraph& operator=(DepGraph&&) noexcept = default;

    /** Construct a DepGraph object for ntx transactions, with no dependencies.
     *
     * Complexity: O(N) where N=ntx.
     **/
    explicit DepGraph(ClusterIndex ntx) noexcept
    {
        Assume(ntx <= SetType::Size());
        entries.resize(ntx);
        for (ClusterIndex i = 0; i < ntx; ++i) {
            entries[i].ancestors = SetType::Singleton(i);
            entries[i].descendants = SetType::Singleton(i);
        }
    }

    /** Construct a DepGraph object given a cluster.
     *
     * Complexity: O(N^2) where N=cluster.size().
     */
    explicit DepGraph(const Cluster<SetType>& cluster) noexcept : entries(cluster.size())
    {
        // Fill in fee, size, parent information.
        for (ClusterIndex i = 0; i < cluster.size(); ++i) {
            entries[i].feerate = cluster[i].first;
            entries[i].ancestors = cluster[i].second;
            // Make sure transactions are ancestors of themselves.
            entries[i].ancestors.Set(i);
        }

        // Propagate ancestor information.
        for (ClusterIndex i = 0; i < entries.size(); ++i) {
            // At this point, entries[a].ancestors[b] is true iff b is an ancestor of a and there
            // is a path from a to b through the subgraph consisting of {a, b} union
            // {0, 1, ..., (i-1)}.
            SetType to_merge = entries[i].ancestors;
            for (ClusterIndex j = 0; j < entries.size(); ++j) {
                if (entries[j].ancestors[i]) {
                    entries[j].ancestors |= to_merge;
                }
            }
        }

        // Fill in descendant information by transposing the ancestor information.
        for (ClusterIndex i = 0; i < entries.size(); ++i) {
            for (auto j : entries[i].ancestors) {
                entries[j].descendants.Set(i);
            }
        }
    }

    /** Construct a DepGraph object given another DepGraph and a mapping from old to new.
     *
     * Complexity: O(N^2) where N=depgraph.TxCount().
     */
    DepGraph(const DepGraph<SetType>& depgraph, Span<const ClusterIndex> mapping) noexcept : entries(depgraph.TxCount())
    {
        Assert(mapping.size() == depgraph.TxCount());
        // Fill in fee, size, ancestors.
        for (ClusterIndex i = 0; i < depgraph.TxCount(); ++i) {
            const auto& input = depgraph.entries[i];
            auto& output = entries[mapping[i]];
            output.feerate = input.feerate;
            for (auto j : input.ancestors) output.ancestors.Set(mapping[j]);
        }
        // Fill in descendant information.
        for (ClusterIndex i = 0; i < entries.size(); ++i) {
            for (auto j : entries[i].ancestors) {
                entries[j].descendants.Set(i);
            }
        }
    }

    /** Get the number of transactions in the graph. Complexity: O(1). */
    auto TxCount() const noexcept { return entries.size(); }
    /** Get the feerate of a given transaction i. Complexity: O(1). */
    const FeeFrac& FeeRate(ClusterIndex i) const noexcept { return entries[i].feerate; }
    /** Get the ancestors of a given transaction i. Complexity: O(1). */
    const SetType& Ancestors(ClusterIndex i) const noexcept { return entries[i].ancestors; }
    /** Get the descendants of a given transaction i. Complexity: O(1). */
    const SetType& Descendants(ClusterIndex i) const noexcept { return entries[i].descendants; }

    /** Add a new unconnected transaction to this transaction graph (at the end), and return its
     *  ClusterIndex.
     *
     * Complexity: O(1) (amortized, due to resizing of backing vector).
     */
    ClusterIndex AddTransaction(const FeeFrac& feefrac) noexcept
    {
        Assume(TxCount() < SetType::Size());
        ClusterIndex new_idx = TxCount();
        entries.emplace_back(feefrac, SetType::Singleton(new_idx), SetType::Singleton(new_idx));
        return new_idx;
    }

    /** Modify this transaction graph, adding a dependency between a specified parent and child.
     *
     * Complexity: O(N) where N=TxCount().
     **/
    void AddDependency(ClusterIndex parent, ClusterIndex child) noexcept
    {
        // To each ancestor of the parent, add as descendants the descendants of the child.
        const auto& chl_des = entries[child].descendants;
        for (auto anc_of_par : Ancestors(parent)) {
            entries[anc_of_par].descendants |= chl_des;
        }
        // To each descendant of the child, add as ancestors the ancestors of the parent.
        const auto& par_anc = entries[parent].ancestors;
        for (auto dec_of_chl : Descendants(child)) {
            entries[dec_of_chl].ancestors |= par_anc;
        }
    }

    /** Compute the aggregate feerate of a set of nodes in this graph.
     *
     * Complexity: O(N) where N=elems.Count().
     **/
    FeeFrac FeeRate(const SetType& elems) const noexcept
    {
        FeeFrac ret;
        for (auto pos : elems) ret += entries[pos].feerate;
        return ret;
    }

    /** Find some connected component within the subset "todo" of this graph.
     *
     * Complexity: O(ret.Count()).
     */
    SetType FindConnectedComponent(const SetType& todo) const noexcept
    {
        if (todo.None()) return todo;
        auto first = todo.First();
        SetType ret = Descendants(first) | Ancestors(first);
        ret &= todo;
        SetType to_add = ret;
        to_add.Reset(first);
        do {
            SetType old = ret;
            for (auto add : to_add) {
                ret |= Descendants(add);
                ret |= Ancestors(add);
            }
            ret &= todo;
            to_add = ret - old;
        } while (to_add.Any());
        return ret;
    }

    /** Determine if a subset is connected.
     *
     * Complexity: O(subset.Count()).
     */
    bool IsConnected(const SetType& subset) const noexcept
    {
        return FindConnectedComponent(subset) == subset;
    }

    /** Determine if this entire graph is connected.
     *
     * Complexity: O(TxCount()).
     */
    bool IsConnected() const noexcept { return IsConnected(SetType::Fill(TxCount())); }

    /** Append the entries of select to list in a topologically valid order.
     *
     * Complexity: O(select.Count() * log(select.Count())).
     */
    void AppendTopo(std::vector<ClusterIndex>& list, const SetType& select) const noexcept
    {
        ClusterIndex old_len = list.size();
        for (auto i : select) list.push_back(i);
        std::sort(list.begin() + old_len, list.end(), [&](ClusterIndex a, ClusterIndex b) noexcept {
            const auto a_anc_count = entries[a].ancestors.Count();
            const auto b_anc_count = entries[b].ancestors.Count();
            if (a_anc_count != b_anc_count) return a_anc_count < b_anc_count;
            return a < b;
        });
    }
};

/** A set of transactions together with their aggregate feerate. */
template<typename SetType>
struct SetInfo
{
    /** The transactions in the set. */
    SetType transactions;
    /** Their combined fee and size. */
    FeeFrac feerate;

    /** Construct a SetInfo for the empty set. */
    SetInfo() noexcept = default;

    /** Construct a SetInfo for a specified set and feerate. */
    SetInfo(const SetType& txn, const FeeFrac& fr) noexcept : transactions(txn), feerate(fr) {}

    /** Construct a SetInfo for a given transaction in a depgraph. */
    explicit SetInfo(const DepGraph<SetType>& depgraph, ClusterIndex pos) noexcept :
        transactions(SetType::Singleton(pos)), feerate(depgraph.FeeRate(pos)) {}

    /** Construct a SetInfo for a set of transactions in a depgraph. */
    explicit SetInfo(const DepGraph<SetType>& depgraph, const SetType& txn) noexcept :
        transactions(txn), feerate(depgraph.FeeRate(txn)) {}

    /** Add a transaction to this SetInfo. */
    void Set(const DepGraph<SetType>& depgraph, ClusterIndex pos) noexcept
    {
        Assume(!transactions[pos]);
        transactions.Set(pos);
        feerate += depgraph.FeeRate(pos);
    }

    /** Add the transactions of other to this SetInfo (no overlap allowed). */
    SetInfo& operator|=(const SetInfo& other) noexcept
    {
        Assume(!transactions.Overlaps(other.transactions));
        transactions |= other.transactions;
        feerate += other.feerate;
        return *this;
    }

    /** Construct a new SetInfo equal to this, with more transactions added (which may overlap
     *  with the existing transactions in the SetInfo). */
    [[nodiscard]] SetInfo Add(const DepGraph<SetType>& depgraph, const SetType& txn) const noexcept
    {
        return {transactions | txn, feerate + depgraph.FeeRate(txn - transactions)};
    }

    /** Construct a new SetInfo equal to this, with some transactions removed. */
    [[nodiscard]] SetInfo Remove(const DepGraph<SetType>& depgraph, const SetType& txn) const noexcept
    {
        return {transactions - txn, feerate - depgraph.FeeRate(txn & transactions)};
    }

    /** Swap two SetInfo objects. */
    friend void swap(SetInfo& a, SetInfo& b) noexcept
    {
        swap(a.transactions, b.transactions);
        swap(a.feerate, b.feerate);
    }

    /** Permit equality testing. */
    friend bool operator==(const SetInfo&, const SetInfo&) noexcept = default;
};

/** Compute the feerates of the chunks of the part of linearization that remains in todo. */
template<typename SetType>
std::vector<FeeFrac> ChunkLinearization(const DepGraph<SetType>& depgraph, Span<const ClusterIndex> linearization) noexcept
{
    std::vector<FeeFrac> ret;
    for (ClusterIndex i : linearization) {
        /** The new chunk to be added, initially a singleton. */
        auto new_chunk = depgraph.FeeRate(i);
        // As long as the new chunk has a higher feerate than the last chunk so far, absorb it.
        while (!ret.empty() && new_chunk >> ret.back()) {
            new_chunk += ret.back();
            ret.pop_back();
        }
        // Actually move that new chunk into the chunking.
        ret.push_back(std::move(new_chunk));
    }
    return ret;
}

/** Data structure encapsulating the chunking of a linearization, permitting removal of subsets. */
template<typename SetType>
class LinearizationChunking
{
    /** The depgraph this linearization is for. */
    const DepGraph<SetType>& m_depgraph;

    /** The linearization we started from, possibly with removed prefix stripped. */
    Span<const ClusterIndex> m_linearization;

    /** Chunk sets and their feerates, of what remains of the linearization. */
    std::vector<SetInfo<SetType>> m_chunks;

    /** How large a prefix of m_chunks corresponds to removed transactions. */
    ClusterIndex m_chunks_skip{0};

    /** Which transactions remain in the linearization. */
    SetType m_todo;

    /** Fill the m_chunks variable, updating lin_done in the process. */
    void BuildChunks() noexcept
    {
        // Caller must clear m_chunks.
        Assume(m_chunks.empty());

        // Chop off the initial part of m_linearization that is already done.
        while (!m_linearization.empty() && !m_todo[m_linearization.front()]) {
            m_linearization = m_linearization.subspan(1);
        }

        // Iterate over the remaining entries in m_linearization. This is effectively the same
        // algorithm as ChunkLinearization, but supports skipping parts of the linearization and
        // keeps track of the sets themselves instead of just their feerates.
        for (auto idx : m_linearization) {
            if (!m_todo[idx]) continue;
            // Start with an initial chunk containing just element idx.
            SetInfo add(m_depgraph, idx);
            // Absorb existing final chunks into add while they have lower feerate.
            while (!m_chunks.empty() && add.feerate >> m_chunks.back().feerate) {
                add |= m_chunks.back();
                m_chunks.pop_back();
            }
            // Remember new chunk.
            m_chunks.push_back(std::move(add));
        }
    }

public:
    /** Initialize a LinearizationSubset object for a given length of linearization. */
    explicit LinearizationChunking(const DepGraph<SetType>& depgraph LIFETIMEBOUND, Span<const ClusterIndex> lin LIFETIMEBOUND) noexcept :
        m_depgraph(depgraph), m_linearization(lin)
    {
        // Mark everything in lin as todo still.
        for (auto i : m_linearization) m_todo.Set(i);
        // Compute the initial chunking.
        m_chunks.reserve(depgraph.TxCount());
        BuildChunks();
    }

    /** Determine how many chunks remain in the linearization. */
    ClusterIndex ChunksLeft() const noexcept { return m_chunks.size() - m_chunks_skip; }

    /** Access a chunk. Chunk 0 is the highest-feerate prefix of what remains. */
    const SetInfo<SetType>& GetChunk(ClusterIndex n) const noexcept
    {
        Assume(n + m_chunks_skip < m_chunks.size());
        return m_chunks[n + m_chunks_skip];
    }

    /** Remove some subset of transactions from the linearization. */
    void MarkDone(SetType subset) noexcept
    {
        Assume(subset.IsSubsetOf(m_todo));
        m_todo -= subset;
        if (GetChunk(0).transactions == subset) {
            // If the newly done transactions exactly match the first chunk of the remainder of
            // the linearization, we do not need to rechunk; just remember to skip one
            // additional chunk.
            ++m_chunks_skip;
            // With subset marked done, some prefix of m_linearization will be done now. How long
            // that prefix is depends on how many done elements were interspersed with subset,
            // but at least as many transactions as there are in subset.
            m_linearization = m_linearization.subspan(subset.Count());
        } else {
            // Otherwise just rechunk what remains of m_linearization.
            m_chunks.clear();
            m_chunks_skip = 0;
            BuildChunks();
        }
    }

    /** Find the shortest intersection between subset and the prefixes of remaining chunks
     *  of the linearization that has a feerate not below best's.
     *
     * This is a crucial operation in guaranteeing improvements to linearizations. The set
     * returned by this function, when moved to the front of (what remains of) the linearization,
     * is guaranteed not to make the linearization worse.
     *
     * See https://delvingbitcoin.org/t/introduction-to-cluster-linearization/1032 for background.
     */
    SetInfo<SetType> Intersect(const SetInfo<SetType>& subset) const noexcept
    {
        Assume(subset.transactions.IsSubsetOf(m_todo));
        SetInfo<SetType> accumulator;
        // Iterate over all chunks of the remaining linearization.
        for (ClusterIndex i = 0; i < ChunksLeft(); ++i) {
            // Find what (if any) intersection the chunk has with subset.
            const SetType to_add = GetChunk(i).transactions & subset.transactions;
            if (to_add.Any()) {
                // If adding that to accumulator makes us hit all of subset, we are done as no
                // shorter intersection with higher/equal feerate exists.
                accumulator.transactions |= to_add;
                if (accumulator.transactions == subset.transactions) break;
                // Otherwise update the accumulator feerate.
                accumulator.feerate += m_depgraph.FeeRate(to_add);
                // If that does result in something better, return that.
                if (!(accumulator.feerate << subset.feerate)) return accumulator;
            }
        }
        return subset;
    }
};

/** Class encapsulating the state needed to find the best remaining ancestor set.
 *
 * It is initialized for an entire DepGraph, and parts of the graph can be dropped by calling
 * MarkDone.
 *
 * As long as any part of the graph remains, FindCandidateSet() can be called which will return a
 * SetInfo with the highest-feerate ancestor set that remains (an ancestor set is a single
 * transaction together with all its remaining ancestors).
 */
template<typename SetType>
class AncestorCandidateFinder
{
    /** Internal dependency graph. */
    const DepGraph<SetType>& m_depgraph;
    /** Which transaction are left to include. */
    SetType m_todo;
    /** Precomputed ancestor-set feerates (only kept up-to-date for indices in m_todo). */
    std::vector<FeeFrac> m_ancestor_set_feerates;

public:
    /** Construct an AncestorCandidateFinder for a given cluster.
     *
     * Complexity: O(N^2) where N=depgraph.TxCount().
     */
    AncestorCandidateFinder(const DepGraph<SetType>& depgraph LIFETIMEBOUND) noexcept :
        m_depgraph(depgraph),
        m_todo{SetType::Fill(depgraph.TxCount())},
        m_ancestor_set_feerates(depgraph.TxCount())
    {
        // Precompute ancestor-set feerates.
        for (ClusterIndex i = 0; i < depgraph.TxCount(); ++i) {
            /** The remaining ancestors for transaction i. */
            SetType anc_to_add = m_depgraph.Ancestors(i);
            FeeFrac anc_feerate;
            // Reuse accumulated feerate from first ancestor, if usable.
            Assume(anc_to_add.Any());
            ClusterIndex first = anc_to_add.First();
            if (first < i) {
                anc_feerate = m_ancestor_set_feerates[first];
                Assume(!anc_feerate.IsEmpty());
                anc_to_add -= m_depgraph.Ancestors(first);
            }
            // Add in other ancestors (which necessarily include i itself).
            Assume(anc_to_add[i]);
            anc_feerate += m_depgraph.FeeRate(anc_to_add);
            // Store the result.
            m_ancestor_set_feerates[i] = anc_feerate;
        }
    }

    /** Remove a set of transactions from the set of to-be-linearized ones.
     *
     * The same transaction may not be MarkDone()'d twice.
     *
     * Complexity: O(N*M) where N=depgraph.TxCount(), M=select.Count().
     */
    void MarkDone(SetType select) noexcept
    {
        Assume(select.IsSubsetOf(m_todo));
        m_todo -= select;
        for (auto i : select) {
            auto feerate = m_depgraph.FeeRate(i);
            for (auto j : m_depgraph.Descendants(i) & m_todo) {
                m_ancestor_set_feerates[j] -= feerate;
            }
        }
    }

    /** Check whether any unlinearized transactions remain. */
    bool AllDone() const noexcept
    {
        return m_todo.None();
    }

    /** Retrieve the set of transactions that remain unlinearized. */
    const SetType& GetTodo() const noexcept
    {
        return m_todo;
    }

    /** Find the best (highest-feerate, smallest among those in case of a tie) ancestor set
     *  among the remaining transactions. Requires !AllDone().
     *
     * Complexity: O(N) where N=depgraph.TxCount();
     */
    SetInfo<SetType> FindCandidateSet() const noexcept
    {
        std::optional<ClusterIndex> best;
        for (auto i : m_todo) {
            if (best.has_value()) {
                Assume(!m_ancestor_set_feerates[i].IsEmpty());
                if (!(m_ancestor_set_feerates[i] > m_ancestor_set_feerates[*best])) continue;
            }
            best = i;
        }
        Assume(best.has_value());
        return {m_depgraph.Ancestors(*best) & m_todo, m_ancestor_set_feerates[*best]};
    }
};

/** Class encapsulating the state needed to perform search for good candidate sets.
 *
 * It is initialized for an entire DepGraph, and parts of the graph can be dropped by calling
 * MarkDone().
 *
 * As long as any part of the graph remains, FindCandidateSet() can be called to perform a search
 * over the set of topologically-valid subsets of that remainder, with a limit on how many
 * combinations are tried.
 */
template<typename SetType>
class SearchCandidateFinder
{
    /** Internal RNG. */
    InsecureRandomContext m_rng;
    /** m_sorted_to_original[i] is the original position that sorted transaction position i had. */
    std::vector<ClusterIndex> m_sorted_to_original;
    /** m_original_to_sorted[i] is the sorted position original transaction position i has. */
    std::vector<ClusterIndex> m_original_to_sorted;
    /** Internal dependency graph for the cluster (with transactions in decreasing individual
     *  feerate order). */
    DepGraph<SetType> m_depgraph;
    /** Which transactions are left to do (indices in m_depgraph's sorted order). */
    SetType m_todo;

    /** Given a set of transactions with sorted indices, get their original indices. */
    SetType SortedToOriginal(const SetType& arg) const noexcept
    {
        SetType ret;
        for (auto pos : arg) ret.Set(m_sorted_to_original[pos]);
        return ret;
    }

    /** Given a set of transactions with original indices, get their sorted indices. */
    SetType OriginalToSorted(const SetType& arg) const noexcept
    {
        SetType ret;
        for (auto pos : arg) ret.Set(m_original_to_sorted[pos]);
        return ret;
    }

public:
    /** Construct a candidate finder for a graph.
     *
     * @param[in] depgraph   Dependency graph for the to-be-linearized cluster.
     * @param[in] rng_seed   A random seed to control the search order.
     *
     * Complexity: O(N^2) where N=depgraph.Count().
     */
    SearchCandidateFinder(const DepGraph<SetType>& depgraph, uint64_t rng_seed) noexcept :
        m_rng(rng_seed),
        m_sorted_to_original(depgraph.TxCount()),
        m_original_to_sorted(depgraph.TxCount())
    {
        // Determine reordering mapping, by sorting by decreasing feerate.
        std::iota(m_sorted_to_original.begin(), m_sorted_to_original.end(), ClusterIndex{0});
        std::sort(m_sorted_to_original.begin(), m_sorted_to_original.end(), [&](auto a, auto b) {
            auto feerate_cmp = depgraph.FeeRate(a) <=> depgraph.FeeRate(b);
            if (feerate_cmp == 0) return a < b;
            return feerate_cmp > 0;
        });
        // Compute reverse mapping.
        for (ClusterIndex i = 0; i < depgraph.TxCount(); ++i) {
            m_original_to_sorted[m_sorted_to_original[i]] = i;
        }
        // Compute reordered dependency graph.
        m_depgraph = DepGraph(depgraph, m_original_to_sorted);
        // Set todo to the entire graph.
        m_todo = SetType::Fill(depgraph.TxCount());
    }

    /** Check whether any unlinearized transactions remain. */
    bool AllDone() const noexcept
    {
        return m_todo.None();
    }

    /** Find a high-feerate topologically-valid subset of what remains of the cluster.
     *  Requires !AllDone().
     *
     * @param[in] max_iterations  The maximum number of optimization steps that will be performed.
     * @param[in] best            A set/feerate pair with an already-known good candidate. This may
     *                            be empty.
     * @return                    A pair of:
     *                            - The best (highest feerate, smallest size as tiebreaker)
     *                              topologically valid subset (and its feerate) that was
     *                              encountered during search. It will be at least as good as the
     *                              best passed in (if not empty).
     *                            - The number of optimization steps that were performed. This will
     *                              be <= max_iterations. If strictly < max_iterations, the
     *                              returned subset is optimal.
     *
     * Complexity: possibly O(N * min(max_iterations, sqrt(2^N))) where N=depgraph.TxCount().
     */
    std::pair<SetInfo<SetType>, uint64_t> FindCandidateSet(uint64_t max_iterations, SetInfo<SetType> best) noexcept
    {
        Assume(!AllDone());

        // Convert the provided best to internal sorted indices.
        best.transactions = OriginalToSorted(best.transactions);

        /** Type for work queue items. */
        struct WorkItem
        {
            /** Set of transactions definitely included (and its feerate). This must be a subset
             *  of m_todo, and be topologically valid (includes all in-m_todo ancestors of
             *  itself). */
            SetInfo<SetType> inc;
            /** Set of undecided transactions. This must be a subset of m_todo, and have no overlap
             *  with inc. The set (inc | und) must be topologically valid. */
            SetType und;
            /** (Only when inc is not empty) The subset with the best feerate of any superset of
             *  inc that is also a subset of (inc | und), without requiring it to be topologically
             *  valid. Its feerate forms a conservative upper bound on how good a set this work
             *  item can give rise to. If the real best such feerate does not exceed best's, then
             *  this value is not guaranteed to be accurate. */
            SetInfo<SetType> pot;

            /** Construct a new work item. */
            WorkItem(SetInfo<SetType>&& i, SetType&& u, SetInfo<SetType>&& p) noexcept :
                inc(std::move(i)), und(std::move(u)), pot(std::move(p)) {}

            /** Swap two WorkItems. */
            void Swap(WorkItem& other) noexcept
            {
                swap(inc, other.inc);
                swap(und, other.und);
                swap(pot, other.pot);
            }
        };

        /** The queue of work items. */
        VecDeque<WorkItem> queue;
        queue.reserve(std::max<size_t>(256, 2 * m_todo.Count()));

        // Create initial entries per connected component of m_todo. While clusters themselves are
        // generally connected, this is not necessarily true after some parts have already been
        // removed from m_todo. Without this, effort can be wasted on searching "inc" sets that
        // span multiple components.
        auto to_cover = m_todo;
        do {
            auto component = m_depgraph.FindConnectedComponent(to_cover);
            to_cover -= component;
            // If best is not provided, set it to the first component, so that during the work
            // processing loop below, and during the add_fn/split_fn calls, we do not need to deal
            // with the best=empty case.
            if (best.feerate.IsEmpty()) best = SetInfo(m_depgraph, component);
            queue.emplace_back(SetInfo<SetType>{}, std::move(component), SetInfo<SetType>{});
        } while (to_cover.Any());

        /** Local copy of the iteration limit. */
        uint64_t iterations_left = max_iterations;

        /** The set of transactions in m_todo which have feerate > best's. */
        SetType imp = m_todo;
        while (imp.Any()) {
            ClusterIndex check = imp.Last();
            if (m_depgraph.FeeRate(check) >> best.feerate) break;
            imp.Reset(check);
        }

        /** Internal function to add a work item, possibly improving it before doing so.
         *
         * - inc: the "inc" value for the new work item (must be topological).
         * - und: the "und" value for the new work item ((inc | und) must be topological).
         * - pot: a subset of the "pot" value for the new work item (but a superset of inc).
         *        It does not need to be the full pot value; missing pot transactions will be added
         *        to it by add_fn.
         * - grow_inc: whether to attempt moving transactions from und to inc, if it can be proven
         *             that they must be a part of the best topologically valid superset of inc and
         *             subset of (inc | und). Transactions that are missing from pot are always
         *             considered, regardless of grow_inc. It only makes sense to enable this if
         *             transactions were added to inc after a split.
         */
        auto add_fn = [&](SetInfo<SetType> inc, SetType und, SetInfo<SetType> pot, bool grow_inc) noexcept {
            if (!inc.feerate.IsEmpty()) {
                /** Which transactions to consider adding to inc. */
                SetType consider_inc;
                if (grow_inc) consider_inc = pot.transactions - inc.transactions;
                // Add entries to pot. We iterate over all undecided transactions whose feerate is
                // higher than best, and aren't already part of pot. While undecided transactions
                // of lower feerate may improve pot still, if they do, the resulting pot feerate
                // cannot possibly exceed best's (and this item will be skipped in split_fn
                // regardless).
                for (auto pos : (imp & und) - pot.transactions) {
                    // Determine if adding transaction pos to pot (ignoring topology) would improve
                    // it. If not, we're done updating pot. This relies on the fact that
                    // m_depgraph, and thus the transactions iterated over, are in decreasing
                    // individual feerate order.
                    if (!(m_depgraph.FeeRate(pos) >> pot.feerate)) break;
                    pot.Set(m_depgraph, pos);
                    consider_inc.Set(pos);
                }

                // The "jump ahead" optimization: whenever pot has a topologically-valid subset,
                // that subset can be added to inc. Any subset of (pot - inc) has the property that
                // its feerate exceeds that of any set compatible with this work item (superset of
                // inc, subset of (inc | und)). Thus, if T is a topological subset of pot, and B is
                // the best topologically-valid set compatible with this work item, and (T - B) is
                // non-empty, then (T | B) is better than B and also topological. This is in
                // contradiction with the assumption that B is best. Thus, (T - B) must be empty,
                // or T must be a subset of B.
                //
                // See https://delvingbitcoin.org/t/how-to-linearize-your-cluster/303 section 2.4.
                const auto init_inc = inc.transactions;
                for (auto pos : consider_inc) {
                    // If the transaction's ancestors are a subset of pot, we can add it together
                    // with its ancestors to inc. Just update the transactions here; the feerate
                    // update happens below.
                    auto anc_todo = m_depgraph.Ancestors(pos) & m_todo;
                    if (anc_todo.IsSubsetOf(pot.transactions)) inc.transactions |= anc_todo;
                }
                // Finally update und and inc's feerate to account for the added transactions.
                und -= inc.transactions;
                inc.feerate += m_depgraph.FeeRate(inc.transactions - init_inc);

                // If inc's feerate is better than best's, remember it as our new best.
                if (inc.feerate > best.feerate) {
                    best = inc;
                    // See if we can remove any entries from imp now.
                    while (imp.Any()) {
                        ClusterIndex check = imp.Last();
                        if (m_depgraph.FeeRate(check) >> best.feerate) break;
                        imp.Reset(check);
                    }
                }

                // If no potential transactions exist beyond the already included ones, no
                // improvement is possible anymore.
                if (pot.feerate.size == inc.feerate.size) return;
                // At this point und must be non-empty. If it were empty then pot would equal inc.
                Assume(und.Any());
            } else {
                Assume(inc.transactions.None());
                // If inc is empty, we just make sure there are undecided transactions left to
                // split on.
                if (und.None()) return;
            }

            // Actually construct new work item on the queue. Due to the switch to DFS when queue
            // space runs out (see below), we know that no reallocation of the queue should ever
            // occur.
            Assume(queue.size() < queue.capacity());
            queue.emplace_back(std::move(inc), std::move(und), std::move(pot));
        };

        /** Internal process function. It takes an existing work item, and splits it in two: one
         *  with a particular transaction (and its ancestors) included, and one with that
         *  transaction (and its descendants) excluded. */
        auto split_fn = [&](WorkItem&& elem) noexcept {
            // Any queue element must have undecided transactions left, otherwise there is nothing
            // to explore anymore.
            Assume(elem.und.Any());
            // The potential set must include the included set, and be a subset of (und | inc).
            Assume(elem.pot.transactions.IsSupersetOf(elem.inc.transactions));
            Assume(elem.pot.transactions.IsSubsetOf(elem.und | elem.inc.transactions));
            // The potential, undecided, and (implicitly) included set are all subsets of m_todo.
            Assume(elem.pot.transactions.IsSubsetOf(m_todo) && elem.und.IsSubsetOf(m_todo));
            // Included transactions cannot be undecided.
            Assume(!elem.inc.transactions.Overlaps(elem.und));
            // If pot is empty, then so is inc.
            Assume(elem.inc.feerate.IsEmpty() == elem.pot.feerate.IsEmpty());

            const ClusterIndex first = elem.und.First();
            if (!elem.inc.feerate.IsEmpty()) {
                // We can ignore any queue item whose potential feerate isn't better than the best
                // seen so far.
                if (elem.pot.feerate <= best.feerate) return;
            } else {
                // In case inc is empty use a simpler alternative check.
                if (m_depgraph.FeeRate(first) <= best.feerate) return;
            }

            // Decide which transaction to split on. Splitting is how new work items are added, and
            // how progress is made. One split transaction is chosen among the queue item's
            // undecided ones, and:
            // - A work item is (potentially) added with that transaction plus its remaining
            //   descendants excluded (removed from the und set).
            // - A work item is (potentially) added with that transaction plus its remaining
            //   ancestors included (added to the inc set).
            //
            // To decide what to split, pick among the undecided ancestors of the highest
            // individual feerate transaction among the undecided ones the one which reduces the
            // search space most:
            // - Minimize the size of the largest of the undecided sets after including or
            //   excluding.
            // - If the above is equal, the one that minimizes the other branch's undecided set
            //   size.
            // - If the above are equal, the one with the best individual feerate.
            ClusterIndex split = 0;
            const auto select = elem.und & m_depgraph.Ancestors(first);
            Assume(select.Any());
            std::optional<std::pair<ClusterIndex, ClusterIndex>> split_counts;
            for (auto i : select) {
                std::pair<ClusterIndex, ClusterIndex> counts{
                    (elem.und - m_depgraph.Ancestors(i)).Count(),
                    (elem.und - m_depgraph.Descendants(i)).Count()};
                if (counts.first < counts.second) std::swap(counts.first, counts.second);
                if (!split_counts.has_value() || counts < *split_counts) {
                    split = i;
                    split_counts = counts;
                }
            }
            // Since there was at least one transaction in select, we must always find one.
            Assume(split_counts.has_value());

            // Add a work item corresponding to excluding the split transaction.
            const auto& desc = m_depgraph.Descendants(split);
            add_fn(/*inc=*/elem.inc,
                   /*und=*/elem.und - desc,
                   /*pot=*/elem.pot.Remove(m_depgraph, desc),
                   /*grow_inc=*/false);

            // Add a work item corresponding to including the first undecided transaction.
            const auto anc = m_depgraph.Ancestors(split) & m_todo;
            add_fn(/*inc=*/elem.inc.Add(m_depgraph, anc),
                   /*und=*/elem.und - anc,
                   /*pot=*/elem.pot.Add(m_depgraph, anc),
                   /*grow_inc=*/true);

            // Account for the performed split.
            --iterations_left;
        };

        // Work processing loop.
        //
        // New work items are always added at the back of the queue, but items to process use a
        // hybrid approach where they can be taken from the front or the back.
        //
        // Depth-first search (DFS) corresponds to always taking from the back of the queue. This
        // is very memory-efficient (linear in the number of transactions). Breadth-first search
        // (BFS) corresponds to always taking from the front, which potentially uses more memory
        // (up to exponential in the transaction count), but seems to work better in practice.
        //
        // The approach here combines the two: use BFS (plus random swapping) until the queue grows
        // too large, at which point we temporarily switch to DFS until the size shrinks again.
        while (!queue.empty()) {
            // Randomly swap the first two items to randomize the search order.
            if (queue.size() > 1 && m_rng.randbool()) {
                queue[0].Swap(queue[1]);
            }

            // Processing the first queue item, and then using DFS for everything it gives rise to,
            // may increase the queue size by the number of undecided elements in there, minus 1
            // for the first queue item being removed. Thus, only when that pushes the queue over
            // its capacity can we not process from the front (BFS), and should we use DFS.
            while (queue.size() - 1 + queue.front().und.Count() > queue.capacity()) {
                if (!iterations_left) break;
                auto elem = queue.back();
                queue.pop_back();
                split_fn(std::move(elem));
            }

            // Process one entry from the front of the queue (BFS exploration)
            if (!iterations_left) break;
            auto elem = queue.front();
            queue.pop_front();
            split_fn(std::move(elem));
        }

        // Return the found best set (converted to the original transaction indices), and the
        // number of iterations performed.
        best.transactions = SortedToOriginal(best.transactions);
        return {std::move(best), max_iterations - iterations_left};
    }

    /** Remove a subset of transactions from the cluster being linearized.
     *
     * Complexity: O(N) where N=done.Count().
     */
    void MarkDone(const SetType& done) noexcept
    {
        m_todo -= OriginalToSorted(done);
    }
};

/** Find or improve a linearization for a cluster.
 *
 * @param[in] depgraph            Dependency graph of the the cluster to be linearized.
 * @param[in] max_iterations      Upper bound on the number of optimization steps that will be done.
 * @param[in] rng_seed            A random number seed to control search order. This prevents peers
 *                                from predicting exactly which clusters would be hard for us to
 *                                linearize.
 * @param[in] old_linearization   An existing linearization for the cluster, or empty.
 * @return                        A pair of:
 *                                - The resulting linearization. It is guaranteed to be at least as
 *                                  good (in the feerate diagram sense) as old_linearization.
 *                                - A boolean indicating whether the result is guaranteed to be
 *                                  optimal.
 *
 * Complexity: possibly O(N * min(max_iterations + N, sqrt(2^N))) where N=depgraph.TxCount().
 */
template<typename SetType>
std::pair<std::vector<ClusterIndex>, bool> Linearize(const DepGraph<SetType>& depgraph, uint64_t max_iterations, uint64_t rng_seed, Span<const ClusterIndex> old_linearization = {}) noexcept
{
    Assume(old_linearization.empty() || old_linearization.size() == depgraph.TxCount());
    if (depgraph.TxCount() == 0) return {{}, true};

    uint64_t iterations_left = max_iterations;
    std::vector<ClusterIndex> linearization;

    AncestorCandidateFinder anc_finder(depgraph);
    SearchCandidateFinder src_finder(depgraph, rng_seed);
    linearization.reserve(depgraph.TxCount());
    bool optimal = true;

    /** Chunking of what remains of the old linearization. */
    LinearizationChunking old_chunking(depgraph, old_linearization);

    while (true) {
        // Find the highest-feerate prefix of the remainder of old_linearization.
        SetInfo<SetType> best_prefix;
        if (old_chunking.ChunksLeft()) best_prefix = old_chunking.GetChunk(0);

        // Then initialize best to be either the best remaining ancestor set, or the first chunk.
        auto best = anc_finder.FindCandidateSet();
        if (!best_prefix.feerate.IsEmpty() && best_prefix.feerate >= best.feerate) best = best_prefix;

        // Invoke bounded search to update best, with up to half of our remaining iterations as
        // limit.
        uint64_t max_iterations_now = (iterations_left + 1) / 2;
        uint64_t iterations_done_now = 0;
        std::tie(best, iterations_done_now) = src_finder.FindCandidateSet(max_iterations_now, best);
        iterations_left -= iterations_done_now;

        if (iterations_done_now == max_iterations_now) {
            optimal = false;
            // If the search result is not (guaranteed to be) optimal, run intersections to make
            // sure we don't pick something that makes us unable to reach further diagram points
            // of the old linearization.
            if (old_chunking.ChunksLeft() > 0) {
                best = old_chunking.Intersect(best);
            }
        }

        // Add to output in topological order.
        depgraph.AppendTopo(linearization, best.transactions);

        // Update state to reflect best is no longer to be linearized.
        anc_finder.MarkDone(best.transactions);
        if (anc_finder.AllDone()) break;
        src_finder.MarkDone(best.transactions);
        if (old_chunking.ChunksLeft() > 0) {
            old_chunking.MarkDone(best.transactions);
        }
    }

    return {std::move(linearization), optimal};
}

} // namespace cluster_linearize

#endif // BITCOIN_CLUSTER_LINEARIZE_H
