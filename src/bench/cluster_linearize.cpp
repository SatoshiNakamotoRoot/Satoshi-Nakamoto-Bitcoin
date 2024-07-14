// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>

#include <util/bitset.h>
#include <cluster_linearize.h>

using namespace cluster_linearize;

namespace {

/** Construct a linear graph. These are pessimal for AncestorCandidateFinder, as they maximize
 *  the number of ancestor set feerate updates. The best ancestor set is always the topmost
 *  remaining transaction, whose removal requires updating all remaining transactions' ancestor
 *  set feerates. */
template<typename SetType>
DepGraph<SetType> MakeLinearGraph(ClusterIndex ntx)
{
    DepGraph<SetType> depgraph;
    for (ClusterIndex i = 0; i < ntx; ++i) {
        depgraph.AddTransaction({-int32_t(i), 1});
        if (i > 0) depgraph.AddDependency(i - 1, i);
    }
    return depgraph;
}

// Construct a difficult graph. These need at least sqrt(2^(n-1)) iterations in the best
// implemented algorithms (purely empircally determined).
template<typename SetType>
DepGraph<SetType> MakeHardGraph(ClusterIndex ntx)
{
    DepGraph<SetType> depgraph;
    for (ClusterIndex i = 0; i < ntx; ++i) {
        if (ntx & 1) {
            if (i == 0) {
                depgraph.AddTransaction({1, 2});
            } else if (i == 1) {
                depgraph.AddTransaction({14, 2});
                depgraph.AddDependency(0, 1);
            } else if (i == 2) {
                depgraph.AddTransaction({6, 1});
                depgraph.AddDependency(2, 1);
            } else if (i == 3) {
                depgraph.AddTransaction({5, 1});
                depgraph.AddDependency(2, 3);
            } else if ((i & 1) == 0) {
                depgraph.AddTransaction({7, 1});
                depgraph.AddDependency(i - 1, i);
            } else {
                depgraph.AddTransaction({5, 1});
                depgraph.AddDependency(i, 4);
            }
        } else {
            if (i == 0) {
                depgraph.AddTransaction({1, 1});
            } else if (i == 1) {
                depgraph.AddTransaction({3, 1});
                depgraph.AddDependency(0, 1);
            } else if (i == 2) {
                depgraph.AddTransaction({1, 1});
                depgraph.AddDependency(0, 2);
            } else if (i & 1) {
                depgraph.AddTransaction({4, 1});
                depgraph.AddDependency(i - 1, i);
            } else {
                depgraph.AddTransaction({0, 1});
                depgraph.AddDependency(i, 3);
            }
        }
    }
    return depgraph;
}

/** Benchmark that does search-based candidate finding with 10000 iterations.
 *
 * Its goal is measuring how much time every additional search iteration in linearization costs.
 */
template<typename SetType>
void BenchLinearizePerIterWorstCase(ClusterIndex ntx, benchmark::Bench& bench)
{
    const auto depgraph = MakeHardGraph<SetType>(ntx);
    const auto iter_limit = std::min<uint64_t>(10000, uint64_t{1} << (ntx / 2 - 1));
    uint64_t rng_seed = 0;
    bench.batch(iter_limit).unit("iters").run([&] {
        SearchCandidateFinder finder(depgraph, rng_seed++);
        auto [candidate, iters_performed] = finder.FindCandidateSet(iter_limit, {});
        assert(iters_performed == iter_limit);
    });
}

/** Benchmark for linearization of a trivial linear graph using just ancestor sort.
 *
 * Its goal is measuring how much time linearization may take without any search iterations.
 *
 * If P is the resulting time of BenchLinearizePerIterWorstCase, and N is the resulting time of
 * BenchLinearizeNoItersWorstCase, then an invocation of Linearize with max_iterations=m should
 * take no more than roughly N+m*P time. This may however be an overestimate, as the worst cases
 * do not coincide (the ones that are worst for linearization without any search happen to be ones
 * that do not need many search iterations).
 */
template<typename SetType>
void BenchLinearizeNoItersWorstCase(ClusterIndex ntx, benchmark::Bench& bench)
{
    const auto depgraph = MakeLinearGraph<SetType>(ntx);
    uint64_t rng_seed = 0;
    std::vector<ClusterIndex> old_lin(ntx);
    for (ClusterIndex i = 0; i < ntx; ++i) old_lin[i] = i;
    bench.run([&] {
        Linearize(depgraph, /*max_iterations=*/0, rng_seed++, old_lin);
    });
}

template<typename SetType>
void BenchPostLinearizeWorstCase(ClusterIndex ntx, benchmark::Bench& bench)
{
    DepGraph<SetType> depgraph;
    for (ClusterIndex i = 0; i < ntx; ++i) {
        depgraph.AddTransaction({i, 1});
        if (i) depgraph.AddDependency(0, i);
    }
    std::vector<ClusterIndex> lin(ntx);
    bench.run([&] {
        for (ClusterIndex i = 0; i < ntx; ++i) lin[i] = i;
        PostLinearize(depgraph, lin);
    });
}

template<typename SetType>
void BenchMergeLinearizationsWorstCase(ClusterIndex ntx, benchmark::Bench& bench)
{
    DepGraph<SetType> depgraph;
    for (ClusterIndex i = 0; i < ntx; ++i) {
        depgraph.AddTransaction({i, 1});
        if (i) depgraph.AddDependency(0, i);
    }
    std::vector<ClusterIndex> lin1;
    std::vector<ClusterIndex> lin2;
    lin1.push_back(0);
    lin2.push_back(0);
    for (ClusterIndex i = 1; i < ntx; ++i) {
        lin1.push_back(i);
        lin2.push_back(ntx - i);
    }
    bench.run([&] {
        MergeLinearizations(depgraph, lin1, lin2);
    });
}

} // namespace

static void LinearizePerIter16TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<16>>(16, bench); }
static void LinearizePerIter32TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<32>>(32, bench); }
static void LinearizePerIter48TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<48>>(48, bench); }
static void LinearizePerIter64TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<64>>(64, bench); }
static void LinearizePerIter75TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<75>>(75, bench); }
static void LinearizePerIter99TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<99>>(99, bench); }

static void LinearizeNoIters16TxWorstCase(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCase<BitSet<16>>(16, bench); }
static void LinearizeNoIters32TxWorstCase(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCase<BitSet<32>>(32, bench); }
static void LinearizeNoIters48TxWorstCase(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCase<BitSet<48>>(48, bench); }
static void LinearizeNoIters64TxWorstCase(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCase<BitSet<64>>(64, bench); }
static void LinearizeNoIters75TxWorstCase(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCase<BitSet<75>>(75, bench); }
static void LinearizeNoIters99TxWorstCase(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCase<BitSet<99>>(99, bench); }

static void PostLinearize16TxWorstCase(benchmark::Bench& bench) { BenchPostLinearizeWorstCase<BitSet<16>>(16, bench); }
static void PostLinearize32TxWorstCase(benchmark::Bench& bench) { BenchPostLinearizeWorstCase<BitSet<32>>(32, bench); }
static void PostLinearize48TxWorstCase(benchmark::Bench& bench) { BenchPostLinearizeWorstCase<BitSet<48>>(48, bench); }
static void PostLinearize64TxWorstCase(benchmark::Bench& bench) { BenchPostLinearizeWorstCase<BitSet<64>>(64, bench); }
static void PostLinearize75TxWorstCase(benchmark::Bench& bench) { BenchPostLinearizeWorstCase<BitSet<75>>(75, bench); }
static void PostLinearize99TxWorstCase(benchmark::Bench& bench) { BenchPostLinearizeWorstCase<BitSet<99>>(99, bench); }

static void MergeLinearizations16TxWorstCase(benchmark::Bench& bench) { BenchMergeLinearizationsWorstCase<BitSet<16>>(16, bench); }
static void MergeLinearizations32TxWorstCase(benchmark::Bench& bench) { BenchMergeLinearizationsWorstCase<BitSet<32>>(32, bench); }
static void MergeLinearizations48TxWorstCase(benchmark::Bench& bench) { BenchMergeLinearizationsWorstCase<BitSet<48>>(48, bench); }
static void MergeLinearizations64TxWorstCase(benchmark::Bench& bench) { BenchMergeLinearizationsWorstCase<BitSet<64>>(64, bench); }
static void MergeLinearizations75TxWorstCase(benchmark::Bench& bench) { BenchMergeLinearizationsWorstCase<BitSet<75>>(75, bench); }
static void MergeLinearizations99TxWorstCase(benchmark::Bench& bench) { BenchMergeLinearizationsWorstCase<BitSet<99>>(99, bench); }

BENCHMARK(LinearizePerIter16TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizePerIter32TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizePerIter48TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizePerIter64TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizePerIter75TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizePerIter99TxWorstCase, benchmark::PriorityLevel::HIGH);

BENCHMARK(LinearizeNoIters16TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters32TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters48TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters64TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters75TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters99TxWorstCase, benchmark::PriorityLevel::HIGH);

BENCHMARK(PostLinearize16TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(PostLinearize32TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(PostLinearize48TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(PostLinearize64TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(PostLinearize75TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(PostLinearize99TxWorstCase, benchmark::PriorityLevel::HIGH);

BENCHMARK(MergeLinearizations16TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(MergeLinearizations32TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(MergeLinearizations48TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(MergeLinearizations64TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(MergeLinearizations75TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(MergeLinearizations99TxWorstCase, benchmark::PriorityLevel::HIGH);
