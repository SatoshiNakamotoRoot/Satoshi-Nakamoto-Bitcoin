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

/** Construct a wide graph (one root, with N-1 children that are otherwise unrelated, with
 *  increasing feerates). These graphs are pessimal for the LIMO step in Linearize, because
 *  rechunking is needed after every candidate (the last transaction gets picked every time).
 */
template<typename SetType>
DepGraph<SetType> MakeWideGraph(ClusterIndex ntx)
{
    DepGraph<SetType> depgraph;
    for (ClusterIndex i = 0; i < ntx; ++i) {
        depgraph.AddTransaction({int32_t(i) + 1, 1});
        if (i > 0) depgraph.AddDependency(0, i);
    }
    return depgraph;
}

// Construct a difficult graph. These need at least sqrt(2^(n-1)) iterations in the best
// known algorithms (purely empirically determined).
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
 * BenchLinearizeNoItersWorstCase*, then an invocation of Linearize with max_iterations=m should
 * take no more than roughly N+m*P time. This may however be an overestimate, as the worst cases
 * do not coincide (the ones that are worst for linearization without any search happen to be ones
 * that do not need many search iterations).
 */
template<typename SetType>
void BenchLinearizeNoItersWorstCaseAnc(ClusterIndex ntx, benchmark::Bench& bench)
{
    const auto depgraph = MakeLinearGraph<SetType>(ntx);
    uint64_t rng_seed = 0;
    std::vector<ClusterIndex> old_lin(ntx);
    for (ClusterIndex i = 0; i < ntx; ++i) old_lin[i] = i;
    bench.run([&] {
        Linearize(depgraph, /*max_iterations=*/0, rng_seed++, old_lin);
    });
}

/** Benchmark for linearization of a trivial linear graph using just ancestor sort/LIMO.
 *
 * Its goal is measuring how much time improving a linearization may take without any search
 * iterations, similar to the previous function.
 */
template<typename SetType>
void BenchLinearizeNoItersWorstCaseLIMO(ClusterIndex ntx, benchmark::Bench& bench)
{
    const auto depgraph = MakeWideGraph<SetType>(ntx);
    uint64_t rng_seed = 0;
    std::vector<ClusterIndex> old_lin(ntx);
    for (ClusterIndex i = 0; i < ntx; ++i) old_lin[i] = i;
    bench.run([&] {
        Linearize(depgraph, /*max_iterations=*/0, rng_seed++, old_lin);
    });
}

} // namespace

static void LinearizePerIter16TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<16>>(16, bench); }
static void LinearizePerIter32TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<32>>(32, bench); }
static void LinearizePerIter48TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<48>>(48, bench); }
static void LinearizePerIter64TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<64>>(64, bench); }
static void LinearizePerIter75TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<75>>(75, bench); }
static void LinearizePerIter99TxWorstCase(benchmark::Bench& bench) { BenchLinearizePerIterWorstCase<BitSet<99>>(99, bench); }

static void LinearizeNoIters16TxWorstCaseAnc(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseAnc<BitSet<16>>(16, bench); }
static void LinearizeNoIters32TxWorstCaseAnc(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseAnc<BitSet<32>>(32, bench); }
static void LinearizeNoIters48TxWorstCaseAnc(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseAnc<BitSet<48>>(48, bench); }
static void LinearizeNoIters64TxWorstCaseAnc(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseAnc<BitSet<64>>(64, bench); }
static void LinearizeNoIters75TxWorstCaseAnc(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseAnc<BitSet<75>>(75, bench); }
static void LinearizeNoIters99TxWorstCaseAnc(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseAnc<BitSet<99>>(99, bench); }

static void LinearizeNoIters16TxWorstCaseLIMO(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseLIMO<BitSet<16>>(16, bench); }
static void LinearizeNoIters32TxWorstCaseLIMO(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseLIMO<BitSet<32>>(32, bench); }
static void LinearizeNoIters48TxWorstCaseLIMO(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseLIMO<BitSet<48>>(48, bench); }
static void LinearizeNoIters64TxWorstCaseLIMO(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseLIMO<BitSet<64>>(64, bench); }
static void LinearizeNoIters75TxWorstCaseLIMO(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseLIMO<BitSet<75>>(75, bench); }
static void LinearizeNoIters99TxWorstCaseLIMO(benchmark::Bench& bench) { BenchLinearizeNoItersWorstCaseLIMO<BitSet<99>>(99, bench); }

BENCHMARK(LinearizePerIter16TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizePerIter32TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizePerIter48TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizePerIter64TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizePerIter75TxWorstCase, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizePerIter99TxWorstCase, benchmark::PriorityLevel::HIGH);

BENCHMARK(LinearizeNoIters16TxWorstCaseAnc, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters32TxWorstCaseAnc, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters48TxWorstCaseAnc, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters64TxWorstCaseAnc, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters75TxWorstCaseAnc, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters99TxWorstCaseAnc, benchmark::PriorityLevel::HIGH);

BENCHMARK(LinearizeNoIters16TxWorstCaseLIMO, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters32TxWorstCaseLIMO, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters48TxWorstCaseLIMO, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters64TxWorstCaseLIMO, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters75TxWorstCaseLIMO, benchmark::PriorityLevel::HIGH);
BENCHMARK(LinearizeNoIters99TxWorstCaseLIMO, benchmark::PriorityLevel::HIGH);
