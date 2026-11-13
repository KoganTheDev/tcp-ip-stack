#pragma once

#include <algorithm>
#include <array>
#include <cstdint>

// A latency histogram with logarithmic buckets, in the spirit of HdrHistogram
// but a fraction of the code: values are microseconds, anything below 64 gets
// its own bucket, and each power of two above that is split into 32 equal
// sub-buckets. The bucket width is therefore at most 1/32 (about 3%) of the
// value, whatever the value is - fine-grained enough for percentiles, and a
// fixed 1.5k counters, so recording is one increment and merging is an
// addition. Counters are plain integers: each worker thread owns its own
// histogram and they are merged after the threads have been joined.
class Histogram
{
public:
    static constexpr int SUB_BITS = 5;
    static constexpr uint64_t SUB_COUNT = 1U << SUB_BITS; // 32
    static constexpr uint64_t LINEAR_LIMIT = 2 * SUB_COUNT; // values below this are exact
    static constexpr int MAX_EXPONENT = 40;                 // 2^40 us is about 12.7 days
    static constexpr size_t BUCKETS = LINEAR_LIMIT + (MAX_EXPONENT - SUB_BITS - 1) * SUB_COUNT;

    void record(uint64_t micros)
    {
        ++_buckets[index_of(micros)];
        ++_count;
        _sum += micros;
        _max = std::max(_max, micros);
    }

    void merge(const Histogram& other)
    {
        for (size_t i = 0; i < BUCKETS; i++)
        {
            _buckets[i] += other._buckets[i];
        }
        _count += other._count;
        _sum += other._sum;
        _max = std::max(_max, other._max);
    }

    uint64_t count() const { return _count; }
    uint64_t max() const { return _max; }
    double mean() const { return _count == 0 ? 0.0 : static_cast<double>(_sum) / static_cast<double>(_count); }

    // The smallest recorded-bucket value at or below which `fraction` of the
    // samples fall (the bucket's lower bound; the exact maximum is max()).
    uint64_t percentile(double fraction) const
    {
        if (_count == 0)
        {
            return 0;
        }
        auto rank = static_cast<uint64_t>(fraction * static_cast<double>(_count));
        rank = std::min(std::max<uint64_t>(rank, 1), _count);
        uint64_t seen = 0;
        for (size_t i = 0; i < BUCKETS; i++)
        {
            seen += _buckets[i];
            if (seen >= rank)
            {
                return std::min(lower_bound_of(i), _max);
            }
        }
        return _max;
    }

private:
    static size_t index_of(uint64_t value)
    {
        if (value < LINEAR_LIMIT)
        {
            return static_cast<size_t>(value);
        }
        int exponent = 63 - __builtin_clzll(value); // >= 6 here
        if (exponent > MAX_EXPONENT)
        {
            return BUCKETS - 1;
        }
        uint64_t sub = (value >> (exponent - SUB_BITS)) & (SUB_COUNT - 1);
        return static_cast<size_t>(LINEAR_LIMIT + static_cast<uint64_t>(exponent - SUB_BITS - 1) * SUB_COUNT + sub);
    }

    static uint64_t lower_bound_of(size_t index)
    {
        if (index < LINEAR_LIMIT)
        {
            return index;
        }
        uint64_t k = index - LINEAR_LIMIT;
        auto exponent = static_cast<int>(k / SUB_COUNT) + SUB_BITS + 1;
        uint64_t sub = k % SUB_COUNT;
        return (SUB_COUNT + sub) << (exponent - SUB_BITS);
    }

    std::array<uint64_t, BUCKETS> _buckets{};
    uint64_t _count = 0;
    uint64_t _sum = 0;
    uint64_t _max = 0;
};
