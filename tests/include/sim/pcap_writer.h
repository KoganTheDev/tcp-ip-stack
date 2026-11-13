#pragma once

#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "bytes.h"

// Collects frames in memory and writes them as a classic libpcap file
// (https://www.tcpdump.org/manpages/pcap-savefile.5.html), LINKTYPE_ETHERNET,
// readable by tcpdump -r, tshark -r and Wireshark.
//
// In memory first, file only on demand: the simulator records every run, but a
// file is only worth writing when a test failed. Writing one per passing seed
// would be thousands of files nobody opens.
//
// Classic pcap rather than pcapng because it is the format every tool reads
// and it is simple enough to get right in a few lines. Its one limitation is
// that a record cannot be annotated, so "this frame was dropped" cannot be
// said inside one file - the simulator keeps two captures instead (what was
// delivered, and everything transmitted).
class PcapWriter
{
public:
    static constexpr uint32_t LINKTYPE_ETHERNET = 1;
    static constexpr uint32_t SNAPLEN = 65535;

    struct Record
    {
        uint64_t timestamp_us;
        Bytes frame;
    };

    void record(uint64_t timestamp_us, const Bytes& frame) { _records.push_back({timestamp_us, frame}); }

    size_t size() const { return _records.size(); }
    bool empty() const { return _records.empty(); }
    const std::vector<Record>& records() const { return _records; }
    void clear() { _records.clear(); }

    // The whole file as bytes, so the format can be tested without a file.
    // Native byte order with the 0xa1b2c3d4 magic: readers detect the order
    // from how the magic reads back, so either is valid.
    Bytes to_bytes() const
    {
        Bytes out;
        append_native<uint32_t>(out, 0xa1b2c3d4); // magic: microsecond timestamps
        append_native<uint16_t>(out, 2);          // version major
        append_native<uint16_t>(out, 4);          // version minor
        append_native<int32_t>(out, 0);           // thiszone: timestamps are UTC (virtual)
        append_native<uint32_t>(out, 0);          // sigfigs, always 0
        append_native<uint32_t>(out, SNAPLEN);
        append_native<uint32_t>(out, LINKTYPE_ETHERNET);
        for (const Record& r : _records)
        {
            uint32_t length = static_cast<uint32_t>(r.frame.size());
            uint32_t captured = length < SNAPLEN ? length : SNAPLEN;
            append_native<uint32_t>(out, static_cast<uint32_t>(r.timestamp_us / 1000000));
            append_native<uint32_t>(out, static_cast<uint32_t>(r.timestamp_us % 1000000));
            append_native<uint32_t>(out, captured);
            append_native<uint32_t>(out, length);
            out.insert(out.end(), r.frame.begin(), r.frame.begin() + captured);
        }
        return out;
    }

    // Returns false if the file could not be written; never throws, since this
    // runs while reporting a failure and must not replace it with another one.
    bool write_file(const std::string& path) const
    {
        Bytes data = to_bytes();
        FILE* file = std::fopen(path.c_str(), "wb");
        if (file == nullptr)
        {
            return false;
        }
        bool ok = std::fwrite(data.data(), 1, data.size(), file) == data.size();
        return std::fclose(file) == 0 && ok;
    }

private:
    template <typename T>
    static void append_native(Bytes& out, T value)
    {
        const byte_t* raw = reinterpret_cast<const byte_t*>(&value);
        out.insert(out.end(), raw, raw + sizeof(T));
    }

    std::vector<Record> _records;
};
