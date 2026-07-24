#pragma once

#include "protocol_layer.h"

class Raw : public ProtocolLayer
{
public:
    Raw() = default;
    // by value + move: constructed almost entirely from rvalue slice() results
    // on the receive path, so this hands the buffer straight in instead of
    // copying it a second time after slice() already copied the sub-range out
    Raw(Bytes data);

    void from_bytes(const Bytes& data);
    Bytes to_bytes();

    virtual std::string to_string() const;

    // by const reference, not by value - returning the payload used to copy the
    // whole thing on every read (and every layer's payload is a Raw)
    const Bytes& get_data() const { return this->_data; }

private:
    Bytes _data;
};