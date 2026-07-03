#pragma once

#include "protocol_layer.h"

class Raw : public ProtocolLayer
{
public:
    Raw() = default;
    Raw(const Bytes& data);

    void from_bytes(const Bytes& data);
    Bytes to_bytes();

    virtual std::string to_string() const;

    Bytes get_data() const { return this->_data; }

private:
    Bytes _data;
};