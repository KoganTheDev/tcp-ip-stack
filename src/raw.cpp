#include "raw.h"

#include <utility>


Raw::Raw(Bytes data)
    : _data(std::move(data))
{
}

std::string Raw::to_string() const
{
    std::string result;

    result = this->_protocol_header_to_string("Raw");
    result += this->_field_to_string("data", this->_data.to_hex());

    if (this->_next_layer)
    {
        result += this->_next_layer->to_string();
    }

    return result;
}

void Raw::from_bytes(const Bytes& data)
{
    this->_data = data;
}

Bytes Raw::to_bytes()
{
    return this->_data;
}
