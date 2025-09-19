#include "protocol_layer.h"
#include "exceptions.h"


ProtocolLayer& ProtocolLayer::operator/=(std::unique_ptr<ProtocolLayer> other)
{
    this->encapsulate(std::move(other));
    return *this;
}

void ProtocolLayer::encapsulate(std::unique_ptr<ProtocolLayer> next_layer)
{
    this->_next_layer = std::move(next_layer);
}

std::string ProtocolLayer::_field_to_string(const std::string &name, const std::string &value)
{
    return "    " + name + " = " + value + "\n";
}

std::string ProtocolLayer::_protocol_header_to_string(const std::string &protocol_name)
{
    return "<" + protocol_name + ">\n";
}
