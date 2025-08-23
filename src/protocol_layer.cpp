#include "protocol_layer.h"
#include "exceptions.h"


ProtocolLayer &ProtocolLayer::operator/=(const ProtocolLayer &&other)
{
    this->encapsulate(std::move(_next_layer));
    return *this;
}

void ProtocolLayer::encapsulate(std::unique_ptr<ProtocolLayer> next_layer)
{
    this->_next_layer = std::move(next_layer);
}
