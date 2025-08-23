#pragma once

#include <memory>
#include "bytes.h"

class ProtocolLayer
{
public:
    virtual void from_bytes(const Bytes&) = 0;
    virtual Bytes to_bytes() = 0;

    // concat layers
    ProtocolLayer& operator/=(const ProtocolLayer&& other);

protected:
    void encapsulate(std::unique_ptr<ProtocolLayer> next_layer);

private:
    std::unique_ptr<ProtocolLayer> _next_layer;
};