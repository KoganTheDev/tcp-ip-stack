#pragma once

#include <memory>
#include <string>
#include "bytes.h"

class ProtocolLayer
{
public:
    virtual ~ProtocolLayer() = default;
    virtual void from_bytes(const Bytes&) = 0;
    virtual Bytes to_bytes() = 0;
    virtual std::string to_string() const = 0;

    // concat layers
    ProtocolLayer& operator/=(std::unique_ptr<ProtocolLayer>);

protected:
    void encapsulate(std::unique_ptr<ProtocolLayer> next_layer);
    template <typename T>
    void encapsulate(T&& next_layer);
    
    // Returns a formatted string of a field and its value
    static std::string _field_to_string(const std::string& name, const std::string& value);
    // Returns a formatted string of the protocol name
    static std::string _protocol_header_to_string(const std::string& protocol_name);
    
    std::unique_ptr<ProtocolLayer> _next_layer;
};

template <typename T>
void ProtocolLayer::encapsulate(T&& next_layer)
{
    this->encapsulate(std::make_unique<T>(std::move(next_layer)));
}