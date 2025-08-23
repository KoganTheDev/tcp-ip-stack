#pragma once

#include <vector>

#include "bridge_object.h"

class TCBridge : public BridgeObject
{
public:
    TCBridge();
    ~TCBridge();
    
    virtual void start();
    virtual void stop();
    virtual void add_interface(const std::string& interface);

private:
    void _create_bridge();
    void _delete_bridge();

    std::vector<std::string> _interfaces;
    bool _is_active;
};
