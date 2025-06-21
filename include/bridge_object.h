#pragma once

#include "system_network_object.h"
#include <string>

class BridgeObject : public SystemNetworkObject
{
    virtual void add_interface(const std::string &interface_name) = 0;
};