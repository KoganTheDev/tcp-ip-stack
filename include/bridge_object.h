#pragma once

#include <string>
#include "system_network_object.h"

class BridgeObject : public SystemNetworkObject
{
    virtual void add_interface(const std::string &interface_name) = 0;
};