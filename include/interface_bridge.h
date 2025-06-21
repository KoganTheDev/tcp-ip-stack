#pragma once

#include <iostream>
#include <string>
#include <vector>

#include "bridge_object.h"
class InterfaceBridge : public BridgeObject
{
public:
    InterfaceBridge(const std::string& bridge_name);
    ~InterfaceBridge();
    
    void start();
    void stop();
    void add_interface(const std::string& interface);

private:
    void _create_bridge();
    void _delete_bridge();

    static void _system_wrapper(const std::string& command);
 
    std::string _bridge_name;
    std::vector<std::string> _interfaces;
    bool _is_active;
};
