#pragma once

#include <iostream>
#include <string>
#include <vector>


class InterfaceBridge 
{
public:
    InterfaceBridge(const std::string& bridge_name, const std::vector<std::string>& interfaces);
    ~InterfaceBridge();
    
    void start();
    void stop();
    void add_interface(const std::string& interface);

private:
    void _create_bridge();
    void _delete_bridge();
    void _set_interface_state(const std::string& interface, bool state_up);
 
    std::string _bridge_name;
    std::vector<std::string> _interfaces;
    bool _is_active;
};
