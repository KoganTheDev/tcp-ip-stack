#include "interface_bridge.h"
#include <stdlib.h>

InterfaceBridge::InterfaceBridge(const std::string& bridge_name, const std::vector<std::string>& interfaces)
    : _bridge_name(bridge_name), _interfaces(), _is_active(false)
{
    this->_create_bridge();
    for (const std::string& interface : interfaces)
    {
        this->add_interface(interface);
    }
}

InterfaceBridge::~InterfaceBridge()
{
    this->_delete_bridge();
}

void InterfaceBridge::start()
{
    this->_set_interface_state(_bridge_name, true);
    this->_is_active = true;
}

void InterfaceBridge::stop()
{
    this->_set_interface_state(_bridge_name, false);
    this->_is_active = false;
}

void InterfaceBridge::_create_bridge()
{
    // TODO handle errors

    std::string command = "sudo ip link add name " + this->_bridge_name + " type bridge";
    system(command.c_str());
}

void InterfaceBridge::add_interface(const std::string& interface)
{
    std::string command = "sudo ip link set " + interface + " master " + this->_bridge_name;
    system(command.c_str());

    this->_interfaces.push_back(interface);
}

void InterfaceBridge::_delete_bridge()
{
    std::string command = "sudo ip link delete " + this->_bridge_name;
    system(command.c_str());
}

void InterfaceBridge::_set_interface_state(const std::string& interface, bool state_up)
{
    std::string command = "sudo ip link set " + interface + " ";
    command += state_up ? "up" : "down";
    system(command.c_str());
}
