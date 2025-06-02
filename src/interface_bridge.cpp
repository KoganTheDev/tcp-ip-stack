#include "interface_bridge.h"
#include "custom_exception.h"
#include <stdlib.h>

InterfaceBridge::InterfaceBridge(const std::string& bridge_name)
    : _bridge_name(bridge_name), _interfaces(), _is_active(false)
{
    this->_create_bridge();
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
    _system_wrapper(command);
}

void InterfaceBridge::add_interface(const std::string& interface)
{
    std::string command = "sudo ip link set " + interface + " master " + this->_bridge_name;
    _system_wrapper(command);

    this->_interfaces.push_back(interface);
}

void InterfaceBridge::_delete_bridge()
{
    std::string command = "sudo ip link delete " + this->_bridge_name;
    _system_wrapper(command);
}

void InterfaceBridge::_set_interface_state(const std::string& interface, bool state_up)
{
    std::string command = "sudo ip link set " + interface + " ";
    command += state_up ? "up" : "down";
    _system_wrapper(command);
}

void InterfaceBridge::_system_wrapper(const std::string &command)
{
    int return_value = system(command.c_str()); 
    if (return_value != 0)
    {
        throw CustomException("Error in command \"" + command + "\", return value " + std::to_string(return_value));
    }
}
