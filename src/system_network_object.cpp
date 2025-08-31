#include "system_network_object.h"
#include "exceptions.h"

void SystemNetworkObject::_set_interface_state(const std::string& interface, bool state_up)
{
    std::string command = "sudo ip link set " + interface + " ";
    command += state_up ? "up" : "down";
    int return_value = system(command.c_str());
    if (return_value != 0)
    {
        throw EXCEPTION(SystemException, "Error in command \"" + command + "\", return value " + std::to_string(return_value));
    }
}
