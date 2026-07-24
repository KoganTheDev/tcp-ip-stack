#include "system_network_object.h"
#include "exceptions.h"

void SystemNetworkObject::_set_interface_state(const std::string& interface, bool state_up)
{
    // No `sudo`: every entry point that reaches this (both main.cpp files)
    // already requires root via a geteuid() check, so `sudo` was redundant -
    // and it hard-fails in a minimal root environment (e.g. a container) that
    // doesn't ship sudo at all.
    std::string command = "ip link set " + interface + " ";
    command += state_up ? "up" : "down";
    int return_value = system(command.c_str());
    if (return_value != 0)
    {
        throw EXCEPTION(SystemException, "Error in command \"" + command + "\", return value " + std::to_string(return_value));
    }
}
