#pragma once

#include <string>

class SystemNetworkObject
{
    public:
        virtual void start() = 0;
        virtual void stop() = 0;

    protected:
        static void _set_interface_state(const std::string& name, bool state);
        static void _system_wrapper(const std::string& command);
};
