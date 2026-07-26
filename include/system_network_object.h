#pragma once

#include <string>

class SystemNetworkObject
{
    public:
        // Any class with virtual methods is meant to be held by base pointer,
        // and destroying one that way without a virtual destructor is
        // undefined behavior. Nothing deletes a SystemNetworkObject
        // polymorphically today - unlike BaseArpCacheEntry, which ASan caught
        // doing exactly that - but the moment something does, the bug would be
        // silent. Cheap to close now.
        virtual ~SystemNetworkObject() = default;

        virtual void start() = 0;
        virtual void stop() = 0;

    protected:
        static void _set_interface_state(const std::string& name, bool state);
};
