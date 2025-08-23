#include "tc_bridge.h"
#include "exceptions.h"
#include "system_network_object.h"

#include <assert.h>


TCBridge::TCBridge()
{

}

TCBridge::~TCBridge()
{

}

void TCBridge::add_interface(const std::string& interface)
{
    if (this->_is_active)
        throw EXCEPTION(BaseException, "can't add interface while bridge is active");

    if (this->_interfaces.size() >= 2)
        throw EXCEPTION(BaseException, "TC Bridge doesn't support more than 2 interfaces");

    this->_interfaces.push_back(interface);
}

void TCBridge::start()
{
    if (this->_is_active)
        throw EXCEPTION(BaseException, "can't start bridge when it's already active");

    this->_create_bridge();
    this->_is_active = true;
}

void TCBridge::stop()
{
    if (!this->_is_active)
        throw EXCEPTION(BaseException, "can't stop bridge when it's not active");

    this->_delete_bridge(); 
    this->_is_active = false;
}

void TCBridge::_create_bridge()
{
    assert(!this->_is_active);

    SystemNetworkObject::_system_wrapper("sudo tc qdisc add dev tap0 clsact");
    SystemNetworkObject::_system_wrapper("sudo tc filter add dev tap0 ingress matchall action mirred egress mirror dev wlp1s0");
}

void TCBridge::_delete_bridge()
{
    assert(this->_is_active);

    SystemNetworkObject::_system_wrapper("sudo tc qdisc del dev tap0 clsact");
}
