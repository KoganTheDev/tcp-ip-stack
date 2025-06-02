#include <iostream>
#include <memory>

#include "interface_bridge.h"
#include "tun_wrapper.h"
#include "custom_exception.h"


const bool USE_BRIDGE = false;


int main() 
{
    std::unique_ptr<InterfaceBridge> bridge;
    try
    {
        TunWrapper tun = TunWrapper();
        tun.start();
        
        if (USE_BRIDGE)
        {
            bridge = std::make_unique<InterfaceBridge>("br0");
            bridge->add_interface(tun.get_interface_name());
            bridge->add_interface("wlp1s0");
            bridge->start();
        }

        std::cout << "Finished network setup" << std::endl;   

        getchar();
        Bytes ethernet_packet({
            '\xff', '\xff', '\xff', '\xff', '\xff', '\xff',
            '\x00', '\x0c', '\x29', '\x08', '\x5b', '\x73',
            '\x08', '\x08'
        });
        std::cout << ethernet_packet.size() << std::endl;
        tun.write(ethernet_packet);
        std::cout << "Writing raw packet to interface" << std::endl;
        getchar();

        return 0;
    }
    catch (const CustomException& e)
    {
        std::cerr << "ERROR: " << e.what() << std::endl;
        return -1;
    }
    catch (...)
    {
        std::cerr << "UNEXPECTED ERROR" << std::endl;
        return -1;
    }
}
