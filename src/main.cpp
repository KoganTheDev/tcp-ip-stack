#include <iostream>
#include <memory>
#include <unistd.h>

#include "interface_bridge.h"
#include "tun_wrapper.h"
#include "exceptions.h"

#include "ethernet.h"
#include "arp.h"

const bool USE_BRIDGE = false;


int main() 
{   
    if (geteuid() != 0)
    {
        std::cerr << "This program must be run as root. Exiting." << std::endl;
        return 1;
    }

    std::unique_ptr<InterfaceBridge> bridge;
    try
    {
        /*
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

        Bytes ethernet_packet = Bytes::from_hex("ffffffffffff") | Bytes::from_hex("000c29085b73") | Bytes::from_hex("0808");

        while (getchar() != 'x') // x for exit.
        {
            tun.write(ethernet_packet);
            std::cout << "Writing raw packet to interface" << std::endl;
        }
        return 0;
        */
        Bytes my_mac = Bytes("123456123456");
        Bytes dst_mac = Bytes("ABABABABABAB");
        EtherType ether_protocol = ETHERTYPE_ARP;

        Ethernet ether = Ethernet(my_mac, dst_mac, ether_protocol);
        // TODO: Arp arp = Arp() ... Continue here with Alon, main problem, too many fields i don`t know what to do with in ARP constructor
    }
    catch (const BaseException& e)
    {
        std::cerr << "ERROR: " << e.what() << std::endl;
        std::cerr << "Exception from " << e.position() << std::endl;
        return -1;
    }
    catch (...)
    {
        std::cerr << "UNEXPECTED ERROR" << std::endl;
        return -1;
    }
}
