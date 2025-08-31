#include <iostream>
#include <memory>
#include <unistd.h>

#include "exceptions.h"

#include "ethernet.h"
#include "arp.h"

#include "raw_socket.h"

// Used for in communication between VM`s linux and my computer
#define INTERFACE_NAME "vmnet8"

int main() 
{   
    if (geteuid() != 0)
    {
        std::cerr << "This program must be run as root. Exiting." << std::endl;
        return 1;
    }

    try
    {
        RawSocket socket(INTERFACE_NAME);

        Ethernet packet(socket.get_mac_address(), MacAddress::BROADCAST, (EtherType)0xcafe);
        for (int i = 0; i < 3; i++)
            socket.send(packet.to_bytes());
        for (int i = 0; i < 100; i ++)
        {
            
            try
            {
                Bytes p = socket.recv();
                // std::cout << p.to_hex() << std::endl;
                Ethernet ether = Ethernet(p);
                if (ether.get_dest() == MacAddress("00:50:56:c0:00:08") || ether.get_src() == MacAddress("00:50:56:c0:00:08"))
                    std::cout << ether.to_string() << std::endl << std::endl;
            }
            catch(const BaseException& e)
            {
            }
        }

        /*
        MacAddress src("11:22:33:44:55:66");
        MacAddress dst("AA:BB:CC:DD:EE:FF");
        EtherType ether_protocol = EtherType::ARP;

        Ethernet ether = Ethernet(src, dst, ether_protocol);

        ether /= std::make_unique<Arp>(src, IPv4Address("1.2.3.4"), IPv4Address("8.8.8.8"));
        std::cout << ether.to_string() << std::endl;

        Bytes packet = ether.to_bytes();
        packet |= Bytes::from_hex("cafecafe0011223344556677cafecafe");
        std::cout << packet.to_hex() << std::endl;

        Ethernet new_ether;
        new_ether.from_bytes(packet);

        std::cout << new_ether.to_string() << std::endl;

        std::cout << new_ether.to_bytes().to_hex() << std::endl;
        */

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
