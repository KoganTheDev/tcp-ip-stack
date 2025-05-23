#include <iostream>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdint.h>

#include "interface_bridge.h"



int tun_read(int fd, char *buf, int len)
{
    return read(fd, buf, len);
}

int tun_write(int fd, char *buf, int len)
{
    return write(fd, buf, len);
}

int set_interface_up(const char* interface)
{
    char command[128] = {0};
    snprintf(command, sizeof command, "sudo ip link set %s up", interface);
    return system(command);
}

int bridge_interfaces(const char* bridge_name, const char* interface1, const char* interface2)
{
    char command[128] = {0};

    // create bridge
    snprintf(command, sizeof command, "sudo ip link add name %s type bridge", bridge_name);
    system(command);
    set_interface_up(bridge_name);

    // add interfaces to bridge
    snprintf(command, sizeof command, "sudo ip link set %s master %s", interface1, bridge_name);
    system(command);
    snprintf(command, sizeof command, "sudo ip link set %s master %s", interface2, bridge_name);
    system(command);

    // TODO return error properly
    return 0;
}

int main() 
{
    InterfaceBridge bridge("br0", {"ens33"});

    uint8_t example[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
        0x00, 0x0c, 0x29, 0x08, 0x5b, 0x73,
        0x08, 0x00
    };
    char tap_interface[10] = {0};
    int fd = tun_alloc(tap_interface);
    set_interface_up(tap_interface);
    printf("Opened TAP: %s\n", tap_interface);
    bridge.add_interface(tap_interface);

    printf("Creating bridge br0\n");
    bridge.start();

    getchar();

    printf("Writing raw packet to ens33\n");
    tun_write(fd, (char*)example, sizeof example);
    // tun_read(fd, (char*)example, sizeof example);

    return 0;
}
