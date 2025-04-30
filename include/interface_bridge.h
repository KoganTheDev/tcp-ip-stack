#pragma once

#include <iostream>
#include <string>
#include <vector>


class InterfaceBridge 
{
public:
    InterfaceBridge(std::vector<std::string>& interfaces);
    ~InterfaceBridge();
    
    void start();
    void stop();

private:
    std::vector<std::string> _interfaces;
    bool _is_active;
};
