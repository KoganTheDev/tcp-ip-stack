#include <iostream>
#include <string>
#include <vector>



class Bridge {       // The class
  public:             // Access specifier
    
    Bridge(std::vector<std::string> _interfaces){
        this->_interfaces = _interfaces;



    }

  private:
    std::vector<std::string> _interfaces;


};