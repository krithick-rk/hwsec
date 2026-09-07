#include <iostream>
#include <cstring>

class ConfigParser {
public:
    void parse(const char *source) {
        char target[64];
        // Insecure memory copy
        strcpy(target, source);
        std::cout << "Config: " << target << std::endl;
    }
};
