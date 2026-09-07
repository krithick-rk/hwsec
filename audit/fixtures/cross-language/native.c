#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc > 1) {
        char buffer[32];
        // Potential buffer overflow in C native binary
        strcpy(buffer, argv[1]);
        printf("Native received: %s\n", buffer);
    }
    return 0;
}
