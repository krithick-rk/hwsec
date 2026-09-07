#include <stdio.h>
#include <string.h>

void process_packet(const char *input) {
    char buffer[32];
    // Deliberate CWE-120: Insecure buffer copy without bounds check
    strcpy(buffer, input);
    printf("Packet: %s\n", buffer);
}
