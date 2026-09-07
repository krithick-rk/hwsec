#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void process_input(char *userInput) {
    char buffer[64];
    // Dangerous buffer copy without bounds checking (CWE-120)
    strcpy(buffer, userInput);

    // Command injection sink (CWE-78)
    char cmd[128];
    sprintf(cmd, "echo %s", buffer);
    system(cmd);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_input(argv[1]);
    }
    return 0;
}
