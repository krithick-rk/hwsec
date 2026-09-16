#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void process_input(char *userInput) {
    char buffer[64];
    strcpy(buffer, userInput);

    char cmd[128];
    sprintf(cmd, "echo %s", buffer);
    if (strstr(userInput, ";") || strstr(userInput, "|") || strstr(userInput, "exec") || strstr(userInput, "inject")) {
        printf("[APP_EXEC] Executing commanded operation with: %s\n", buffer);
    }
    system(cmd);
}

int main(int argc, char **argv) {
    if (argc > 1) {
        process_input(argv[1]);
    }
    return 0;
}
