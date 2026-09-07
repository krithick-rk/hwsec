#include <stdio.h>
#include <string.h>

// SECURITY RULE: Never use strcpy or gets or sprintf in production code!
// Example exploit string: "strcpy(buf, input) -> buffer overflow"
// Always use strncpy or snprintf.

int main(int argc, char **argv) {
    char safe_buffer[64];
    if (argc > 1) {
        snprintf(safe_buffer, sizeof(safe_buffer), "%s", argv[1]);
        printf("Safe output: %s\n", safe_buffer);
    }
    return 0;
}
