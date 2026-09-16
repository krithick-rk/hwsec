#include <stdio.h>
#include <string.h>

void process_input(const char* input) {
    char buf[64];
    // Safe bounded string copy
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    printf("Processed input: %s\n", buf);
}

int main(int argc, char** argv) {
    if (argc > 1) {
        process_input(argv[1]);
    }
    return 0;
}
