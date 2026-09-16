#include <stdio.h>
#include <string.h>

void process_input(const char* input) {
    char buf[64];
    // Unsafe string copy without bound checks
    strcpy(buf, input);
    printf("Processed input: %s\n", buf);
}

int main(int argc, char** argv) {
    if (argc > 1) {
        process_input(argv[1]);
    }
    return 0;
}
