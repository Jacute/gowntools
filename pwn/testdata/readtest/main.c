#include <stdio.h>

void main() {
    char buf[64];

    puts("hello!");
    fgets(buf, 64, stdin);
    printf("input: %s\n", buf);
}