#include <stdio.h>

void main() {
    char buf[32];
    puts("hello!");
    fgets(buf, 64, stdin);
}