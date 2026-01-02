#include <stdio.h>

void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void main() {
    char buf[64];

    init();
    puts("hello!");
    fgets(buf, 64, stdin);
    buf[strcspn(buf, "\n")] = 0;
    printf("input: %s\n", buf);
}