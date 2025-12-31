#include <stdio.h>
#include <stdlib.h>


void init() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}


void win() {
    system("id");
}

void main() {
    char buf[64];

    init();
    puts("hello! please overflow me");
    read(0, buf, 96);
}