#include <stdio.h>
#include <stdlib.h>


void win() {
    system("id");
}

void main() {
    char buf[64];

    puts("hello! please overflow me");
    fgets(buf, 96, stdin);
}