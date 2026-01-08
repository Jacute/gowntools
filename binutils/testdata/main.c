#include <stdio.h>
#include <stdlib.h>

void win() {
    system("id");
}

void main() {
    char buf[32];
    puts("hello!");
    fgets(buf, 64, stdin);
}