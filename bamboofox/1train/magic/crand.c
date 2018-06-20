#include <stdio.h>
#include <time.h>
#include <stdlib.h>

int main() {
    int i;
    srand(time(NULL));
    for (i = 0; i < 0x50; i++) {
        printf("%02X ", rand() % 256);
    }
    puts("");
    return 0;
}