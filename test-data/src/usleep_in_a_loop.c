#include <unistd.h>
#include <stdio.h>

void __attribute__ ((noinline)) function() {
    asm("");
    usleep(1);
    asm("");
}

int main() {
    for (;;) { function(); }
    return 0;
}
