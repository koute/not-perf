#include <unistd.h>

void __attribute__ ((noreturn, noinline)) infinite_loop() {
    asm("");
    for (;;) {
        usleep(1);
    }
}

void __attribute__ ((noreturn, noinline)) function() {
    asm("");
    infinite_loop();
}

int main() {
    function();
    return 0;
}
