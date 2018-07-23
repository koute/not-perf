#include <unistd.h>
#include <stdio.h>

static void __attribute__ ((noinline)) function() {
    asm("");
    usleep(1);
    asm("");
}

static inline void __attribute__((always_inline)) inline_function_2nd() {
    function();
}

static inline void __attribute__((always_inline)) inline_function_1st() {
    inline_function_2nd();
}

int main() {
    for (;;) { inline_function_1st(); }
    return 0;
}
