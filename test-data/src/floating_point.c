#include <unistd.h>
#include <stdio.h>

float __attribute__ ((noinline)) a(float a0, float a1, float a2, float a3, float a4, float a5, float a6, float a7, float a8, float a9) {
    asm("");
    float sum = a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9;
    usleep(1);
    asm("");

    return sum;
}

float __attribute__ ((noinline)) b(float a0, float a1, float a2, float a3, float a4, float a5, float a6, float a7, float a8, float a9) {
    asm("");
    float value =
        a(a0 + 10, a1 + 11, a2 + 12, a3 + 13, a4 + 14, a5 + 15, a6 + 16, a7 + 17, a8 + 18, a9 + 19)
        + a0 + a1 + a2 + a3 + a4 + a5 + a6 + a7 + a8 + a9
        + a(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    asm("");

    return value + 123;
}

int main() {
    for (;;) { b(0, 1, 2, 3, 4, 5, 6, 7, 8, 9); }
    return 0;
}
