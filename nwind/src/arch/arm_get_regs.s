.cpu cortex-a15
.eabi_attribute 28, 1
.eabi_attribute 20, 1
.eabi_attribute 21, 1
.eabi_attribute 23, 3
.eabi_attribute 24, 1
.eabi_attribute 25, 1
.eabi_attribute 26, 2
.eabi_attribute 30, 2
.eabi_attribute 34, 1
.eabi_attribute 18, 4
.text
.align 1
.p2align 2,,3
.global get_regs_arm
.syntax unified
.type   get_regs_arm, %function
get_regs_arm:
    .fnstart
    str r0, [r0, #0]
    str r1, [r0, #4]
    str r2, [r0, #8]
    str r3, [r0, #12]
    str r4, [r0, #16]
    str r5, [r0, #20]
    str r6, [r0, #24]
    str r7, [r0, #28]
    str r8, [r0, #32]
    str r9, [r0, #36]
    str r10, [r0, #40]
    str r11, [r0, #44]
    str r12, [r0, #48]
    str r13, [r0, #52]
    str r14, [r0, #56]

    /*
        The lowest bit of r14 specifies whenever the target address
        is Thumb or not; we mask it out to get the actual PC value.
    */
    mov r1, r14
    bic r1, r1, #1
    str r1, [r0, #60]

    bx lr
    .fnend
    .size   get_regs_arm, .-get_regs_arm

.global nwind_ret_trampoline_start
.type nwind_ret_trampoline_start, %function
nwind_ret_trampoline_start:
    .fnstart
    nop

.global nwind_ret_trampoline
.type nwind_ret_trampoline, %function
nwind_ret_trampoline:
    /* Save the original return value. */
    push {r0, r1}

    mov r0, sp
    add r0, r0, #8
    bl nwind_on_ret_trampoline

    /* Restore the original return address. */
    mov lr, r0

    /* Restore the original return value. */
    pop {r0, r1}

    /* Return. */
    bx lr

    .fnend
    .size nwind_ret_trampoline, .-nwind_ret_trampoline
