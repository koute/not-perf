.arch armv8-a
.text
.align  2
.p2align 3,,7
.global get_regs_aarch64
.type   get_regs_aarch64, %function
get_regs_aarch64:
    .cfi_startproc
    stp x0, x1, [x0]
    stp x2, x3, [x0, 16]
    stp x4, x5, [x0, 32]
    stp x6, x7, [x0, 48]
    stp x8, x9, [x0, 64]
    stp x10, x11, [x0, 80]
    stp x12, x13, [x0, 96]
    stp x14, x15, [x0, 112]
    stp x16, x17, [x0, 128]
    stp x18, x19, [x0, 144]
    stp x20, x21, [x0, 160]
    stp x22, x23, [x0, 176]
    stp x24, x25, [x0, 192]
    stp x26, x27, [x0, 208]
    stp x28, x29, [x0, 224]
    str x30, [x0, 240]

    mov x9, sp
    str x9, [x0, 248]

    str x30, [x0, 256]
    ret
    .cfi_endproc
    .size   get_regs_aarch64, .-get_regs_aarch64

.global nwind_ret_trampoline_start
.type nwind_ret_trampoline_start, %function
nwind_ret_trampoline_start:
    nop

.global nwind_ret_trampoline
.type nwind_ret_trampoline, %function
nwind_ret_trampoline:
    /* Save the original return value. */
    sub sp, sp, #(8 * 8)
    stp x0, x1, [sp, 0]
    stp x2, x3, [sp, 16]
    stp x4, x5, [sp, 32]
    stp x6, x7, [sp, 48]

    mov x0, sp
    add x0, x0, #64
    bl nwind_on_ret_trampoline

    /* Restore the original return address. */
    mov x30, x0

    /* Restore the original return value. */
    ldp x0, x1, [sp, 0]
    ldp x2, x3, [sp, 16]
    ldp x4, x5, [sp, 32]
    ldp x6, x7, [sp, 48]
    add sp, sp, #(8 * 8)

    /* Return. */
    br x30

    nop
    .size nwind_ret_trampoline, .-nwind_ret_trampoline
