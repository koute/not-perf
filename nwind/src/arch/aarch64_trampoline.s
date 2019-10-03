    .arch armv8-a
    .text
    .align    2
    .p2align 3,,7
    .global    nwind_ret_trampoline_start
    .hidden    nwind_ret_trampoline_start
    .type    nwind_ret_trampoline_start, %function
nwind_ret_trampoline_start:
.LFB0:
    .cfi_startproc
    .cfi_personality 0x9b,DW.ref.__gxx_personality_v0
    .cfi_lsda 0x1b,.LLSDA0
    .cfi_undefined lr
.LEHB0:
    nop
.LEHE0:

.globl nwind_ret_trampoline
.type nwind_ret_trampoline, @function
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

.L3:
    bl    nwind_on_exception_through_trampoline
    /* Restore the real return address. */
    mov x30, x0
    b     __cxa_rethrow

    .cfi_endproc
.LFE0:
    .global    __gxx_personality_v0
    .section    .gcc_except_table,"a",@progbits
    .align    2
.LLSDA0:
    .byte    0xff
    .byte    0x9b
    .uleb128 .LLSDATT0-.LLSDATTD0
.LLSDATTD0:
    .byte    0x1
    .uleb128 .LLSDACSE0-.LLSDACSB0
.LLSDACSB0:
    .uleb128 .LEHB0-.LFB0
    .uleb128 .LEHE0-.LEHB0
    .uleb128 .L3-.LFB0
    .uleb128 0x1
.LLSDACSE0:
    .byte    0x1
    .byte    0
    .align    2
    .4byte    0

.LLSDATT0:
    .text
    .size    nwind_ret_trampoline_start, .-nwind_ret_trampoline_start
    .hidden    DW.ref.__gxx_personality_v0
    .weak    DW.ref.__gxx_personality_v0
    .section    .data.rel.local.DW.ref.__gxx_personality_v0,"awG",@progbits,DW.ref.__gxx_personality_v0,comdat
    .align    3
    .type    DW.ref.__gxx_personality_v0, %object
    .size    DW.ref.__gxx_personality_v0, 8
DW.ref.__gxx_personality_v0:
    .xword    __gxx_personality_v0
    .hidden    nwind_on_exception_through_trampoline
    .hidden    nwind_on_ret_trampoline
    .section    .note.GNU-stack,"",@progbits
