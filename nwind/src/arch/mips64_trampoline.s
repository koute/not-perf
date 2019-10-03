    .section .mdebug.abi64
    .previous
    .nan    legacy
    .module    fp=64
    .module    oddspreg
    .abicalls

    .section    .text.trampoline
    .align 12 /* Align to a page boundary. (2 ** 12 = 4096) */

    .globl    nwind_ret_trampoline_start
    .hidden    nwind_ret_trampoline_start
.LFB0 = .
    .cfi_startproc
    .cfi_personality 0x80,DW.ref.__gxx_personality_v0
    .cfi_lsda 0,.LLSDA0
    .cfi_undefined $31
    .set    nomips16
    .set    nomicromips
    .ent    nwind_ret_trampoline_start
    .type    nwind_ret_trampoline_start, @function
nwind_ret_trampoline_start:
    .mask    0x90000000,-8
    .fmask    0x00000000,0
    .set    noreorder
    .set    nomacro

.LEHB0 = .
    nop

.LEHE0 = .

.globl nwind_ret_trampoline
.type nwind_ret_trampoline, @function
nwind_ret_trampoline:

    /* Pass the stack pointer as the first argument to the handler. */
    move $4, $sp

    /* Save the return value of the original function. */
    daddiu $sp, $sp, -16
    sd $2, 0($sp)
    sd $3, 8($sp)

    /*
        Load the address of our handler. This will be patched at runtime
        with the actual address.
    */
    lui $25, 0x1234
    ori $25, $25, 0x5678
    dsll $25, $25, 16
    ori $25, $25, 0xABCD
    dsll $25, $25, 16
    ori $25, $25, 0xEF00

    /* Call `nwind_on_ret_trampoline`. */
    jalr $25
    nop

    /* Grab the real return address. */
    move $31, $2

    /* Restore the original return value. */
    ld      $3, 8($sp)
    ld      $2, 0($sp)

    /* Jump to the outer frame. */
    jr $31
    daddiu  $sp, $sp, 16

.L3:
    lui $25, 0x1234
    ori $25, $25, 0x5678
    dsll $25, $25, 16
    ori $25, $25, 0xABCD
    dsll $25, $25, 16
    ori $25, $25, 0xEF01

    /* Call `nwind_on_exception_through_trampoline`. */
    jalr $25
    nop

    /* Restore the real return address. */
    move $31, $2

    lui $25, 0x1234
    ori $25, $25, 0x5678
    dsll $25, $25, 16
    ori $25, $25, 0xABCD
    dsll $25, $25, 16
    ori $25, $25, 0xEF02

    /* Call `__cxa_rethrow`. */
    jr $25
    nop

    .set    macro
    .set    reorder
    .end    nwind_ret_trampoline_start
    .cfi_endproc
.LFE0:
    .globl    __gxx_personality_v0
    .section    .gcc_except_table,"aw",@progbits
    .align    3
.LLSDA0:
    .byte    0xff
    .byte    0x80
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
    .align    3
    .8byte    0

.LLSDATT0:
    .section .text.trampoline
    .size    nwind_ret_trampoline_start, .-nwind_ret_trampoline_start
    .hidden    DW.ref.__gxx_personality_v0
    .weak    DW.ref.__gxx_personality_v0
    .section    .data.rel.local.DW.ref.__gxx_personality_v0,"awG",@progbits,DW.ref.__gxx_personality_v0,comdat
    .align    3
    .type    DW.ref.__gxx_personality_v0, @object
    .size    DW.ref.__gxx_personality_v0, 8
DW.ref.__gxx_personality_v0:
    .dword    __gxx_personality_v0
    .hidden    nwind_on_exception_through_trampoline
    .hidden    nwind_on_ret_trampoline
