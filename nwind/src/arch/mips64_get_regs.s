.set noat

.cfi_startproc
.set    nomips16
.set    nomicromips
.ent    get_regs_mips64
.globl get_regs_mips64
.type get_regs_mips64, @function

get_regs_mips64:
    sd $0, 0*8($4)
    sd $1, 1*8($4)
    sd $2, 2*8($4)
    sd $3, 3*8($4)
    sd $4, 4*8($4)
    sd $5, 5*8($4)
    sd $6, 6*8($4)
    sd $7, 7*8($4)
    sd $8, 8*8($4)
    sd $9, 9*8($4)
    sd $10, 10*8($4)
    sd $11, 11*8($4)
    sd $12, 12*8($4)
    sd $13, 13*8($4)
    sd $14, 14*8($4)
    sd $15, 15*8($4)
    sd $16, 16*8($4)
    sd $17, 17*8($4)
    sd $18, 18*8($4)
    sd $19, 19*8($4)
    sd $20, 20*8($4)
    sd $21, 21*8($4)
    sd $22, 22*8($4)
    sd $23, 23*8($4)
    sd $24, 24*8($4)
    sd $25, 25*8($4)
    sd $26, 26*8($4)
    sd $27, 27*8($4)
    sd $28, 28*8($4)
    sd $29, 29*8($4)
    sd $30, 30*8($4)
    sd $31, 31*8($4)
    sd $31, 34*8($4)

    /* Return. */
    j $31

    .set    macro
    .set    reorder
    .end    get_regs_mips64
    .cfi_endproc


    .section    .text.trampoline
    .align 12 /* Align to a page boundary. (2 ** 12 = 4096) */
    .globl nwind_ret_trampoline
    .cfi_startproc

.globl nwind_ret_trampoline_start
.type nwind_ret_trampoline_start, @function
nwind_ret_trampoline_start:

    .cfi_personality 0x80,DW.ref.nwind_ret_trampoline_personality

    /* The stack pointer is already unwound. */
    .cfi_def_cfa_offset 0
    /* We reuse the slot for the return address. */
    .cfi_offset 16, 8

    /* We need this nop as the unwinder looks at $addr - 1 when looking for a CFI. */
    nop

        .set    nomips16
        .set    nomicromips
        .ent    nwind_ret_trampoline
        .type   nwind_ret_trampoline, @function
nwind_ret_trampoline:
        .mask   0x90000000,-8
        .fmask  0x00000000,0
        .set    noreorder
        .set    nomacro

    /* Pass the stack pointer as the first argument to the handler. */
    move $4, $sp

    /* Save the return value of the original function. */
    daddiu $sp, $sp, -8
    sd $2, ($sp)

    daddiu $sp, $sp, -8
    sd $3, ($sp)

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

    /* Call the handler. */
    jalr $25
    nop

    /* Grab the real return address. */
    move $31, $2

    /* Restore the original return value. */
    ld      $3, 0($sp)
    daddiu  $sp, $sp, 8

    ld      $2, 0($sp)
    daddiu  $sp, $sp, 8

    /* Jump to the outer frame. */
    jr $31
    nop

    .set    macro
    .set    reorder
    .end    nwind_ret_trampoline
    .cfi_endproc
    .size   nwind_ret_trampoline, .-nwind_ret_trampoline

    .section    .text.startup

    .hidden DW.ref.nwind_ret_trampoline_personality
    .weak   DW.ref.nwind_ret_trampoline_personality
    .section    .data.DW.ref.nwind_ret_trampoline_personality,"awG",@progbits,DW.ref.nwind_ret_trampoline_personality,comdat
    .align 8
    .type   DW.ref.nwind_ret_trampoline_personality, @object
    .size   DW.ref.nwind_ret_trampoline_personality, 8
DW.ref.nwind_ret_trampoline_personality:
    .quad   nwind_ret_trampoline_personality
