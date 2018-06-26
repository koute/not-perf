.set noat

.cfi_startproc
.set    nomips16
.set    nomicromips
.ent    get_regs_mips64
.globl get_regs_mips64
.type get_regs_mips64, @function

get_regs_mips64:
    sd $1, 0*8($2)
    sd $2, 1*8($2)
    sd $3, 2*8($2)
    sd $4, 3*8($2)
    sd $5, 4*8($2)
    sd $6, 5*8($2)
    sd $7, 6*8($2)
    sd $8, 7*8($2)
    sd $9, 8*8($2)
    sd $10, 9*8($2)
    sd $11, 10*8($2)
    sd $12, 11*8($2)
    sd $13, 12*8($2)
    sd $14, 13*8($2)
    sd $15, 14*8($2)
    sd $16, 15*8($2)
    sd $17, 16*8($2)
    sd $18, 17*8($2)
    sd $19, 18*8($2)
    sd $20, 19*8($2)
    sd $21, 20*8($2)
    sd $22, 21*8($2)
    sd $23, 22*8($2)
    sd $24, 23*8($2)
    sd $25, 24*8($2)
    sd $26, 25*8($2)
    sd $27, 26*8($2)
    sd $28, 27*8($2)
    sd $29, 28*8($2)
    sd $30, 29*8($2)
    sd $31, 30*8($2)

    /* Return. */
    j $31
    nop

    .set    macro
    .set    reorder
    .end    get_regs_mips64
    .cfi_endproc
