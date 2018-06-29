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
