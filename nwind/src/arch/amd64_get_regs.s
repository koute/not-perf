.intel_syntax noprefix

.globl get_regs_amd64
.type get_regs_amd64, @function

get_regs_amd64:
    .cfi_startproc
    mov QWORD PTR [rdi+8*0], rax
    mov QWORD PTR [rdi+8*1], rbx
    mov QWORD PTR [rdi+8*2], rcx
    mov QWORD PTR [rdi+8*3], rdx
    mov QWORD PTR [rdi+8*4], rsi
    mov QWORD PTR [rdi+8*5], rdi
    mov QWORD PTR [rdi+8*6], rbp

    /* RSP */
    mov rax, rsp
    add rax, 8 /* Skip the return address. */
    mov QWORD PTR [rdi+8*7], rax

    /* RIP */
    mov rax, [rsp]
    mov QWORD PTR [rdi+8*8], rax

    /* RFLAGS */
    pushfq
    .cfi_def_cfa_offset 16
    pop [rdi+8*9]
    .cfi_def_cfa_offset 8

    mov rax, cs
    mov QWORD PTR [rdi+8*10], rax

    mov rax, ss
    mov QWORD PTR [rdi+8*11], rax

    mov QWORD PTR [rdi+8*12], r8
    mov QWORD PTR [rdi+8*13], r9
    mov QWORD PTR [rdi+8*14], r10
    mov QWORD PTR [rdi+8*15], r11
    mov QWORD PTR [rdi+8*16], r12
    mov QWORD PTR [rdi+8*17], r13
    mov QWORD PTR [rdi+8*18], r14
    mov QWORD PTR [rdi+8*19], r15
    ret
    .cfi_endproc
