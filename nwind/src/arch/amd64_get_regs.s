.intel_syntax noprefix

.p2align 4,,15
.globl get_regs_amd64
.type get_regs_amd64, @function

get_regs_amd64:
    .cfi_startproc
    mov QWORD PTR [rdi+8*0], rax
    mov QWORD PTR [rdi+8*1], rdx
    mov QWORD PTR [rdi+8*2], rcx
    mov QWORD PTR [rdi+8*3], rbx
    mov QWORD PTR [rdi+8*4], rsi
    mov QWORD PTR [rdi+8*5], rdi
    mov QWORD PTR [rdi+8*6], rbp

    /* RSP */
    mov rax, rsp
    add rax, 8 /* Skip the return address. */
    mov QWORD PTR [rdi+8*7], rax

    mov QWORD PTR [rdi+8*8], r8
    mov QWORD PTR [rdi+8*9], r9
    mov QWORD PTR [rdi+8*10], r10
    mov QWORD PTR [rdi+8*11], r11
    mov QWORD PTR [rdi+8*12], r12
    mov QWORD PTR [rdi+8*13], r13
    mov QWORD PTR [rdi+8*14], r14
    mov QWORD PTR [rdi+8*15], r15

    /* RIP */
    mov rax, [rsp]
    mov QWORD PTR [rdi+8*16], rax

    /* RFLAGS */
    pushfq
    .cfi_def_cfa_offset 16
    pop [rdi+8*49]
    .cfi_def_cfa_offset 8

    mov rax, cs
    mov QWORD PTR [rdi+8*51], rax

    mov rax, ss
    mov QWORD PTR [rdi+8*52], rax

    ret
    .cfi_endproc

.p2align 4,,15
.globl nwind_ret_trampoline
.type nwind_ret_trampoline, @function

    .cfi_startproc
    .cfi_personality 0x9b,DW.ref.nwind_ret_trampoline_personality

    /* The stack pointer is already unwound. */
    .cfi_def_cfa_offset 0
    /* We reuse the slot for the return address. */
    .cfi_offset 16, 8

    /* We need this nop as the unwinder looks at $addr - 1 when looking for a CFI. */
    nop

nwind_ret_trampoline:
    /* Save the return value of the original function. */
    push rax
    push rdx

    mov rdi, rsp
    add rdi, 16
    call nwind_on_ret_trampoline

    mov rsi, rax
    pop rdx
    pop rax
    jmp rsi
    .cfi_endproc

.globl nwind_on_ret_trampoline
.type nwind_on_ret_trampoline, @function

    .section    .text.startup

    .hidden DW.ref.nwind_ret_trampoline_personality
    .weak   DW.ref.nwind_ret_trampoline_personality
    .section    .data.rel.local.DW.ref.nwind_ret_trampoline_personality,"awG",@progbits,DW.ref.nwind_ret_trampoline_personality,comdat
    .align 8
    .type   DW.ref.nwind_ret_trampoline_personality, @object
    .size   DW.ref.nwind_ret_trampoline_personality, 8
DW.ref.nwind_ret_trampoline_personality:
    .quad   nwind_ret_trampoline_personality
