    .text
    .section    .text.unlikely,"ax",@progbits
.LCOLDB0:
    .text
.LHOTB0:
    .p2align 4
    .globl    nwind_ret_trampoline_start
    .hidden    nwind_ret_trampoline_start
    .type    nwind_ret_trampoline_start, @function
nwind_ret_trampoline_start:
.LFB0:
    .cfi_startproc
    .cfi_personality 0x9b,DW.ref.__gxx_personality_v0
    .cfi_lsda 0x1b,.LLSDA0
    .cfi_undefined rip
.LEHB0:
    nop
.LEHE0:

.globl nwind_ret_trampoline
.type nwind_ret_trampoline, @function
nwind_ret_trampoline:
.intel_syntax noprefix
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
.att_syntax

.L3:
    movq    %rax, %rdi
    jmp    .L2
    .globl    __gxx_personality_v0
    .section    .gcc_except_table,"a",@progbits
    .align 4
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
    .align 4
    .long    0

.LLSDATT0:
    .text
    .cfi_endproc
    .section    .text.unlikely
    .cfi_startproc
    .cfi_personality 0x9b,DW.ref.__gxx_personality_v0
    .cfi_lsda 0x1b,.LLSDAC0
    .type    nwind_ret_trampoline_start.cold, @function
nwind_ret_trampoline_start.cold:
.LFSB0:
.L2:
    call    nwind_on_exception_through_trampoline
    /* Push real return address. */
    push %rax
    jmp     __cxa_rethrow@PLT
    .cfi_endproc
.LFE0:
    .section    .gcc_except_table
    .align 4
.LLSDAC0:
    .byte    0xff
    .byte    0x9b
    .uleb128 .LLSDATTC0-.LLSDATTDC0
.LLSDATTDC0:
    .byte    0x1
    .uleb128 .LLSDACSEC0-.LLSDACSBC0
.LLSDACSBC0:
.LLSDACSEC0:
    .byte    0x1
    .byte    0
    .align 4
    .long    0

.LLSDATTC0:
    .section    .text.unlikely
    .text
    .size    nwind_ret_trampoline_start, .-nwind_ret_trampoline_start
    .section    .text.unlikely
    .size    nwind_ret_trampoline_start.cold, .-nwind_ret_trampoline_start.cold
.LCOLDE0:
    .text
.LHOTE0:
    .hidden    DW.ref.__gxx_personality_v0
    .weak    DW.ref.__gxx_personality_v0
    .section    .data.rel.local.DW.ref.__gxx_personality_v0,"awG",@progbits,DW.ref.__gxx_personality_v0,comdat
    .align 8
    .type    DW.ref.__gxx_personality_v0, @object
    .size    DW.ref.__gxx_personality_v0, 8
DW.ref.__gxx_personality_v0:
    .quad    __gxx_personality_v0
    .hidden    nwind_on_exception_through_trampoline
    .hidden    nwind_on_ret_trampoline
    .section    .note.GNU-stack,"",@progbits
