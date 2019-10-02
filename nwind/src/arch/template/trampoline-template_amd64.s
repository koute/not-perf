    .file    "trampoline-template.cpp"
    .text
    .section    .text.unlikely,"ax",@progbits
.LCOLDB0:
    .text
.LHOTB0:
    .p2align 4,,15
    .globl    nwind_ret_trampoline_start
    .hidden    nwind_ret_trampoline_start
    .type    nwind_ret_trampoline_start, @function
nwind_ret_trampoline_start:
.LFB0:
    .cfi_startproc
    .cfi_personality 0x9b,DW.ref.__gxx_personality_v0
    .cfi_lsda 0x1b,.LLSDA0
    subq    $8, %rsp
    .cfi_def_cfa_offset 16
.LEHB0:
    call    nwind_dummy
.LEHE0:
    call    nwind_on_ret_trampoline
.L3:
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
    .type    nwind_ret_trampoline_start.cold.0, @function
nwind_ret_trampoline_start.cold.0:
.LFSB0:
.L2:
    .cfi_def_cfa_offset 16
    movq    %rax, %rdi
    call    __cxa_begin_catch@PLT
    call    nwind_on_exception_through_trampoline
    call    __cxa_rethrow@PLT
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
    .size    nwind_ret_trampoline_start.cold.0, .-nwind_ret_trampoline_start.cold.0
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
    .hidden    nwind_dummy
    .ident    "GCC: (Ubuntu 8.3.0-6ubuntu1) 8.3.0"
    .section    .note.GNU-stack,"",@progbits
