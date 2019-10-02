    .arch armv8-a
    .file    "trampoline-template.cpp"
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
    stp    x29, x30, [sp, -16]!
    .cfi_def_cfa_offset 16
    .cfi_offset 29, -16
    .cfi_offset 30, -8
    mov    x29, sp
.LEHB0:
    bl    nwind_dummy
.LEHE0:
    bl    nwind_on_ret_trampoline
.L3:
    bl    __cxa_begin_catch
    bl    nwind_on_exception_through_trampoline
    bl    __cxa_rethrow
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
    .hidden    nwind_dummy
    .ident    "GCC: (Ubuntu/Linaro 8.3.0-6ubuntu1) 8.3.0"
    .section    .note.GNU-stack,"",@progbits
