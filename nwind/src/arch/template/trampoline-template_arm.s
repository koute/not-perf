    .arch armv7-a
    .eabi_attribute 28, 1
    .eabi_attribute 20, 1
    .eabi_attribute 21, 1
    .eabi_attribute 23, 3
    .eabi_attribute 24, 1
    .eabi_attribute 25, 1
    .eabi_attribute 26, 2
    .eabi_attribute 30, 2
    .eabi_attribute 34, 1
    .eabi_attribute 18, 4
    .file    "trampoline-template.cpp"
    .text
    .align    1
    .p2align 2,,3
    .global    nwind_ret_trampoline_start
    .hidden    nwind_ret_trampoline_start
    .arch armv7-a
    .syntax unified
    .thumb
    .thumb_func
    .fpu vfpv3-d16
    .type    nwind_ret_trampoline_start, %function
nwind_ret_trampoline_start:
    .fnstart
.LFB0:
    @ Volatile: function does not return.
    @ args = 0, pretend = 0, frame = 0
    @ frame_needed = 0, uses_anonymous_args = 0
    push    {r3, lr}
    .save {r3, lr}
.LEHB0:
    bl    nwind_dummy(PLT)
.LEHE0:
    bl    nwind_on_ret_trampoline(PLT)
.L3:
    bl    __cxa_begin_catch(PLT)
    bl    nwind_on_exception_through_trampoline(PLT)
    bl    __cxa_rethrow(PLT)
    .global    __gxx_personality_v0
    .personality    __gxx_personality_v0
    .handlerdata
    .align    2
.LLSDA0:
    .byte    0xff
    .byte    0x90
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
    .word    0
.LLSDATT0:
    .text
    .fnend
    .size    nwind_ret_trampoline_start, .-nwind_ret_trampoline_start
    .hidden    nwind_on_exception_through_trampoline
    .hidden    nwind_on_ret_trampoline
    .hidden    nwind_dummy
    .ident    "GCC: (Ubuntu/Linaro 8.3.0-6ubuntu1) 8.3.0"
    .section    .note.GNU-stack,"",%progbits
