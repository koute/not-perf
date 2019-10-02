    .file    1 "trampoline-template.cpp"
    .section .mdebug.abi64
    .previous
    .nan    legacy
    .module    fp=64
    .module    oddspreg
    .abicalls
    .text
    .align    2
    .align    3
    .globl    nwind_ret_trampoline_start
    .hidden    nwind_ret_trampoline_start
.LFB0 = .
    .cfi_startproc
    .cfi_personality 0x80,DW.ref.__gxx_personality_v0
    .cfi_lsda 0,.LLSDA0
    .set    nomips16
    .set    nomicromips
    .ent    nwind_ret_trampoline_start
    .type    nwind_ret_trampoline_start, @function
nwind_ret_trampoline_start:
    .frame    $sp,16,$31        # vars= 0, regs= 2/0, args= 0, gp= 0
    .mask    0x90000000,-8
    .fmask    0x00000000,0
    .set    noreorder
    .set    nomacro
    daddiu    $sp,$sp,-16
    .cfi_def_cfa_offset 16
    sd    $28,0($sp)
    .cfi_offset 28, -16
    lui    $28,%hi(%neg(%gp_rel(nwind_ret_trampoline_start)))
    daddu    $28,$28,$25
    daddiu    $28,$28,%lo(%neg(%gp_rel(nwind_ret_trampoline_start)))
    ld    $25,%got_disp(nwind_dummy)($28)
    sd    $31,8($sp)
    .cfi_offset 31, -8
.LEHB0 = .
    .reloc    1f,R_MIPS_JALR,nwind_dummy
1:    jalr    $25
    nop

.LEHE0 = .
    ld    $25,%got_disp(nwind_on_ret_trampoline)($28)
    .reloc    1f,R_MIPS_JALR,nwind_on_ret_trampoline
1:    jalr    $25
    nop

.L3:
    ld    $25,%call16(__cxa_begin_catch)($28)
    .reloc    1f,R_MIPS_JALR,__cxa_begin_catch
1:    jalr    $25
    nop

    ld    $25,%got_disp(nwind_on_exception_through_trampoline)($28)
    .reloc    1f,R_MIPS_JALR,nwind_on_exception_through_trampoline
1:    jalr    $25
    nop

    ld    $25,%call16(__cxa_rethrow)($28)
    .reloc    1f,R_MIPS_JALR,__cxa_rethrow
1:    jalr    $25
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
    .text
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
    .hidden    nwind_dummy
    .ident    "GCC: (Ubuntu 8.3.0-2ubuntu2) 8.3.0"
