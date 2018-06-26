use std::mem;
use dwarf_regs::DwarfRegs;

extern "C" {
    fn get_regs_mips64( ptr: *mut Regs );
}

#[repr(C)]
#[derive(Debug)]
pub struct Regs {
    r1: u64,
    r2: u64,
    r3: u64,
    r4: u64,
    r5: u64,
    r6: u64,
    r7: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64,
    r16: u64,
    r17: u64,
    r18: u64,
    r19: u64,
    r20: u64,
    r21: u64,
    r22: u64,
    r23: u64,
    r24: u64,
    r25: u64,
    r26: u64,
    r27: u64,
    r28: u64,
    r29: u64,
    r30: u64,
    r31: u64
}

impl Regs {
    #[inline(always)]
    pub fn get() -> Regs {
        unsafe {
            let mut regs: Regs =  mem::zeroed();
            get_regs_mips64( &mut regs );
            regs
        }
    }

    pub fn into_dwarf_regs( &self, dwarf_regs: &mut DwarfRegs ) {
        use arch::mips64::dwarf;

        dwarf_regs.append( dwarf::R0, 0 );
        dwarf_regs.append( dwarf::R1, self.r1 );
        dwarf_regs.append( dwarf::R2, self.r2 );
        dwarf_regs.append( dwarf::R3, self.r3 );
        dwarf_regs.append( dwarf::R4, self.r4 );
        dwarf_regs.append( dwarf::R5, self.r5 );
        dwarf_regs.append( dwarf::R6, self.r6 );
        dwarf_regs.append( dwarf::R7, self.r7 );
        dwarf_regs.append( dwarf::R8, self.r8 );
        dwarf_regs.append( dwarf::R9, self.r9 );
        dwarf_regs.append( dwarf::R10, self.r10 );
        dwarf_regs.append( dwarf::R11, self.r11 );
        dwarf_regs.append( dwarf::R12, self.r12 );
        dwarf_regs.append( dwarf::R13, self.r13 );
        dwarf_regs.append( dwarf::R14, self.r14 );
        dwarf_regs.append( dwarf::R15, self.r15 );
        dwarf_regs.append( dwarf::R16, self.r16 );
        dwarf_regs.append( dwarf::R17, self.r17 );
        dwarf_regs.append( dwarf::R18, self.r18 );
        dwarf_regs.append( dwarf::R19, self.r19 );
        dwarf_regs.append( dwarf::R20, self.r20 );
        dwarf_regs.append( dwarf::R21, self.r21 );
        dwarf_regs.append( dwarf::R22, self.r22 );
        dwarf_regs.append( dwarf::R23, self.r23 );
        dwarf_regs.append( dwarf::R24, self.r24 );
        dwarf_regs.append( dwarf::R25, self.r25 );
        dwarf_regs.append( dwarf::R26, self.r26 );
        dwarf_regs.append( dwarf::R27, self.r27 );
        dwarf_regs.append( dwarf::R28, self.r28 );
        dwarf_regs.append( dwarf::R29, self.r29 );
        dwarf_regs.append( dwarf::R30, self.r30 );
        dwarf_regs.append( dwarf::R31, self.r31 );
        dwarf_regs.append( dwarf::PC, self.r31 );
    }
}
