use std::mem;
use dwarf_regs::DwarfRegs;

extern "C" {
    fn get_regs_amd64( ptr: *mut Regs );
}

#[repr(C)]
#[derive(Debug)]
pub struct Regs {
    rax: u64,
    rbx: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    rbp: u64,
    rsp: u64,
    rip: u64,
    flags: u64,
    cs: u64,
    ss: u64,
    r8: u64,
    r9: u64,
    r10: u64,
    r11: u64,
    r12: u64,
    r13: u64,
    r14: u64,
    r15: u64
}

impl Regs {
    #[inline(always)]
    pub fn get() -> Regs {
        unsafe {
            let mut regs: Regs =  mem::zeroed();
            get_regs_amd64( &mut regs );
            regs
        }
    }

    pub fn into_dwarf_regs( &self, dwarf_regs: &mut DwarfRegs ) {
        use arch::amd64::dwarf;

        dwarf_regs.append( dwarf::RAX, self.rax );
        dwarf_regs.append( dwarf::RBX, self.rbx );
        dwarf_regs.append( dwarf::RCX, self.rcx );
        dwarf_regs.append( dwarf::RDX, self.rdx );
        dwarf_regs.append( dwarf::RSI, self.rsi );
        dwarf_regs.append( dwarf::RDI, self.rdi );
        dwarf_regs.append( dwarf::RBP, self.rbp );
        dwarf_regs.append( dwarf::RSP, self.rsp );
        dwarf_regs.append( dwarf::RETURN_ADDRESS, self.rip );
        dwarf_regs.append( dwarf::FLAGS, self.flags );
        dwarf_regs.append( dwarf::CS, self.cs );
        dwarf_regs.append( dwarf::SS, self.ss );
        dwarf_regs.append( dwarf::R8, self.r8 );
        dwarf_regs.append( dwarf::R9, self.r9 );
        dwarf_regs.append( dwarf::R10, self.r10 );
        dwarf_regs.append( dwarf::R11, self.r11 );
        dwarf_regs.append( dwarf::R12, self.r12 );
        dwarf_regs.append( dwarf::R13, self.r13 );
        dwarf_regs.append( dwarf::R14, self.r14 );
        dwarf_regs.append( dwarf::R15, self.r15 );
    }
}
