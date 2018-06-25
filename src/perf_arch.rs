use nwind::DwarfRegs;

pub trait IntoDwarfRegs {
    fn copy_to_dwarf_regs( &self, regs: &mut DwarfRegs );

    #[inline]
    fn to_dwarf_regs( &self ) -> DwarfRegs {
        let mut regs = DwarfRegs::new();
        self.copy_to_dwarf_regs( &mut regs );
        regs
    }
}

impl< T: IntoDwarfRegs > IntoDwarfRegs for Option< T > {
    fn copy_to_dwarf_regs( &self, regs: &mut DwarfRegs ) {
        regs.clear();
        if let Some( itself ) = self.as_ref() {
            itself.copy_to_dwarf_regs( regs );
        }
    }
}

macro_rules! count {
    ($item:tt, $($next_item:tt),+) => { count!( $item ) + count!( $($next_item),+ ) };
    ($item:tt) => { 1 };
    () => { 0 };
}

macro_rules! mask {
    ($item:tt, $($next_item:tt),+) => { mask!( $item ) | mask!( $($next_item),+ ) };
    ($item:tt) => { (1_u64 << $item) };
    () => { 0 };
}

macro_rules! define_regs {
    ($($perf_reg:ident => $dwarf_reg:ident),+) => {
        #[allow(dead_code)]
        pub const REG_MASK: u64 = mask!( $($perf_reg),+ );
        pub const REG_COUNT: usize = count!( $($perf_reg),+ );

        #[derive(Clone)]
        pub struct Regs {
            pub regs: [u64; count!( $($perf_reg),+ )],
            pub mask: u64
        }

        impl ::std::fmt::Debug for Regs {
            fn fmt( &self, fmt: &mut ::std::fmt::Formatter ) -> Result< (), ::std::fmt::Error > {
                let mut map = fmt.debug_map();
                let mut counter = 0;

                $(
                    map.entry( &stringify!( $dwarf_reg ), &$crate::utils::HexValue( self.regs[ counter ] ) );
                    counter += 1;
                )+

                assert_eq!( counter, REG_COUNT );
                map.finish()
            }
        }

        impl $crate::perf_arch::IntoDwarfRegs for Regs {
            #[allow(unused_assignments)]
            #[inline]
            fn copy_to_dwarf_regs( &self, regs: &mut ::nwind::DwarfRegs ) {
                let mut index = 0;
                let mut last_reg = 0;

                $(
                    if validate( $dwarf_reg, self.regs[ index ] ) {
                        regs.append( $dwarf_reg, self.regs[ index ] );
                    }
                    index += 1;

                    // To ensure that they're in the same order as
                    // Linux's perf subsystem will give them to us.
                    assert!( $perf_reg >= last_reg, "assertion failed: {} >= {}", $perf_reg, last_reg );
                    last_reg = $perf_reg;
                )+

                assert_eq!( index, REG_COUNT );
            }
        }
    }
}

pub mod amd64 {
    use perf_sys::*;
    use nwind::arch::amd64::dwarf::*;

    fn validate( register: u16, value: u64 ) -> bool {
        // If the call chain goes through the kernel space -> user space
        // boundary Linux likes to return invalid RBP values for some reason.
        if register == RBP && value == !0 {
            return false;
        }

        return true;
    }

    define_regs!(
        PERF_REG_X86_AX => RAX,
        PERF_REG_X86_BX => RBX,
        PERF_REG_X86_CX => RCX,
        PERF_REG_X86_DX => RDX,
        PERF_REG_X86_SI => RSI,
        PERF_REG_X86_DI => RDI,
        PERF_REG_X86_BP => RBP,
        PERF_REG_X86_SP => RSP,
        PERF_REG_X86_IP => RETURN_ADDRESS,
        PERF_REG_X86_FLAGS => FLAGS,
        PERF_REG_X86_CS => CS,
        PERF_REG_X86_SS => SS,
        // These result in an invalid argument error:
        // PERF_REG_X86_DS
        // PERF_REG_X86_ES
        // PERF_REG_X86_FS
        // PERF_REG_X86_GS
        PERF_REG_X86_R8 => R8,
        PERF_REG_X86_R9 => R9,
        PERF_REG_X86_R10 => R10,
        PERF_REG_X86_R11 => R11,
        PERF_REG_X86_R12 => R12,
        PERF_REG_X86_R13 => R13,
        PERF_REG_X86_R14 => R14,
        PERF_REG_X86_R15 => R15
    );
}

pub mod mips64 {
    use perf_sys::*;
    use nwind::arch::mips64::dwarf::*;

    fn validate( _register: u16, _value: u64 ) -> bool { return true; }

    define_regs!(
        PERF_REG_MIPS_PC => PC,
        PERF_REG_MIPS_R1 => R1,
        PERF_REG_MIPS_R2 => R2,
        PERF_REG_MIPS_R3 => R3,
        PERF_REG_MIPS_R4 => R4,
        PERF_REG_MIPS_R5 => R5,
        PERF_REG_MIPS_R6 => R6,
        PERF_REG_MIPS_R7 => R7,
        PERF_REG_MIPS_R8 => R8,
        PERF_REG_MIPS_R9 => R9,
        PERF_REG_MIPS_R10 => R10,
        PERF_REG_MIPS_R11 => R11,
        PERF_REG_MIPS_R12 => R12,
        PERF_REG_MIPS_R13 => R13,
        PERF_REG_MIPS_R14 => R14,
        PERF_REG_MIPS_R15 => R15,
        PERF_REG_MIPS_R16 => R16,
        PERF_REG_MIPS_R17 => R17,
        PERF_REG_MIPS_R18 => R18,
        PERF_REG_MIPS_R19 => R19,
        PERF_REG_MIPS_R20 => R20,
        PERF_REG_MIPS_R21 => R21,
        PERF_REG_MIPS_R22 => R22,
        PERF_REG_MIPS_R23 => R23,
        PERF_REG_MIPS_R24 => R24,
        PERF_REG_MIPS_R25 => R25,
        PERF_REG_MIPS_R28 => R28,
        PERF_REG_MIPS_R29 => R29,
        PERF_REG_MIPS_R30 => R30,
        PERF_REG_MIPS_R31 => R31
    );
}

pub mod arm {
    use perf_sys::*;
    use nwind::arch::arm::dwarf::*;

    fn validate( _register: u16, _value: u64 ) -> bool { return true; }

    define_regs!(
        PERF_REG_ARM_R0 => R0,
        PERF_REG_ARM_R1 => R1,
        PERF_REG_ARM_R2 => R2,
        PERF_REG_ARM_R3 => R3,
        PERF_REG_ARM_R4 => R4,
        PERF_REG_ARM_R5 => R5,
        PERF_REG_ARM_R6 => R6,
        PERF_REG_ARM_R7 => R7,
        PERF_REG_ARM_R8 => R8,
        PERF_REG_ARM_R9 => R9,
        PERF_REG_ARM_R10 => R10,
        PERF_REG_ARM_FP => R11,
        PERF_REG_ARM_IP => R12,
        PERF_REG_ARM_SP => R13,
        PERF_REG_ARM_LR => R14,
        PERF_REG_ARM_PC => R15
    );
}

pub mod native {
    #[cfg(target_arch = "x86_64")]
    pub use super::amd64::*;

    #[cfg(target_arch = "mips64")]
    pub use super::mips64::*;

    #[cfg(target_arch = "arm")]
    pub use super::arm::*;
}
