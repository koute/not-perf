use arch::{Registers, RegsIter};

#[derive(Clone)]
pub struct DwarfRegs {
    regs: Vec< u64 >,
    regs_mask: u64,
    regs_list: Vec< u16 >
}

impl Default for DwarfRegs {
    fn default() -> Self {
        let mut regs = Vec::new();
        regs.resize( 64, 0 );

        DwarfRegs {
            regs,
            regs_mask: 0,
            regs_list: Vec::with_capacity( 64 )
        }
    }
}

impl DwarfRegs {
    pub fn new() -> Self { Default::default() }
}

impl Registers for DwarfRegs {
    #[inline]
    fn get( &self, register: u16 ) -> Option< u64 > {
        if !self.contains( register ) {
            None
        } else {
            Some( self.regs[ register as usize ] )
        }
    }

    #[inline]
    fn contains( &self, register: u16 ) -> bool {
        self.regs_mask & (1_u64 << (register as u32)) != 0 && (register as usize) < self.regs.len()
    }

    #[inline]
    fn append( &mut self, register: u16, value: u64 ) {
        self.regs_mask |= 1_u64 << (register as u32);
        self.regs[ register as usize ] = value;
        self.regs_list.push( register );
    }

    #[inline]
    fn iter< 'a >( &'a self ) -> RegsIter< 'a > {
        RegsIter::new( &self.regs_list, &self.regs, 0xFFFFFFFFFFFFFFFF )
    }

    #[inline]
    fn clear( &mut self ) {
        self.regs_mask = 0;
        self.regs_list.clear();
    }
}
