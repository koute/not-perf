#[derive(Clone)]
pub struct DwarfRegs {
    regs: Vec< u64 >,
    regs_mask: u64,
    regs_list: Vec< u16 >
}

impl DwarfRegs {
    #[inline]
    pub fn new() -> DwarfRegs {
        let mut regs = Vec::new();
        regs.resize( 64, 0 );

        DwarfRegs {
            regs,
            regs_mask: 0,
            regs_list: Vec::with_capacity( 64 )
        }
    }

    #[inline]
    pub fn get( &self, register: u16 ) -> Option< u64 > {
        if self.regs_mask & (1_u64 << (register as u32)) == 0 || register as usize >= self.regs.len() {
            None
        } else {
            Some( self.regs[ register as usize ] )
        }
    }

    #[inline]
    pub fn append( &mut self, register: u16, value: u64 ) {
        self.regs_mask |= 1_u64 << (register as u32);
        self.regs[ register as usize ] = value;
        self.regs_list.push( register );
    }

    #[inline]
    pub fn iter< 'a >( &'a self ) -> impl Iterator< Item = (u16, u64) > + 'a {
        self.regs_list.iter().map( move |&register| (register as u16, self.regs[ register as usize ]) )
    }

    #[inline]
    pub fn clear( &mut self ) {
        self.regs_mask = 0;
        self.regs_list.clear();
    }
}
