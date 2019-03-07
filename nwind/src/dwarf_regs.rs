use arch::{Registers, RegsIter};
use std::fmt;
use crate::utils::HexValue;

#[derive(Clone)]
pub struct DwarfRegs {
    regs: Vec< u64 >,
    regs_mask: u64,
    regs_list: Vec< u16 >
}

impl fmt::Debug for DwarfRegs {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> fmt::Result {
        let mut dbg = fmt.debug_struct( "DwarfRegs" );

        for (register, value) in self.iter() {
            dbg.field( &format!( "{}", register ), &HexValue( value ) );
        }

        dbg.finish()
    }
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

#[test]
fn test_dwarf_regs() {
    let mut regs = DwarfRegs::new();
    assert_eq!( regs.iter().count(), 0 );

    regs.append( 10, 1024 );
    assert_eq!( regs.contains( 10 ), true );
    assert_eq!( regs.contains( 11 ), false );
    assert_eq!( regs.get( 10 ), Some( 1024 ) );
    assert_eq!( regs.get( 11 ), None );

    let vec: Vec< _ > = regs.iter().collect();
    assert_eq!( vec, [(10, 1024)] );

    regs.append( 50, 2048 );
    let vec: Vec< _ > = regs.iter().collect();
    assert_eq!( vec, [(10, 1024), (50, 2048)] );
}
