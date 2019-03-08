use arch::{Registers, RegsIter};
use std::fmt;
use crate::utils::HexValue;

#[derive(Clone)]
pub struct DwarfRegs {
    regs: Box< [u64] >,
    regs_mask: u64,
    regs_list: Box< [u16] >,
    regs_count: usize
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

        let mut regs_list = Vec::new();
        regs_list.resize( 64, 0 );

        DwarfRegs {
            regs: regs.into_boxed_slice(),
            regs_mask: 0,
            regs_list: regs_list.into_boxed_slice(),
            regs_count: 0
        }
    }
}

impl DwarfRegs {
    pub fn new() -> Self { Default::default() }
}

impl Registers for DwarfRegs {
    type RegTy = u64;

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
        let index = register as usize;
        assert!( index < self.regs.len() );

        self.regs[ index ] = value;

        let mask = 1_u64 << (register as u32);
        if self.regs_mask & mask == 0 {
            self.regs_mask |= mask;
            self.regs_list[ self.regs_count ] = register;
            self.regs_count += 1;
        }
    }

    #[inline]
    fn iter< 'a >( &'a self ) -> RegsIter< 'a, u64 > {
        RegsIter::new( &self.regs_list[ 0..self.regs_count ], &self.regs, 0xFFFFFFFFFFFFFFFF )
    }

    #[inline]
    fn clear( &mut self ) {
        self.regs_mask = 0;
        self.regs_count = 0;
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
    assert_eq!( regs.iter().count(), 1 );
    assert_eq!( regs.regs_count, 1 );

    let vec: Vec< _ > = regs.iter().collect();
    assert_eq!( vec, [(10, 1024)] );

    regs.append( 50, 2048 );
    let vec: Vec< _ > = regs.iter().collect();
    assert_eq!( vec, [(10, 1024), (50, 2048)] );

    regs.append( 10, 100 );
    assert_eq!( regs.get( 10 ), Some( 100 ) );
    assert_eq!( regs.iter().count(), 2 );
    assert_eq!( regs.regs_count, 2 );
}
