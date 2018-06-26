use std::fmt;
use std::marker::PhantomData;
use std::mem;
use arch::Architecture;
use dwarf_regs::DwarfRegs;
use utils::{HexValue, HexRange};
use address_space::{MemoryReader, BinaryHandle};

pub struct EmptyUnwindContext< A: Architecture > {
    state: A::State,
    panic_on_partial_backtrace: bool,
    regs_buffer_1: DwarfRegs,
    regs_buffer_2: DwarfRegs,
    phantom: PhantomData< A >
}

pub struct UnwindContext< A: Architecture > {
    nth_frame: usize,
    current_frame: UnwindFrame< A >,
    next_frame: UnwindFrame< A >,
    state: A::State,
    is_done: bool,
    panic_on_partial_backtrace: bool,

    phantom: PhantomData< A >
}

pub struct UnwindFrame< A: Architecture > {
    pub initial_address: Option< u64 >,
    pub binary: Option< BinaryHandle< A > >,
    pub regs: DwarfRegs,
    pub cfa: Option< u64 >
}

impl< A: Architecture > UnwindFrame< A > {
    #[inline]
    pub fn new_with_regs( regs: DwarfRegs ) -> Self {
        UnwindFrame {
            initial_address: None,
            binary: None,
            regs,
            cfa: None
        }
    }

    #[inline]
    pub fn clear( &mut self ) {
        self.initial_address = None;
        self.binary = None;
        self.regs.clear();
        self.cfa = None;
    }

    pub fn assign_binary< M: MemoryReader< A > >( &mut self, nth_frame: usize, memory: &M ) -> bool {
        if self.binary.is_some() {
            return true;
        }

        let address = A::get_instruction_pointer( &self.regs ).unwrap();
        let region = match memory.get_region_at_address( address ) {
            Some( region ) => region,
            None => {
                debug!( "Cannot find a binary corresponding to address 0x{:016X}", address );
                return false;
            }
        };

        self.binary = Some( region.binary().clone() );

        debug!(
            "Frame #{}: '{}' at 0x{:016X} (0x{:X}): {:?}",
            nth_frame,
            region.binary().name(),
            address,
            address - region.binary().base_address(),
            region.binary().lookup_absolute_symbol( address ).map( |(range, symbol)| (HexRange( range ), symbol) )
        );

        true
    }
}

impl< A: Architecture > fmt::Debug for UnwindFrame< A > {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        let mut map = fmt.debug_map();
        if let Some( cfa ) = self.cfa {
            map.entry( &"CFA", &HexValue( cfa ) );
        } else {
            map.entry( &"CFA", &"None" );
        }

        for (index, value) in self.regs.iter() {
            map.entry( &index, &HexValue( value ) );
        }

        map.finish()
    }
}

impl< A: Architecture > AsRef< DwarfRegs > for UnwindFrame< A > {
    #[inline]
    fn as_ref( &self ) -> &DwarfRegs {
        &self.regs
    }
}

impl< A: Architecture > AsMut< DwarfRegs > for UnwindFrame< A > {
    #[inline]
    fn as_mut( &mut self ) -> &mut DwarfRegs {
        &mut self.regs
    }
}

impl< A: Architecture > EmptyUnwindContext< A > {
    pub fn new() -> Self {
        EmptyUnwindContext {
            state: A::initial_state(),
            panic_on_partial_backtrace: false,
            regs_buffer_1: DwarfRegs::new(),
            regs_buffer_2: DwarfRegs::new(),
            phantom: PhantomData
        }
    }

    pub fn set_panic_on_partial_backtrace( &mut self, value: bool ) {
        self.panic_on_partial_backtrace = value;
    }

    pub fn start< M: MemoryReader< A > >( mut self, memory: &M, regs: &mut DwarfRegs ) -> UnwindContext< A > {
        debug!( "Starting unwinding at: 0x{:016X}", A::get_instruction_pointer( &regs ).unwrap() );

        mem::swap( &mut self.regs_buffer_1, regs );
        self.regs_buffer_2.clear();
        let mut ctx = UnwindContext {
            nth_frame: 0,
            current_frame: UnwindFrame::new_with_regs( self.regs_buffer_1 ),
            next_frame: UnwindFrame::new_with_regs( self.regs_buffer_2 ),
            state: self.state,
            panic_on_partial_backtrace: self.panic_on_partial_backtrace,
            is_done: false,
            phantom: PhantomData
        };

        if !A::unwind( 0, memory, &mut ctx.state, &mut ctx.current_frame, &mut ctx.next_frame, ctx.panic_on_partial_backtrace ) {
            if ctx.should_panic_on_partial_backtrace() {
                panic!( "Partial backtrace!" );
            }

            ctx.is_done = true;
        }

        ctx
    }
}

impl< A: Architecture > UnwindContext< A > {
    fn current_frame( &self ) -> &UnwindFrame< A > {
        &self.current_frame
    }

    pub fn unwind< M: MemoryReader< A > >( mut self, memory: &M ) -> Result< Self, EmptyUnwindContext< A > > {
        if self.is_done {
            return Err( self.end() );
        }

        debug!( "Unwinding #{} -> #{} at: 0x{:016X}", self.nth_frame, self.nth_frame + 1, A::get_instruction_pointer( &self.current_frame.regs ).unwrap() );

        mem::swap( &mut self.current_frame, &mut self.next_frame );
        self.next_frame.clear();
        self.nth_frame += 1;

        if !A::unwind( self.nth_frame, memory, &mut self.state, &mut self.current_frame, &mut self.next_frame, self.panic_on_partial_backtrace ) {
            self.is_done = true;
        } else {
            debug!( "Current address on frame #{}: 0x{:016X}", self.nth_frame, A::get_instruction_pointer( &self.current_frame().regs ).unwrap() );
        }

        Ok( self )
    }

    fn end( self ) -> EmptyUnwindContext< A > {
        EmptyUnwindContext {
            state: self.state,
            panic_on_partial_backtrace: self.panic_on_partial_backtrace,
            regs_buffer_1: self.current_frame.regs,
            regs_buffer_2: self.next_frame.regs,
            phantom: PhantomData
        }
    }

    pub fn current_initial_address( &mut self ) -> Option< u64 > {
        self.current_frame().initial_address
    }

    pub fn current_address( &self ) -> u64 {
        A::get_instruction_pointer( &self.current_frame().regs ).unwrap()
    }

    pub fn should_panic_on_partial_backtrace( &self ) -> bool {
        self.panic_on_partial_backtrace
    }
}
