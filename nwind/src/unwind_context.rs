use std::fmt;
use std::marker::PhantomData;
use std::mem;
use arch::Architecture;
use dwarf_regs::DwarfRegs;
use utils::{HexValue, HexRange};
use address_space::{MemoryReader, BinaryHandle};

pub struct UnwindContext< A: Architecture > {
    nth_frame: usize,
    frame_a: UnwindFrame< A >,
    frame_b: UnwindFrame< A >,
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
    fn new() -> Self {
        UnwindFrame {
            initial_address: None,
            binary: None,
            regs: DwarfRegs::new(),
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

pub struct UnwindHandle< 'a, A: Architecture + 'a > {
    ctx: &'a mut UnwindContext< A >
}

impl< A: Architecture > UnwindContext< A > {
    pub fn new() -> Self {
        UnwindContext {
            nth_frame: 0,
            frame_a: UnwindFrame::new(),
            frame_b: UnwindFrame::new(),
            state: A::initial_state(),
            panic_on_partial_backtrace: false,
            is_done: true,
            phantom: PhantomData
        }
    }

    pub fn set_panic_on_partial_backtrace( &mut self, value: bool ) {
        self.panic_on_partial_backtrace = value;
    }

    pub fn start< 'a, M: MemoryReader< A > >( &'a mut self, memory: &M, regs: &mut DwarfRegs ) -> UnwindHandle< 'a, A > {
        debug!( "Starting unwinding at: 0x{:016X}", A::get_instruction_pointer( &regs ).unwrap() );

        self.is_done = false;
        self.nth_frame = 0;
        self.frame_a.clear();
        self.frame_b.clear();

        mem::swap( &mut self.frame_a.regs, regs );
        if !A::unwind( 0, memory, &mut self.state, &mut self.frame_a, &mut self.frame_b, self.panic_on_partial_backtrace ) {
            if self.panic_on_partial_backtrace {
                panic!( "Partial backtrace!" );
            }

            self.is_done = true;
        }

        UnwindHandle {
            ctx: self
        }
    }
}

impl< 'a, A: Architecture > UnwindHandle< 'a, A > {
    fn current_frame( &self ) -> &UnwindFrame< A > {
        if self.ctx.nth_frame & 1 == 0 {
            &self.ctx.frame_a
        } else {
            &self.ctx.frame_b
        }
    }

    pub fn unwind< M: MemoryReader< A > >( &mut self, memory: &M ) -> bool {
        if self.ctx.is_done {
            return false;
        }

        self.ctx.nth_frame += 1;
        let (current_frame, next_frame) = if self.ctx.nth_frame & 1 == 0 {
            (&mut self.ctx.frame_a, &mut self.ctx.frame_b)
        } else {
            (&mut self.ctx.frame_b, &mut self.ctx.frame_a)
        };

        debug!( "Unwinding #{} -> #{} at: 0x{:016X}", self.ctx.nth_frame - 1, self.ctx.nth_frame, A::get_instruction_pointer( &current_frame.regs ).unwrap() );
        next_frame.clear();

        if !A::unwind( self.ctx.nth_frame, memory, &mut self.ctx.state, current_frame, next_frame, self.ctx.panic_on_partial_backtrace ) {
            self.ctx.is_done = true;
        } else {
            debug!( "Current address on frame #{}: 0x{:016X}", self.ctx.nth_frame, A::get_instruction_pointer( &current_frame.regs ).unwrap() );
        }

        true
    }

    pub fn current_initial_address( &mut self ) -> Option< u64 > {
        self.current_frame().initial_address
    }

    pub fn current_address( &self ) -> u64 {
        A::get_instruction_pointer( &self.current_frame().regs ).unwrap()
    }
}
