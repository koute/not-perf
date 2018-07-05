use std::marker::PhantomData;
use arch::{Architecture, UnwindStatus};
use address_space::MemoryReader;

pub struct UnwindContext< A: Architecture > {
    nth_frame: usize,
    initial_address: Option< u64 >,
    address: u64,
    regs_1: A::Regs,
    regs_2: A::Regs,
    state: A::State,
    is_done: bool,
    panic_on_partial_backtrace: bool,

    phantom: PhantomData< A >
}

pub struct UnwindHandle< 'a, A: Architecture + 'a > {
    ctx: &'a mut UnwindContext< A >
}

impl< A: Architecture > UnwindContext< A > {
    pub fn new() -> Self {
        UnwindContext {
            nth_frame: 0,
            initial_address: None,
            address: 0,
            regs_1: Default::default(),
            regs_2: Default::default(),
            state: A::initial_state(),
            panic_on_partial_backtrace: false,
            is_done: true,
            phantom: PhantomData
        }
    }

    pub fn set_panic_on_partial_backtrace( &mut self, value: bool ) {
        self.panic_on_partial_backtrace = value;
    }

    pub fn start< 'a, M: MemoryReader< A >, F: FnOnce( &mut A::Regs ) >( &'a mut self, memory: &M, initialize_regs: F ) -> UnwindHandle< 'a, A > {
        self.is_done = false;
        self.nth_frame = 0;
        initialize_regs( &mut self.regs_1 );
        self.regs_2 = self.regs_1.clone();

        self.address = A::get_instruction_pointer( &self.regs_1 ).unwrap();
        debug!( "Starting unwinding at: 0x{:016X}", self.address );

        let result = A::unwind( 0, memory, &mut self.state, &mut self.regs_1, &mut self.regs_2, &mut self.initial_address );
        match result {
            None => {
                if self.panic_on_partial_backtrace {
                    panic!( "Partial backtrace!" );
                }

                self.is_done = true;
            },
            Some( UnwindStatus::Finished ) => self.is_done = true,
            Some( UnwindStatus::InProgress ) => {}
        };

        UnwindHandle {
            ctx: self
        }
    }
}

impl< 'a, A: Architecture > UnwindHandle< 'a, A > {
    pub fn unwind< M: MemoryReader< A > >( &mut self, memory: &M ) -> bool {
        if self.ctx.is_done {
            return false;
        }

        self.ctx.nth_frame += 1;
        self.ctx.initial_address = None;
        let (regs, next_regs) = if self.ctx.nth_frame & 1 == 0 {
            (&mut self.ctx.regs_1, &mut self.ctx.regs_2)
        } else {
            (&mut self.ctx.regs_2, &mut self.ctx.regs_1)
        };

        self.ctx.address = A::get_instruction_pointer( regs ).unwrap();
        debug!( "Unwinding #{} -> #{} at: 0x{:016X}", self.ctx.nth_frame - 1, self.ctx.nth_frame, A::get_instruction_pointer( &regs ).unwrap() );

        self.ctx.initial_address = None;
        let result = A::unwind( self.ctx.nth_frame, memory, &mut self.ctx.state, regs, next_regs, &mut self.ctx.initial_address );
        match result {
            None => {
                if self.ctx.panic_on_partial_backtrace {
                    panic!( "Partial backtrace!" );
                }

                self.ctx.is_done = true;
            },
            Some( UnwindStatus::Finished ) => self.ctx.is_done = true,
            Some( UnwindStatus::InProgress ) => {
                debug!( "Current address on frame #{}: 0x{:016X}", self.ctx.nth_frame, self.ctx.address );
            }
        };

        true
    }

    #[inline]
    pub fn current_initial_address( &mut self ) -> Option< u64 > {
        self.ctx.initial_address
    }

    #[inline]
    pub fn current_address( &self ) -> u64 {
        self.ctx.address
    }
}
