use std::marker::PhantomData;
use crate::arch::{Architecture, Registers, UnwindStatus};
use crate::address_space::MemoryReader;

pub struct UnwindContext< A: Architecture > {
    nth_frame: usize,
    initial_address: Option< A::RegTy >,
    ra_address: Option< A::RegTy >,
    address: A::RegTy,
    regs: A::Regs,
    state: A::State,
    is_done: bool,
    panic_on_partial_backtrace: bool,

    phantom: PhantomData< A >
}

pub struct UnwindHandle< 'a, A: Architecture + 'a > {
    ctx: &'a mut UnwindContext< A >
}

// We define this trait to be able to put the `#[inline(always)]`
// on the register fetching callback to guarantee that we won't
// produce any extra frames when unwinding locally.
pub trait InitializeRegs< A: Architecture > {
    fn initialize_regs( self, regs: &mut A::Regs );
}

impl< T, A: Architecture > InitializeRegs< A > for T where T: FnOnce( &mut A::Regs ) {
    #[inline(always)]
    fn initialize_regs( self, regs: &mut A::Regs ) {
        self( regs )
    }
}

impl< A: Architecture > UnwindContext< A > {
    pub fn new() -> Self {
        UnwindContext {
            nth_frame: 0,
            initial_address: None,
            ra_address: None,
            address: Default::default(),
            regs: Default::default(),
            state: A::initial_state(),
            panic_on_partial_backtrace: false,
            is_done: true,
            phantom: PhantomData
        }
    }

    pub(crate) fn set_panic_on_partial_backtrace( &mut self, value: bool ) {
        self.panic_on_partial_backtrace = value;
    }

    #[inline(always)]
    pub(crate) fn start< 'a, M: MemoryReader< A >, T: InitializeRegs< A > >( &'a mut self, memory: &M, initializer: T ) -> UnwindHandle< 'a, A > {
        initializer.initialize_regs( &mut self.regs );
        self.start_impl( memory )
    }

    pub(crate) fn clear_cache( &mut self ) {
        A::clear_cache( &mut self.state );
    }

    fn start_impl< 'a, M: MemoryReader< A > >( &'a mut self, memory: &M ) -> UnwindHandle< 'a, A > {
        self.is_done = false;
        self.nth_frame = 0;

        self.address = self.regs.get( A::INSTRUCTION_POINTER_REG ).unwrap();
        debug!( "Starting unwinding at: 0x{:016X}", self.address );

        let result = A::unwind( 0, memory, &mut self.state, &mut self.regs, &mut self.initial_address, &mut self.ra_address );
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

        // avoid infinite loops
        if self.ctx.nth_frame > 1000 {
            warn!("infinite loop detected and avoided");
            return false;
        }

        self.ctx.address = self.ctx.regs.get( A::INSTRUCTION_POINTER_REG ).unwrap();
        debug!( "Unwinding #{} -> #{} at: 0x{:016X}", self.ctx.nth_frame - 1, self.ctx.nth_frame, self.ctx.address );

        self.ctx.initial_address = None;
        self.ctx.ra_address = None;
        let result = A::unwind( self.ctx.nth_frame, memory, &mut self.ctx.state, &mut self.ctx.regs, &mut self.ctx.initial_address, &mut self.ctx.ra_address );
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
    pub fn current_initial_address( &mut self ) -> Option< A::RegTy > {
        self.ctx.initial_address
    }

    #[inline]
    pub fn current_address( &self ) -> A::RegTy {
        self.ctx.address
    }

    #[cfg(feature = "local-unwinding")]
    #[inline]
    pub fn next_address_location( &mut self ) -> Option< A::RegTy > {
        self.ctx.ra_address
    }

    #[cfg(feature = "local-unwinding")]
    #[inline]
    pub fn next_stack_pointer( &self ) -> A::RegTy {
        self.ctx.regs.get( A::STACK_POINTER_REG ).unwrap()
    }

    #[cfg(feature = "local-unwinding")]
    #[inline]
    pub fn replace_next_address( &mut self, value: A::RegTy ) {
        self.ctx.regs.append( A::INSTRUCTION_POINTER_REG, value )
    }
}
