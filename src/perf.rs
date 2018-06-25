use std::mem;
use std::io;
use std::os::unix::io::RawFd;
use std::ptr;
use std::sync::atomic::fence;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::fmt;
use std::slice;
use std::ops::Range;
use std::cmp::max;
use std::cell::Cell;

use libc::{self, pid_t, c_void};
use byteorder::{ReadBytesExt, NativeEndian};
use parking_lot::Mutex;

use perf_arch;
use perf_sys::*;
use utils::{HexValue, HexSlice};
use raw_data::RawData;

#[derive(Debug)]
#[repr(C)]
struct PerfEventHeader {
    kind: u32,
    misc: u16,
    size: u16
}

#[derive(Clone, Debug)]
enum SliceLocation {
    Single( Range< usize > ),
    Split( Range< usize >, Range< usize > )
}

impl SliceLocation {
    #[inline]
    fn get< 'a >( &self, buffer: &'a [u8] ) -> RawData< 'a > {
        match *self {
            SliceLocation::Single( ref range ) => RawData::Single( &buffer[ range.clone() ] ),
            SliceLocation::Split( ref left, ref right ) => RawData::Split( &buffer[ left.clone() ], &buffer[ right.clone() ] )
        }
    }
}

#[derive(Clone, Debug)]
struct RawEventLocation {
    kind: u32,
    misc: u16,
    data_location: SliceLocation
}

pub struct RawEvent< 'a > {
    pub kind: u32,
    pub misc: u16,
    pub data: RawData< 'a >
}

impl RawEventLocation {
    #[inline]
    fn get< 'a >( &self, buffer: &'a [u8] ) -> RawEvent< 'a > {
        RawEvent {
            kind: self.kind,
            misc: self.misc,
            data: self.data_location.get( buffer )
        }
    }
}

pub struct SampleEvent< 'a > {
    pub timestamp: u64,
    pub pid: u32,
    pub tid: u32,
    pub cpu: u32,
    pub period: u64,
    pub regs: Option< perf_arch::native::Regs >,
    pub dynamic_stack_size: u64,
    pub stack: RawData< 'a >,
    pub callchain: Vec< u64 >
}

#[derive(Debug)]
pub struct ProcessEvent {
    pub pid: u32,
    pub ppid: u32,
    pub tid: u32,
    pub ptid: u32,
    pub timestamp: u64
}

pub struct CommEvent {
    pub pid: u32,
    pub tid: u32,
    pub name: Vec< u8 >
}

pub struct Mmap2Event {
    pub pid: u32,
    pub tid: u32,
    pub address: u64,
    pub length: u64,
    pub page_offset: u64,
    pub major: u32,
    pub minor: u32,
    pub inode: u64,
    pub inode_generation: u64,
    pub protection: u32,
    pub flags: u32,
    pub filename: Vec< u8 >
}

#[derive(Debug)]
pub struct LostEvent {
    pub id: u64,
    pub count: u64
}

#[derive(Debug)]
pub enum Event< 'a > {
    Sample( SampleEvent< 'a > ),
    Comm( CommEvent ),
    Exit( ProcessEvent ),
    Fork( ProcessEvent ),
    Mmap2( Mmap2Event ),
    Lost( LostEvent ),
    Raw( RawEvent< 'a > )
}

impl< 'a > fmt::Debug for SampleEvent< 'a > {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        fmt.debug_map()
            .entry( &"timestamp", &self.timestamp )
            .entry( &"pid", &self.pid )
            .entry( &"tid", &self.tid )
            .entry( &"cpu", &self.cpu )
            .entry( &"period", &self.period )
            .entry( &"regs", &self.regs )
            .entry( &"stack", &self.stack )
            .entry( &"callchain", &HexSlice( &self.callchain ) )
            .finish()
    }
}

impl fmt::Debug for CommEvent {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        use std::str;

        let mut map = fmt.debug_map();
        map
            .entry( &"pid", &self.pid )
            .entry( &"tid", &self.tid );

        if let Ok( string ) = str::from_utf8( &self.name ) {
            map.entry( &"name", &string );
        } else {
            map.entry( &"name", &self.name );
        }

        map.finish()
    }
}

impl fmt::Debug for Mmap2Event {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        fmt.debug_map()
            .entry( &"pid", &self.pid )
            .entry( &"tid", &self.tid )
            .entry( &"address", &HexValue( self.address ) )
            .entry( &"length", &HexValue( self.length ) )
            .entry( &"page_offset", &HexValue( self.page_offset ) )
            .entry( &"major", &self.major )
            .entry( &"minor", &self.minor )
            .entry( &"inode", &self.inode )
            .entry( &"inode_generation", &self.inode_generation )
            .entry( &"protection", &HexValue( self.protection as _ ) )
            .entry( &"flags", &HexValue( self.flags as _ ) )
            .entry( &"filename", &&*String::from_utf8_lossy( &self.filename ) )
            .finish()
    }
}

impl< 'a > fmt::Debug for RawEvent< 'a > {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        fmt.debug_map()
            .entry( &"kind", &self.kind )
            .entry( &"misc", &self.misc )
            .entry( &"data.len", &self.data.len() )
            .finish()
    }
}

impl< 'a > RawEvent< 'a > {
    pub fn parse( self ) -> Event< 'a > {
        match self.kind {
            PERF_RECORD_EXIT | PERF_RECORD_FORK => {
                let raw_data = self.data.as_slice();
                let mut cur = io::Cursor::new( &raw_data );

                let pid = cur.read_u32::< NativeEndian >().unwrap();
                let ppid = cur.read_u32::< NativeEndian >().unwrap();
                let tid = cur.read_u32::< NativeEndian >().unwrap();
                let ptid = cur.read_u32::< NativeEndian >().unwrap();
                let timestamp = cur.read_u64::< NativeEndian >().unwrap();

                assert_eq!( cur.position(), self.data.len() as u64 );
                let event = ProcessEvent {
                    pid,
                    ppid,
                    tid,
                    ptid,
                    timestamp
                };

                if self.kind == PERF_RECORD_EXIT {
                    Event::Exit( event )
                } else {
                    Event::Fork( event )
                }
            },

            PERF_RECORD_SAMPLE => {
                let raw_data = self.data.as_slice();
                let mut cur = io::Cursor::new( &raw_data );

                // PERF_SAMPLE_IP
                let _ = cur.read_u64::< NativeEndian >().unwrap();

                // PERF_SAMPLE_TID
                let pid = cur.read_u32::< NativeEndian >().unwrap();
                let tid = cur.read_u32::< NativeEndian >().unwrap();

                // PERF_SAMPLE_TIME
                let timestamp = cur.read_u64::< NativeEndian >().unwrap();

                // PERF_SAMPLE_CPU
                let cpu = cur.read_u32::< NativeEndian >().unwrap();
                let _ = cur.read_u32::< NativeEndian >().unwrap(); // Reserved field; is always zero.

                // PERF_SAMPLE_PERIOD
                let period = cur.read_u64::< NativeEndian >().unwrap();

                // PERF_SAMPLE_CALLCHAIN
                let callchain_length = cur.read_u64::< NativeEndian >().unwrap();
                let mut callchain = Vec::with_capacity( callchain_length as usize );
                for _ in 0..callchain_length {
                    let addr = cur.read_u64::< NativeEndian >().unwrap();
                    callchain.push( addr );
                }

                // PERF_SAMPLE_REGS_USER
                let regs_abi = cur.read_u64::< NativeEndian >().unwrap();
                let regs = if regs_abi == 0 {
                    None
                } else {
                    let mut regs = perf_arch::native::Regs {
                        regs: unsafe { mem::uninitialized() },
                        mask: perf_arch::native::REG_MASK
                    };
                    cur.read_u64_into::< NativeEndian >( &mut regs.regs ).unwrap();
                    Some( regs )
                };

                // PERF_SAMPLE_STACK_USER
                let stack_size = cur.read_u64::< NativeEndian >().unwrap();
                let stack_end_pos = cur.position() + stack_size;
                let stack_range = cur.position() as usize..stack_end_pos as usize;
                cur.set_position( stack_end_pos );

                let dynamic_stack_size =
                    if stack_size != 0 {
                         cur.read_u64::< NativeEndian >().unwrap()
                    } else {
                        0
                    };

                assert_eq!( cur.position(), self.data.len() as u64 );
                Event::Sample( SampleEvent {
                    regs,
                    dynamic_stack_size,
                    stack: self.data.get( stack_range ),
                    callchain,
                    cpu,
                    timestamp,
                    pid,
                    tid,
                    period
                })
            },

            PERF_RECORD_COMM => {
                let raw_data = self.data.as_slice();
                let mut cur = io::Cursor::new( &raw_data );

                let pid = cur.read_u32::< NativeEndian >().unwrap();
                let tid = cur.read_u32::< NativeEndian >().unwrap();
                let name = &raw_data[ cur.position() as usize.. ];
                let name = &name[ 0..name.iter().position( |&byte| byte == 0 ).unwrap_or( name.len() ) ];

                Event::Comm( CommEvent {
                    pid,
                    tid,
                    name: name.to_owned()
                })
            },

            PERF_RECORD_MMAP2 => {
                let raw_data = self.data.as_slice();
                let mut cur = io::Cursor::new( &raw_data );

                let pid = cur.read_u32::< NativeEndian >().unwrap();
                let tid = cur.read_u32::< NativeEndian >().unwrap();
                let address = cur.read_u64::< NativeEndian >().unwrap();
                let length = cur.read_u64::< NativeEndian >().unwrap();
                let page_offset = cur.read_u64::< NativeEndian >().unwrap();
                let major = cur.read_u32::< NativeEndian >().unwrap();
                let minor = cur.read_u32::< NativeEndian >().unwrap();
                let inode = cur.read_u64::< NativeEndian >().unwrap();
                let inode_generation = cur.read_u64::< NativeEndian >().unwrap();
                let protection = cur.read_u32::< NativeEndian >().unwrap();
                let flags = cur.read_u32::< NativeEndian >().unwrap();
                let name = &raw_data[ cur.position() as usize.. ];
                let name = &name[ 0..name.iter().position( |&byte| byte == 0 ).unwrap_or( name.len() ) ];

                Event::Mmap2( Mmap2Event {
                    pid,
                    tid,
                    address,
                    length,
                    page_offset,
                    major,
                    minor,
                    inode,
                    inode_generation,
                    protection,
                    flags,
                    filename: name.to_owned()
                })
            },

            PERF_RECORD_LOST => {
                let raw_data = self.data.as_slice();
                let mut cur = io::Cursor::new( &raw_data );

                let id = cur.read_u64::< NativeEndian >().unwrap();
                let count = cur.read_u64::< NativeEndian >().unwrap();
                Event::Lost( LostEvent {
                    id,
                    count
                })
            },

            _ => Event::Raw( self )
        }
    }
}

unsafe fn read_head( pointer: *const u8 ) -> u64 {
    let page = &*(pointer as *const PerfEventMmapPage);
    let head = ptr::read_volatile( &page.data_head );
    fence( Ordering::Acquire );
    head
}

unsafe fn write_tail( pointer: *mut u8, value: u64 ) {
    let page = &mut *(pointer as *mut PerfEventMmapPage);
    fence( Ordering::AcqRel );
    ptr::write_volatile( &mut page.data_tail, value );
}

pub struct Perf {
    pid: u32,
    event_ref_state: Arc< Mutex< EventRefState > >,
    buffer: *mut u8,
    size: u64,
    fd: RawFd,
    position: Cell< u64 >
}

impl Drop for Perf {
    fn drop( &mut self ) {
        unsafe {
            libc::close( self.fd );
        }
    }
}

#[inline]
unsafe fn get_buffer< 'a >( buffer: *const u8, size: u64 ) -> &'a [u8] {
    slice::from_raw_parts( buffer.offset( 4096 ), size as usize )
}

fn next_raw_event( buffer: *const u8, size: u64, position_cell: &Cell< u64 > ) -> Option< RawEventLocation > {
    let head = unsafe { read_head( buffer ) };
    if head == position_cell.get() {
        return None;
    }

    let buffer = unsafe { get_buffer( buffer, size ) };
    let position = position_cell.get();
    let relative_position = position % size;
    let event_position = relative_position as usize;
    let event_data_position = (relative_position + mem::size_of::< PerfEventHeader >() as u64) as usize;
    let event_header = unsafe { &*(&buffer[ event_position..event_data_position ] as *const _ as *const PerfEventHeader) };
    let next_event_position = event_position + event_header.size as usize;

    let data_location = if next_event_position > size as usize {
        let first = event_data_position..buffer.len();
        let second = 0..next_event_position % size as usize;
        SliceLocation::Split( first, second )
    } else {
        SliceLocation::Single( event_data_position..next_event_position )
    };

    let raw_event_location = RawEventLocation {
        kind: event_header.kind,
        misc: event_header.misc,
        data_location
    };

    debug!( "Parsed raw event: {:?}", raw_event_location );

    let next_position = position + event_header.size as u64;
    position_cell.set( next_position );

    Some( raw_event_location )
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub enum EventSource {
    HwCpuCycles,
    HwRefCpuCycles,
    SwCpuClock,
    SwPageFaults
}

impl Perf {
    pub fn open( pid: u32, cpu: u32, frequency: u64, stack_size: u32, event_source: EventSource ) -> io::Result< Self > {
        assert_eq!( mem::size_of::< PerfEventMmapPage >(), 1088 );

        if cfg!( target_arch = "x86_64" ) {
            assert_eq!( PERF_EVENT_IOC_ENABLE, 9216 );
        } else if cfg!( target_arch = "mips64" ) {
            assert_eq!( PERF_EVENT_IOC_ENABLE, 536880128 );
        }

        let mut attr: PerfEventAttr = unsafe { mem::zeroed() };
        attr.size = mem::size_of::< PerfEventAttr >() as u32;

        match event_source {
            EventSource::HwCpuCycles => {
                attr.kind = PERF_TYPE_HARDWARE;
                attr.config = PERF_COUNT_HW_CPU_CYCLES;
            },
            EventSource::HwRefCpuCycles => {
                attr.kind = PERF_TYPE_HARDWARE;
                attr.config = PERF_COUNT_HW_REF_CPU_CYCLES;
            },
            EventSource::SwCpuClock => {
                attr.kind = PERF_TYPE_SOFTWARE;
                attr.config = PERF_COUNT_SW_CPU_CLOCK;
            },
            EventSource::SwPageFaults => {
                attr.kind = PERF_TYPE_SOFTWARE;
                attr.config = PERF_COUNT_SW_PAGE_FAULTS;
            }
        }

        attr.sample_type =
            PERF_SAMPLE_IP |
            PERF_SAMPLE_TID |
            PERF_SAMPLE_TIME |
            PERF_SAMPLE_CALLCHAIN |
            PERF_SAMPLE_CPU |
            PERF_SAMPLE_PERIOD |
            PERF_SAMPLE_REGS_USER |
            PERF_SAMPLE_STACK_USER;
        attr.sample_regs_user = perf_arch::native::REG_MASK;
        attr.sample_stack_user = stack_size;
        attr.sample_period_or_freq = frequency;

        attr.flags =
            PERF_ATTR_FLAG_DISABLED |
            PERF_ATTR_FLAG_MMAP |
            PERF_ATTR_FLAG_MMAP2 |
            PERF_ATTR_FLAG_MMAP_DATA |
            PERF_ATTR_FLAG_COMM |
            PERF_ATTR_FLAG_FREQ |
            PERF_ATTR_FLAG_EXCLUDE_CALLCHAIN_USER |
            PERF_ATTR_FLAG_INHERIT |
            PERF_ATTR_FLAG_TASK;

        let fd = sys_perf_event_open( &attr, pid as pid_t, cpu as _, -1, PERF_FLAG_FD_CLOEXEC );
        if fd < 0 {
            let err = io::Error::from_raw_os_error( -fd );
            error!( "The perf_event_open syscall failed for PID {}: {}", pid, err );
            if let Some( errcode ) = err.raw_os_error() {
                if errcode == libc::EINVAL {
                    info!( "Your profiling frequency might be too high; try lowering it" );
                }
            }

            return Err( err );
        }

        let required_space = stack_size * 8;
        let page_size = 4096;
        let n = (1..26).into_iter().find( |n| (1_u32 << n) * 4096_u32 >= required_space ).expect( "cannot find appropriate page count for given stack size" );
        let page_count: u32 = max( 1 << n, 16 );
        debug!( "Allocating {} + 1 pages for the ring buffer for PID {} on CPU {}", page_count, pid, cpu );

        let full_size = (page_size * (page_count + 1)) as usize;

        let buffer;
        unsafe {
            buffer = libc::mmap( ptr::null_mut(), full_size, libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED, fd, 0 );
            if buffer == libc::MAP_FAILED {
                libc::close( fd );
                return Err( io::Error::new( io::ErrorKind::Other, "mmap failed" ) );
            }
        }

        let buffer = buffer as *mut u8;
        let size = (page_size * page_count) as u64;
        Ok( Perf {
            pid,
            event_ref_state: Arc::new( Mutex::new( EventRefState::new( buffer, size ) ) ),
            buffer: buffer,
            size,
            fd,
            position: Cell::new( 0 )
        })
    }

    pub fn enable( &mut self ) {
        let result = unsafe {
            libc::ioctl( self.fd, PERF_EVENT_IOC_ENABLE as _ )
        };

        assert!( result != -1 );
    }

    #[allow(dead_code)]
    pub fn disable( &mut self ) {
        unsafe {
            libc::ioctl( self.fd, PERF_EVENT_IOC_DISABLE as _ );
        }
    }

    #[inline]
    pub fn are_events_pending( &self ) -> bool {
        let head = unsafe { read_head( self.buffer ) };
        head != self.position.get()
    }

    #[inline]
    pub fn fd( &self ) -> RawFd {
        self.fd
    }

    #[inline]
    pub fn iter( &mut self ) -> EventIter {
        EventIter::new( self )
    }
}

struct EventRefState {
    buffer: *mut u8,
    size: u64,
    done: u32,
    positions: [u64; 32]
}

impl EventRefState {
    fn new( buffer: *mut u8, size: u64 ) -> Self {
        EventRefState {
            buffer,
            size,
            done: !0,
            positions: [0; 32]
        }
    }
}

impl Drop for EventRefState {
    fn drop( &mut self ) {
        unsafe {
            libc::munmap( self.buffer as *mut c_void, (self.size + 4096) as _ );
        }
    }
}

#[derive(Clone)]
pub struct EventRef {
    buffer: *mut u8,
    buffer_size: usize,
    event_location: RawEventLocation,
    mask: u32,
    state: Arc< Mutex< EventRefState > >
}

impl fmt::Debug for EventRef {
    fn fmt( &self, fmt: &mut fmt::Formatter ) -> Result< (), fmt::Error > {
        fmt.debug_map()
            .entry( &"location", &self.event_location )
            .entry( &"mask", &format!( "{:032b}", self.mask ) )
            .finish()
    }
}

impl Drop for EventRef {
    #[inline]
    fn drop( &mut self ) {
        let mut state = self.state.lock();
        let last_empty_spaces = state.done.leading_zeros();
        state.done &= self.mask;
        let empty_spaces = state.done.leading_zeros();

        debug_assert!( empty_spaces >= last_empty_spaces );
        if empty_spaces != last_empty_spaces {
            let position = state.positions[ empty_spaces as usize ];
            unsafe {
                write_tail( self.buffer, position );
            }
        }
    }
}

impl EventRef {
    pub fn get< 'a >( &'a self ) -> RawEvent< 'a > {
        let buffer = unsafe {
            slice::from_raw_parts( self.buffer.offset( 4096 ), self.buffer_size )
        };

        self.event_location.get( buffer )
    }
}

pub struct EventIter< 'a > {
    perf: &'a mut Perf,
    index: usize,
    count: usize,
    locations: [RawEventLocation; 32],
    state: Arc< Mutex< EventRefState > >
}

impl< 'a > EventIter< 'a > {
    #[inline]
    fn new( perf: &'a mut Perf ) -> Self {
        let mut locations: [RawEventLocation; 32] = unsafe { mem::uninitialized() };
        let mut count = 0;

        {
            let state = Arc::get_mut( &mut perf.event_ref_state ).expect( "Perf::iter called while the previous iterator hasn't finished processing" );
            let state = state.get_mut();

            for _ in 0..31 {
                state.positions[ count ] = perf.position.get();
                let raw_event_location = match next_raw_event( perf.buffer, perf.size, &perf.position ) {
                    Some( location ) => location,
                    None => break
                };

                mem::forget( mem::replace( &mut locations[ count ], raw_event_location ) );
                count += 1;
            }

            state.positions[ count ] = perf.position.get();
            state.done = !0;
        }

        debug!( "Batched {} events for PID {}", count, perf.pid );

        let state = perf.event_ref_state.clone();
        EventIter {
            perf,
            index: 0,
            count,
            locations,
            state
        }
    }
}

impl< 'a > Iterator for EventIter< 'a > {
    type Item = EventRef;

    #[inline]
    fn next( &mut self ) -> Option< Self::Item > {
        if self.index == self.count {
            return None;
        }

        let event_location = self.locations[ self.index ].clone();
        let event = EventRef {
            buffer: self.perf.buffer,
            buffer_size: self.perf.size as usize,
            event_location,
            mask: !(1 << (31 - self.index)),
            state: self.state.clone()
        };

        self.index += 1;
        Some( event )
    }
}
