use std::collections::BTreeMap;
use std::io::{self, Read};
use std::fs::{self, File};
use std::os::unix::io::RawFd;
use std::ops::{Deref, DerefMut};
use std::cell::Cell;
use std::vec;
use std::mem;

use num_cpus;
use libc;

use proc_maps;

use crate::utils::read_string_lossy;
use crate::perf_arch;
use perf_event_open::{Perf, Event, CommEvent, Mmap2Event, EventSource};

pub struct EventRef {
    pid: u32,
    cpu: u32,
    inner: perf_event_open::EventRef
}

impl EventRef {
    pub fn cpu( &self ) -> u32 {
        self.cpu
    }

    pub fn pid( &self ) -> u32 {
        self.pid
    }
}

impl Deref for EventRef {
    type Target = perf_event_open::EventRef;

    fn deref( &self ) -> &Self::Target {
        &self.inner
    }
}

struct StoppedProcess( u32 );

impl StoppedProcess {
    fn new( pid: u32 ) -> Result< Self, io::Error > {
        debug!( "Stopping process with PID {}...", pid );
        let ok = unsafe { libc::kill( pid as _, libc::SIGSTOP ) };
        if ok < 0 {
            return Err( io::Error::last_os_error() );
        }

        Ok( StoppedProcess( pid ) )
    }
}

impl Drop for StoppedProcess {
    fn drop( &mut self ) {
        debug!( "Resuming process with PID {}...", self.0 );
        unsafe {
            libc::kill( self.0 as _, libc::SIGCONT );
        }
    }
}

struct Member {
    pid: u32,
    cpu: u32,
    perf: Perf,
    is_closed: Cell< bool >
}

impl Member {
    fn new( pid: u32, cpu: u32, perf: Perf ) -> Self {
        Member {
            pid,
            cpu,
            perf,
            is_closed: Cell::new( false )
        }
    }
}

impl Deref for Member {
    type Target = Perf;
    fn deref( &self ) -> &Self::Target {
        &self.perf
    }
}

impl DerefMut for Member {
    fn deref_mut( &mut self ) -> &mut Self::Target {
        &mut self.perf
    }
}

pub struct PerfGroup {
    event_buffer: Vec< EventRef >,
    members: BTreeMap< RawFd, Member >,
    poll_fds: Vec< libc::pollfd >,
    frequency: u32,
    stack_size: u32,
    event_source: EventSource,
    initial_events: Vec< Event< 'static > >,
    stopped_processes: Vec< StoppedProcess >,
    stop_processes: bool,
}

fn poll_events< 'a, I >( poll_fds: &mut Vec< libc::pollfd >, iter: I ) where I: IntoIterator< Item = &'a Member >, <I as IntoIterator>::IntoIter: Clone {
    let iter = iter.into_iter();

    poll_fds.clear();
    poll_fds.extend( iter.clone().map( |member| {
        libc::pollfd {
            fd: member.fd(),
            events: libc::POLLIN | libc::POLLHUP,
            revents: 0
        }
    }));

    let ok = unsafe { libc::poll( poll_fds.as_ptr() as *mut _, poll_fds.len() as _, 1000 ) };
    if ok == -1 {
        let err = io::Error::last_os_error();
        if err.kind() != io::ErrorKind::Interrupted {
            panic!( "poll failed: {}", err );
        }
    }

    for (member, poll_fd) in iter.zip( poll_fds.iter() ) {
        member.is_closed.set( poll_fd.revents & libc::POLLHUP != 0 );
    }
}

fn get_threads( pid: u32 ) -> Result< Vec< (u32, Option< Vec< u8 > >) >, io::Error > {
    let mut output = Vec::new();
    for entry in fs::read_dir( format!( "/proc/{}/task", pid ) )? {
        if let Ok( entry ) = entry {
            let tid: u32 = entry.file_name().to_string_lossy().parse().unwrap();
            if tid == pid {
                continue;
            }

            let mut name = None;
            let comm_path = format!( "/proc/{}/task/{}/comm", pid, tid );
            if let Ok( mut fp ) = File::open( &comm_path ) {
                let mut buffer = Vec::new();
                if let Ok( _ ) = fp.read_to_end( &mut buffer ) {
                    let length = buffer.iter().position( |&byte| byte == 0 ).unwrap_or( buffer.len() );
                    buffer.truncate( length );

                    if !buffer.is_empty() && buffer[ buffer.len() - 1 ] == b'\n' {
                        buffer.truncate( length - 1 );
                    }

                    name = Some( buffer );
                }
            }

            output.push( (tid, name) );
        }
    }

    Ok( output )
}

impl PerfGroup {
    pub fn new( frequency: u32, stack_size: u32, event_source: EventSource, stop_processes: bool ) -> Self {
        let group = PerfGroup {
            event_buffer: Vec::new(),
            members: Default::default(),
            poll_fds: Vec::new(),
            frequency,
            stack_size,
            event_source,
            initial_events: Vec::new(),
            stopped_processes: Vec::new(),
            stop_processes: stop_processes
        };

        group
    }

    pub fn open( pid: u32, frequency: u32, stack_size: u32, event_source: EventSource, stop_processes: bool ) -> Result< Self, io::Error > {
        let mut group = PerfGroup::new( frequency, stack_size, event_source, stop_processes );
        group.open_process( pid )?;
        Ok( group )
    }

    pub fn open_process( &mut self, pid: u32 ) -> Result< (), io::Error > {
        if self.stop_processes {
            self.stopped_processes.push( StoppedProcess::new( pid )? );
        }

        let mut perf_events = Vec::new();
        let threads = get_threads( pid )?;

        for cpu in 0..num_cpus::get() as u32 {
            let perf = Perf::build()
                .pid( pid )
                .only_cpu( cpu as _ )
                .frequency( self.frequency as u64 )
                .sample_user_stack( self.stack_size )
                .sample_user_regs( perf_arch::native::REG_MASK )
                .sample_kernel()
                .gather_context_switches()
                .event_source( self.event_source )
                .inherit_to_children()
                .start_disabled()
                .open()?;

            perf_events.push( (cpu, perf) );

            for &(tid, _) in &threads {
                let perf = Perf::build()
                    .pid( tid )
                    .only_cpu( cpu as _ )
                    .frequency( self.frequency as u64 )
                    .sample_user_stack( self.stack_size )
                    .sample_user_regs( perf_arch::native::REG_MASK )
                    .sample_kernel()
                    .gather_context_switches()
                    .event_source( self.event_source )
                    .inherit_to_children()
                    .start_disabled()
                    .open()?;

                perf_events.push( (cpu, perf) );
            }
        }

        for (cpu, perf) in perf_events {
            self.members.insert( perf.fd(), Member::new( pid, cpu, perf ) );
        }

        let maps = read_string_lossy( &format!( "/proc/{}/maps", pid ) )?;
        let maps = proc_maps::parse( &maps );

        for (tid, name) in threads {
            self.initial_events.push( Event::Comm( CommEvent {
                pid,
                tid,
                name: name.unwrap_or( Vec::new() )
            }));
        }

        for region in maps {
            let mut protection = 0;
            if region.is_read {
                protection |= libc::PROT_READ;
            }
            if region.is_write {
                protection |= libc::PROT_WRITE;
            }
            if region.is_executable {
                protection |= libc::PROT_EXEC;
            }

            let mut flags = 0;
            if region.is_shared {
                flags |= libc::MAP_SHARED;
            } else {
                flags |= libc::MAP_PRIVATE;
            }

            self.initial_events.push( Event::Mmap2( Mmap2Event {
                pid,
                tid: pid,
                address: region.start,
                length: region.end - region.start,
                page_offset: region.file_offset,
                major: region.major,
                minor: region.minor,
                inode: region.inode,
                inode_generation: 0,
                protection: protection as _,
                flags: flags as _,
                filename: region.name.into()
            }));
        }

        Ok(())
    }

    pub fn take_initial_events( &mut self ) -> Vec< Event< 'static > > {
        let mut events = Vec::new();
        mem::swap( &mut events, &mut self.initial_events );
        events
    }

    pub fn is_empty( &self ) -> bool {
        self.members.is_empty()
    }

    pub fn enable( &mut self ) {
        for perf in self.members.values_mut() {
            perf.enable();
        }

        self.stopped_processes.clear();
    }

    pub fn wait( &mut self ) {
        for member in self.members.values() {
            if member.are_events_pending() {
                return;
            }
        }

        poll_events( &mut self.poll_fds, self.members.values() );
    }

    pub fn iter( &mut self ) -> vec::Drain< EventRef > {
        self.event_buffer.clear();

        let mut fds_to_remove = Vec::new();
        for member in self.members.values_mut() {
            let perf = &mut member.perf;
            if !perf.are_events_pending() {
                if member.is_closed.get() {
                    fds_to_remove.push( perf.fd() );
                    continue;
                }

                continue;
            }

            let pid = member.pid;
            let cpu = member.cpu;
            self.event_buffer.extend( perf.iter().map( |event| {
                EventRef {
                    inner: event,
                    pid,
                    cpu
                }
            }));
        }

        for fd in fds_to_remove {
            self.members.remove( &fd );
        }

        self.event_buffer.drain( .. )
    }
}
