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

use nwind::maps;

use utils::read_string_lossy;
use perf::{Perf, EventRef, Event, CommEvent, Mmap2Event, EventSource};

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
    perf: Perf,
    is_closed: Cell< bool >
}

impl Member {
    fn new( perf: Perf ) -> Self {
        Member {
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
    frequency: u64,
    stack_size: u32,
    event_source: EventSource,
    initial_events: Vec< Event< 'static > >,
    stopped_processes: Vec< StoppedProcess >
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
    pub fn new( frequency: u64, stack_size: u32, event_source: EventSource ) -> Self {
        let group = PerfGroup {
            event_buffer: Vec::new(),
            members: Default::default(),
            poll_fds: Vec::new(),
            frequency,
            stack_size,
            event_source,
            initial_events: Vec::new(),
            stopped_processes: Vec::new()
        };

        group
    }

    pub fn open( pid: u32, frequency: u64, stack_size: u32, event_source: EventSource ) -> Result< Self, io::Error > {
        let mut group = PerfGroup::new( frequency, stack_size, event_source );
        group.open_process( pid )?;
        Ok( group )
    }

    pub fn open_process( &mut self, pid: u32 ) -> Result< (), io::Error > {
        self.stopped_processes.push( StoppedProcess::new( pid )? );
        let mut perf_events = Vec::new();
        let threads = get_threads( pid )?;

        for cpu in 0..num_cpus::get() {
            let perf = Perf::open( pid, cpu as _, self.frequency, self.stack_size, self.event_source )?;
            perf_events.push( perf );

            for &(tid, _) in &threads {
                let perf = Perf::open( tid, cpu as _, self.frequency, self.stack_size, self.event_source )?;
                perf_events.push( perf );
            }
        }

        for perf in perf_events {
            self.members.insert( perf.fd(), Member::new( perf ) );
        }

        let maps = read_string_lossy( &format!( "/proc/{}/maps", pid ) )?;
        let maps = maps::parse( &maps );

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
        for perf in self.members.values_mut() {
            if !perf.are_events_pending() {
                if perf.is_closed.get() {
                    fds_to_remove.push( perf.fd() );
                    continue;
                }

                continue;
            }

            self.event_buffer.extend( perf.iter() );
        }

        for fd in fds_to_remove {
            self.members.remove( &fd );
        }

        self.event_buffer.drain( .. )
    }
}
