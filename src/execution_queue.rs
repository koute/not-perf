use std::io;
use std::sync::mpsc;
use std::marker::PhantomData;
use std::thread;
use std::mem;

trait Callback< T >: Send {
    fn call_fn( self: Box< Self >, value: &mut T ) -> io::Result< () >;
}

impl< T, F > Callback< T > for F where F: Send + for <'a> FnOnce( &'a mut T ) -> io::Result< () > {
    fn call_fn( self: Box< Self >, value: &mut T ) -> io::Result< () > {
        (*self)( value )
    }
}

pub struct ExecutionQueue< T: Send > {
    tx: Option< mpsc::SyncSender< Box< dyn Callback< T > > > >,
    handle: Option< thread::JoinHandle< () > >,
    phantom: PhantomData< T >
}

impl< T: Send + 'static > ExecutionQueue< T > {
    pub fn new( mut state: T ) -> Self {
        let (tx, rx) = mpsc::sync_channel( 32 );
        let handle = thread::spawn( move || {
            while let Ok( cb ) = rx.recv() {
                Callback::< T >::call_fn( cb, &mut state ).unwrap();
            }
        });

        ExecutionQueue {
            tx: Some( tx ),
            handle: Some( handle ),
            phantom: PhantomData
        }
    }

    #[inline]
    pub fn spawn< F >( &self, callback: F ) where F: Send + 'static + for <'a> FnOnce( &'a mut T ) -> io::Result< () > {
        self.tx.as_ref().unwrap().send( Box::new( callback ) ).unwrap();
    }
}

impl< T: Send > Drop for ExecutionQueue< T > {
    fn drop( &mut self ) {
        if let Some( handle ) = self.handle.take() {
            mem::drop( self.tx.take() );
            handle.join().unwrap();
        }
    }
}
