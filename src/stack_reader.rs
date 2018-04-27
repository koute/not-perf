use std::mem;

use archive::Endianness;
use raw_data::RawData;
use address_space::{Primitive, BufferReader};

pub struct StackReader< 'a > {
    pub stack: RawData< 'a >
}

impl< 'a > StackReader< 'a > {
    #[inline]
    fn get_value_at_offset< T: Primitive >( &self, endianness: Endianness, offset: u64 ) -> Option< T > {
        let offset = offset as usize;
        if offset + mem::size_of::< T >() >= self.stack.len() {
            None
        } else {
            // TODO: Make this more efficient; if we're on the ring buffer boundary
            //       this will currently allocate memory.
            let slice = self.stack.get( offset..offset + mem::size_of::< T >() ).as_slice();
            let value = T::read_from_slice( endianness, &slice );
            Some( value )
        }
    }
}

impl< 'a > BufferReader for StackReader< 'a > {
    #[inline]
    fn len( &self ) -> usize {
        self.stack.len()
    }

    fn get_u32_at_offset( &self, endianness: Endianness, offset: u64 ) -> Option< u32 > {
        self.get_value_at_offset::< u32 >( endianness, offset )
    }

    fn get_u64_at_offset( &self, endianness: Endianness, offset: u64 ) -> Option< u64 > {
        self.get_value_at_offset::< u64 >( endianness, offset )
    }
}
