use std::num::NonZeroU32;
use string_interner;

pub type StringInterner = string_interner::StringInterner< StringId >;

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct StringId( NonZeroU32 );

impl string_interner::Symbol for StringId {
    #[inline]
    fn from_usize( value: usize ) -> Self {
        unsafe {
            StringId( NonZeroU32::new_unchecked( (value + 1) as u32 ) )
        }
    }

    #[inline]
    fn to_usize( self ) -> usize {
        self.0.get() as usize - 1
    }
}
