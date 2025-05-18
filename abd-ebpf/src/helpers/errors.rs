use core::fmt;

#[derive(Debug)]
pub struct PtrOutOfBounds;

impl fmt::Display for PtrOutOfBounds {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Pointer out of bounds")
    }
}

impl core::error::Error for PtrOutOfBounds {}
