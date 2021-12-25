// Update of https://github.com/ajungren/crc32_digest to work with digest v0.9
#![forbid(unsafe_code)]

use crc32fast::Hasher as Crc32Hasher;
use digest::{FixedOutput, OutputSizeUser, Update, Reset, HashMarker};
use generic_array::typenum::U4;
use generic_array::GenericArray;

pub use digest::Digest;

#[derive(Clone, Default)]
/// Wraps a [`Hasher`] and provides it with [`Digest`] and [`DynDigest`] implementations.
///
/// [`Digest`]: ../digest/trait.Digest.html
/// [`DynDigest`]: ../digest/trait.DynDigest.html
/// [`Hasher`]: ../crc32fast/struct.Hasher.html
pub struct Crc32(Crc32Hasher);

/*impl Crc32 {
    /// Creates a new `Crc32`.
    #[inline]
    pub fn new() -> Self {
        Self(Hasher::new())
    }

    /// Creates a new `Crc32` initialized with the given state.
    #[inline]
    pub fn from_state(state: u32) -> Self {
        Self(Hasher::new_with_initial(state))
    }
}*/
impl OutputSizeUser for Crc32 {
    type OutputSize = U4;
}
impl HashMarker for Crc32 {}

impl FixedOutput for Crc32 {
    #[inline]
    fn finalize_into(self, out: &mut GenericArray<u8, Self::OutputSize>) {
        let result = self.0.finalize();
        out.copy_from_slice(&result.to_be_bytes());
    }
}

impl Update for Crc32 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

impl Reset for Crc32 {
    #[inline]
    fn reset(&mut self) {
        self.0.reset();
    }
}

//impl_write!(Crc32);