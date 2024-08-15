// Update of https://github.com/ajungren/crc32_digest to work with newer digest
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

#[cfg(test)]
mod test {
    use super::*;

    fn assert_impls_digest<D: Digest>(_digester: &D) {}

    #[test]
    fn test_crc32_impl_digest() {
        let crc32 = Crc32::default();
        assert_impls_digest(&crc32);
    }
}