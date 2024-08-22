use digest::Digest;
use crate::crc32_utils::Crc32;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use blake2::{Blake2b512, Blake2s256};
use blake3::Hasher as Blake3;

use strum::VariantArray;
use strum_macros::{IntoStaticStr, EnumString, VariantArray, FromRepr};

use std::convert::TryFrom;

use std::fmt;

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
#[derive(IntoStaticStr, EnumString, VariantArray, FromRepr, strum_macros::Display)]
#[allow(non_camel_case_types)]
#[repr(u8)]
/*
    * Encoding choices:
    * - val & 0x80 = 0x80 if cryptographic, 0 otherwise
    * - val & 0x40 = 0x40 if recommended for use, 0 otherwise
    * - val & 0x20 bit reserved as a future bitflag
    * - val & 0x1f is counter to distinguish individual hashes
    */
// Stability: do not change these values once committed
pub enum HashFunctions {
    crc32 = 0x40,
    // For sha2 family: set bit 0x04 to indicate sha512 base
    sha224 = 0xc0,
    sha256 = 0xc1,
    sha384 = 0xc4,
    sha512 = 0xc5,
    #[strum(to_string = "sha512_224", serialize = "sha512trunc224")]
    sha512_224 = 0xc6,
    #[strum(to_string = "sha512_256", serialize = "sha512trunc256")]
    sha512_256 = 0xc7,
    sha3_224 = 0xc8,
    sha3_256 = 0xc9,
    sha3_384 = 0xca,
    sha3_512 = 0xcb,
    #[strum(to_string = "blake2b512", serialize = "blake2b")]
    blake2b_512 = 0xcc,
    #[strum(to_string = "blake2s256", serialize = "blake2s")]
    blake2s_256 = 0xcd,
    blake3 = 0xce
}
impl clap::ValueEnum for HashFunctions {
    fn value_variants<'a>() -> &'a [Self] {
        HashFunctions::VARIANTS
    }

    fn to_possible_value(&self) -> Option<clap::builder::PossibleValue> {
        // Variants with aliases need to be handled separately
        // TODO: is there a way to reuse serialize info from strum?
        Some(match self {
            Self::sha512_224 => clap::builder::PossibleValue::new("sha512_224").alias("sha512trunc224"),
            Self::sha512_256 => clap::builder::PossibleValue::new("sha512_256").alias("sha512trunc256"),
            Self::blake2b_512 => clap::builder::PossibleValue::new("blake2b512").alias("blake2b"),
            Self::blake2s_256 => clap::builder::PossibleValue::new("blake2s256").alias("blake2s"),
            others => {
                let hash_func_str: &str = others.into();
                clap::builder::PossibleValue::new(hash_func_str)
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashFunctionFromUIntErr(u8);
impl fmt::Display for HashFunctionFromUIntErr {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(fmt, "Invalid hash id {:#02x}", self.0)
    }
}
impl std::error::Error for HashFunctionFromUIntErr {}

impl HashFunctions {
    #[inline]
    pub fn hash_len(&self) -> usize {
        match self {
            HashFunctions::crc32 => Crc32::output_size(),
            HashFunctions::sha224 => Sha224::output_size(),
            HashFunctions::sha256 => Sha256::output_size(),
            HashFunctions::sha384 => Sha384::output_size(),
            HashFunctions::sha512 => Sha512::output_size(),
            HashFunctions::sha512_224 => Sha512_224::output_size(),
            HashFunctions::sha512_256 => Sha512_256::output_size(),
            HashFunctions::sha3_224 => Sha3_224::output_size(),
            HashFunctions::sha3_256 => Sha3_256::output_size(),
            HashFunctions::sha3_384 => Sha3_384::output_size(),
            HashFunctions::sha3_512 => Sha3_512::output_size(),
            HashFunctions::blake2b_512 => Blake2b512::output_size(),
            HashFunctions::blake2s_256 => Blake2s256::output_size(),
            HashFunctions::blake3 => Blake3::output_size()
        }
    }
}
// Future use for binary files (and Discriminant<T> lacks stability guarantees)
impl From<HashFunctions> for u8 {
    #[inline]
    fn from(val: HashFunctions) -> Self {
        val as u8 // Discriminants defined above
    }
}
impl TryFrom<u8> for HashFunctions {
    type Error = HashFunctionFromUIntErr;
    fn try_from(val: u8) -> Result<Self, <Self as TryFrom<u8>>::Error> {
        Self::from_repr(val).ok_or(HashFunctionFromUIntErr(val))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    // Specifically test backwards compatibility here
    // The rest are OK, assuming strum isn't broken
    #[test]
    fn hash_enum_sha512trunc_backcompat() {
        assert_eq!(HashFunctions::from_str("sha512trunc224").unwrap(),
            HashFunctions::sha512_224);
        assert_eq!(HashFunctions::from_str("sha512trunc256").unwrap(),
            HashFunctions::sha512_256);
        assert_eq!(HashFunctions::from_str("sha512_224").unwrap(),
            HashFunctions::sha512_224);
        assert_eq!(HashFunctions::from_str("sha512_256").unwrap(),
            HashFunctions::sha512_256);
    }
    #[test]
    fn hash_enum_blake2_backcompat() {
        assert_eq!(HashFunctions::from_str("blake2b").unwrap(),
            HashFunctions::blake2b_512);
        assert_eq!(HashFunctions::from_str("blake2s").unwrap(),
            HashFunctions::blake2s_256);
        assert_eq!(HashFunctions::from_str("blake2b512").unwrap(),
            HashFunctions::blake2b_512);
        assert_eq!(HashFunctions::from_str("blake2s256").unwrap(),
            HashFunctions::blake2s_256);
    }
}
