#![forbid(unsafe_code)]

extern crate merkle_tree;

use std::convert::TryFrom;
use std::str::FromStr;
use std::fmt;
use crate::error_types::HeaderParsingErr;
use crate::parse_functions::size_str_to_num;

use digest::Digest;
use crate::crc32_utils::Crc32;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use blake2::{Blake2b, Blake2s};
use blake3::Hasher as Blake3;
use merkle_tree::{block_t, branch_t};

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoredAndComputed<T> {
    stored: T,
    computed: T
}
impl<T> StoredAndComputed<T> {
    pub fn new(stored: T, computed: T) -> Self {
        StoredAndComputed {stored, computed}
    }
    #[inline]
    pub fn stored(&self) -> &T {
        &self.stored
    }
    #[inline]
    pub fn computed(&self) -> &T {
        &self.computed
    }
}
impl<T: Copy> Copy for StoredAndComputed<T> {}

arg_enum!{
    #[derive(PartialEq, Eq, Debug, Clone, Copy)]
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
        sha512trunc224 = 0xc6,
        sha512trunc256 = 0xc7,
        sha3_224 = 0xc8,
        sha3_256 = 0xc9,
        sha3_384 = 0xca,
        sha3_512 = 0xcb,
        blake2b = 0xcc,
        blake2s = 0xcd,
        blake3 = 0xce
    }
}

type HashFunctionFromUIntErr = ();
impl HashFunctions {
    #[inline]
    pub fn hash_len(&self) -> usize {
        match self {
            HashFunctions::crc32 => Crc32::output_size(),
            HashFunctions::sha224 => Sha224::output_size(),
            HashFunctions::sha256 => Sha256::output_size(),
            HashFunctions::sha384 => Sha384::output_size(),
            HashFunctions::sha512 => Sha512::output_size(),
            HashFunctions::sha512trunc224 => Sha512Trunc224::output_size(),
            HashFunctions::sha512trunc256 => Sha512Trunc256::output_size(),
            HashFunctions::sha3_224 => Sha3_224::output_size(),
            HashFunctions::sha3_256 => Sha3_256::output_size(),
            HashFunctions::sha3_384 => Sha3_384::output_size(),
            HashFunctions::sha3_512 => Sha3_512::output_size(),
            HashFunctions::blake2b => Blake2b::output_size(),
            HashFunctions::blake2s => Blake2s::output_size(),
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
        match val {
            0x40 => Ok(HashFunctions::crc32),
            0xc0 => Ok(HashFunctions::sha224),
            0xc1 => Ok(HashFunctions::sha256),
            0xc4 => Ok(HashFunctions::sha384),
            0xc5 => Ok(HashFunctions::sha512),
            0xc6 => Ok(HashFunctions::sha512trunc224),
            0xc7 => Ok(HashFunctions::sha512trunc256),
            0xc8 => Ok(HashFunctions::sha3_224),
            0xc9 => Ok(HashFunctions::sha3_256),
            0xca => Ok(HashFunctions::sha3_384),
            0xcb => Ok(HashFunctions::sha3_512),
            0xcc => Ok(HashFunctions::blake2b),
            0xcd => Ok(HashFunctions::blake2s),
            0xce => Ok(HashFunctions::blake3),
            _ => Err(())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderElement {
    BlockSize,
    BranchFactor,
    HashFunction
}
type HeaderElementFromStrErr = ();
impl FromStr for HeaderElement {
    type Err = HeaderElementFromStrErr;
    fn from_str(string: &str) -> Result<Self, Self::Err> {
        match string {
            "Block size" | "block size" => Ok(Self::BlockSize),
            "Branching factor" | "branch factor" => Ok(Self::BranchFactor),
            "Hash function" | "hash function" => Ok(Self::HashFunction),
            _ => Err(())
        }
    }
}
impl fmt::Display for HeaderElement {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::BlockSize => write!(fmt, "Block size"),
            Self::BranchFactor => write!(fmt, "Branching factor"),
            Self::HashFunction => write!(fmt, "Hash function")
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TreeParams {
    pub block_size: block_t,
    pub branch_factor: branch_t,
    pub hash_function: HashFunctions
}
impl TreeParams {
    pub fn from_lines(string_arr: &[String; 3]) -> Result<TreeParams, Vec<HeaderParsingErr>> {
        let mut block_size_opt: Option<block_t> = None;
        let mut branch_factor_opt: Option<branch_t> = None;
        let mut hash_function_opt: Option<HashFunctions> = None;
        let mut errors: Vec<HeaderParsingErr> = Vec::new();
        for string_element in string_arr {
            let string_split: Vec<&str> = string_element.split(':').collect();
            if string_split.len() != 2 {
                errors.push(HeaderParsingErr::MalformedFile);
                continue;
            }
            let (key, value) = (string_split[0], string_split[1].trim());
            match HeaderElement::from_str(key) {
                Ok(HeaderElement::BlockSize) => {
                    match size_str_to_num(value) {
                        Some(0) | None => {
                            errors.push(HeaderParsingErr::BadParameterValue(
                                HeaderElement::BlockSize, value.to_owned()));
                        }
                        Some(val) => {
                            block_size_opt = Some(val);
                        }
                    }
                },
                Ok(HeaderElement::BranchFactor) => {
                    match value.parse::<branch_t>() {
                        Ok(0) | Ok(1) | Err(_) => {
                            errors.push(HeaderParsingErr::BadParameterValue(
                                HeaderElement::BranchFactor, value.to_owned()));
                        },
                        Ok(val) => {
                            branch_factor_opt = Some(val)
                        }
                    }
                },
                Ok(HeaderElement::HashFunction) => {
                    match value.parse::<HashFunctions>() {
                        Err(_) => {
                            errors.push(HeaderParsingErr::BadParameterValue(
                                HeaderElement::HashFunction, value.to_owned()));
                        },
                        Ok(val) => {
                            hash_function_opt = Some(val)
                        }
                    }
                },
                Err(_) => {
                    errors.push(
                        HeaderParsingErr::UnexpectedParameter(key.to_owned()));
                    continue;
                }
            }
        }
        if let (Some(block_size), Some(branch_factor), Some(hash_function)) = (block_size_opt, branch_factor_opt, hash_function_opt) {
            Ok(TreeParams {
                block_size,
                branch_factor,
                hash_function
            })
        } else {
            if block_size_opt.is_none() {
                errors.push(
                    HeaderParsingErr::MissingParameter(HeaderElement::BlockSize));
            }
            if branch_factor_opt.is_none() {
                errors.push(
                    HeaderParsingErr::MissingParameter(HeaderElement::BranchFactor));
            }
            if hash_function_opt.is_none() {
                errors.push(
                    HeaderParsingErr::MissingParameter(HeaderElement::HashFunction));
            }
            assert!(!errors.is_empty());
            Err(errors)
        }
    }
}
impl fmt::Display for TreeParams {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        writeln!(fmt, "Hash function: {}", self.hash_function)?;
        writeln!(fmt, "Block size: {}", self.block_size)?;
        writeln!(fmt, "Branching factor: {}", self.branch_factor)?;
        Ok(())
    }
}

pub(crate) fn str_to_files(file_str: &OsStr) -> Option<Vec<PathBuf>> {
    let mut file_list = Vec::<PathBuf>::new();
    let file_path = Path::new(&file_str);
    if file_path.is_file() {
        file_list.push(file_path.to_path_buf());
    } else if file_path.is_dir() {
        // Walk directory to find all the files in it
        for entry in WalkDir::new(file_path).min_depth(1).follow_links(true) {
            let entry_unwrap = entry.unwrap();
            let entry_path = entry_unwrap.path();
            if entry_path.is_file() {
                file_list.push(entry_path.to_path_buf());
            }
        }
    } else {
        return None;
    }
    return Some(file_list);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;
    use std::str::FromStr;

    #[test]
    fn enum_u8_roundtrip() {
        let enum_arr = HashFunctions::variants();
        for enum_variant_name in enum_arr {
            let enum_variant = HashFunctions::from_str(enum_variant_name).unwrap();
            let enum_as_u8 = u8::from(enum_variant);
            let u8_enum_roundtrip = HashFunctions::try_from(enum_as_u8);
            assert_eq!(Ok(enum_variant), u8_enum_roundtrip);
        }
    }
    #[test]
    fn enum_header_roundtrip() {
        let enum_arr = [HeaderElement::BlockSize, HeaderElement::BranchFactor, HeaderElement::HashFunction];
        for enum_variant in enum_arr {
            let enum_variant_name = format!("{}", enum_variant);
            let enum_roundtrip = HeaderElement::from_str(&enum_variant_name);
            assert_eq!(Ok(enum_variant), enum_roundtrip);
        }
    }
}