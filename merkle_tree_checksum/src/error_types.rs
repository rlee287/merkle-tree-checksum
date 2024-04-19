#![forbid(unsafe_code)]
use crate::utils::{StoredAndComputed, HeaderElement};
use merkle_tree::BlockRange;

use hex::ToHex;
use std::fmt;

#[derive(Default, Debug, Clone)]
pub struct SizeStrToNumErr {}
impl fmt::Display for SizeStrToNumErr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("Could not parse size string")
    }
}
impl std::error::Error for SizeStrToNumErr {}

// No Copy to simplify refactoring if non-copy types get added later
#[derive(PartialEq, Eq, Debug, Clone)]
pub(crate) enum PreHashError {
    FileNotFound,
    ReadPermissionError,
    MismatchedLength(StoredAndComputed<u64>)
}
impl fmt::Display for PreHashError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FileNotFound => write!(fmt, "file not found"),
            Self::MismatchedLength(s_c) => {
                write!(fmt, concat!("mismatched file length:\n",
                    "  expected: {}\n",
                    "  actual:   {}"),
                    s_c.stored(), s_c.computed())
            },
            Self::ReadPermissionError => write!(fmt, "permission denied to read")
        }
    }
}
impl std::error::Error for PreHashError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HeaderParsingErr {
    MalformedFile,
    UnexpectedParameter(String),
    MissingParameter(HeaderElement),
    BadParameterValue(HeaderElement, String),
    MalformedVersion(String),
}
impl fmt::Display for HeaderParsingErr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MalformedFile => write!(fmt,
                "Hash file is malformed: unable to parse tree parameters"),
            Self::UnexpectedParameter(p) => write!(fmt,
                "Hash file has unexpected parameter {}", p),
            Self::MissingParameter(p) => write!(fmt,
                "Hash file is missing parameter {}", p),
            Self::BadParameterValue(p, val) => write!(fmt,
                "Hash file parameter {} has invalid value {}", p, val),
            Self::MalformedVersion(vers) => write!(fmt,
                "Hash file has malformed version {}", vers)
        }
    }
}
impl std::error::Error for HeaderParsingErr {}

#[derive(PartialEq, Eq, Debug, Clone)]
pub(crate) enum VerificationError {
    MismatchedFileID, // No StoredAndComputed as this would not be helpful
    MismatchedBlockRange(StoredAndComputed<BlockRange>),
    MismatchedByteRange(StoredAndComputed<BlockRange>),
    // Range is byte range, which exists when verifying long hashes
    MismatchedHash(Option<BlockRange>, StoredAndComputed<Box<[u8]>>),
    MalformedEntry(String), // String is the malformed line
    UnexpectedEof
}
impl fmt::Display for VerificationError {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Will be printed as "Error verifying file {name}: {err}\n"
        match self {
            Self::MismatchedFileID => write!(fmt, "found entry for different file"),
            Self::MismatchedBlockRange(s_c) => {
                write!(fmt, concat!("mismatched block range in entry:\n",
                    "  stored:   {}\n",
                    "  computed: {}"),
                    s_c.stored(), s_c.computed())
            }
            Self::MismatchedByteRange(s_c) => {
                write!(fmt, concat!("mismatched byte range in entry:\n",
                    "  stored:   {}\n",
                    "  computed: {}"),
                    s_c.stored(), s_c.computed())
            }
            Self::MismatchedHash(range_option, s_c) => {
                match range_option {
                    Some(range) => writeln!(fmt,
                        "hash mismatch over byte range {}:", range),
                    None => writeln!(fmt, "hash mismatch:")
                }?;
                write!(fmt, concat!(
                    "  stored:   {}\n",
                    "  computed: {}"),
                    Vec::<u8>::encode_hex::<String>(&s_c.stored().to_vec()),
                    Vec::<u8>::encode_hex::<String>(&s_c.computed().to_vec()))
            }
            Self::MalformedEntry(line) => {
                write!(fmt, "found malformed entry {}", line)
            }
            Self::UnexpectedEof => write!(fmt, "unexpected EOF")
        }
    }
}
impl std::error::Error for VerificationError {}
