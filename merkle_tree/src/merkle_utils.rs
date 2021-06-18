#![forbid(unsafe_code)]

use std::fmt;
use std::io::{Seek, SeekFrom};

use std::ops::{RangeBounds, Bound, RangeInclusive, Range};

use std::str::FromStr;
use regex::Regex;

use lazy_static::lazy_static;

pub(crate) const fn ceil_div(num: u64, denom: u64) -> u64 {
    let result = num / denom;
    // return
    match num % denom {
        0 => result,
        _ => result + 1
    }
}
pub(crate) const fn exp_ceil_log(number: u64, base: u16) -> u64 {
    let base_as_u64: u64 = base as u64;
    let mut result = 1;
    while result < number {
        result *= base_as_u64;
    }
    // return
    result
}
pub const fn node_count(file_size: u64, block_size: u32, branch: u16) -> Option<u64> {
    let block_count = ceil_div(file_size, block_size as u64);
    let mut node_count = block_count;
    let mut node_at_layer_count = block_count;
    if branch < 2 {
        None
    } else {
        while node_at_layer_count > 1 {
            node_at_layer_count = ceil_div(node_at_layer_count, branch as u64);
            node_count += node_at_layer_count;
        }
        match node_count {
            0 => Some(1),
            val => Some(val)
        }
    }
}

pub fn seek_len(seekable: &mut dyn Seek) -> u64 {
    let old_pos = seekable.stream_position().unwrap();
    let len = seekable.seek(SeekFrom::End(0)).unwrap();
    seekable.seek(SeekFrom::Start(old_pos)).unwrap();
    // return
    len
}

// Match to <opening [> 0x#-0x# <closing ] or )>, with # being hex digits
// Do not require a specific count for future compatibility
lazy_static! {
    static ref BLOCK_RANGE_REGEX: Regex = 
        Regex::new(r"^\[0x([[:xdigit:]]+)-0x([[:xdigit:]]+)(\]|\))$").unwrap();
}
#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash)]
pub struct BlockRange {
    pub start: u64,
    pub end: u64,
    pub include_end: bool
}
impl BlockRange {
    pub fn new(start: u64, end: u64, include_end: bool) -> BlockRange {
        BlockRange {start: start, end: end, include_end: include_end}
    }
    pub fn range(&self) -> u64 {
        let init_range = match self.start <= self.end {
            true  => self.end - self.start,
            false => self.start - self.end
        };
        match self.include_end {
            true => init_range + 1,
            false => init_range
        }
    }
}

impl From<RangeInclusive<u64>> for BlockRange {
    fn from(value: RangeInclusive<u64>) -> Self {
        let start_val: u64 = match value.start_bound() {
            Bound::Included(val) => *val,
            _ => unreachable!()
        };
        let end_val: u64 = match value.end_bound() {
            Bound::Included(val) => *val,
            _ => unreachable!()
        };
        BlockRange::new(start_val, end_val, true)
    }
}

impl From<Range<u64>> for BlockRange {
    fn from(value: Range<u64>) -> Self {
        let start_val: u64 = match value.start_bound() {
            Bound::Included(val) => *val,
            _ => unreachable!()
        };
        let end_val: u64 = match value.end_bound() {
            Bound::Excluded(val) => val-1,
            _ => unreachable!()
        };
        BlockRange::new(start_val, end_val, true)
    }
}

impl fmt::Display for BlockRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let end_char = match self.include_end {
            true => ']',
            false => ')'
        };
        // Emit [] for including end, and [) for excluding end
        write!(f, "[{:#010x}-{:#010x}{}", self.start, self.end, end_char)
    }
}
impl FromStr for BlockRange {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(captures) = BLOCK_RANGE_REGEX.captures(s) {
            assert_eq!(captures.len(), 4);
            let start_val = u64::from_str_radix(&captures[1], 16).unwrap();
            let end_val = u64::from_str_radix(&captures[2], 16).unwrap();
            let end_included = match &captures[3] {
                "]" => true,
                ")" => false,
                _ => panic!("Invalid end char")
            };
            Ok(BlockRange::new(start_val, end_val, end_included))
        } else {
            Err(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HashRange {
    pub block_range: BlockRange,
    pub byte_range: BlockRange,
    pub hash_result: Box<[u8]>
}
impl HashRange {
    pub fn new(block_range: BlockRange,
            byte_range: BlockRange,
            hash_result: Box<[u8]>) -> HashRange {
        HashRange {block_range: block_range,
                byte_range: byte_range,
                hash_result: hash_result}
    }
}

pub trait Consumer<T> {
    fn accept(&mut self, var: T) -> Result<(), T>;
}
