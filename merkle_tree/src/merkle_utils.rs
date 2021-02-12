#![forbid(unsafe_code)]

use std::fmt;
use std::io::{Seek, SeekFrom};

pub(crate) fn ceil_div(num: u64, denom: u64) -> u64 {
    let result = num / denom;
    // return
    match num % denom {
        0 => result,
        _ => result + 1
    }
}
pub(crate) fn exp_ceil_log(number: u64, base: u16) -> u64 {
    let base_as_u64: u64 = base.into();
    let mut result = 1;
    while result < number {
        result = result * base_as_u64;
    }
    // return
    result
}
pub fn node_count(file_size: u64, block_size: u32, branch: u16) -> u64 {
    let block_count = ceil_div(file_size, block_size as u64);
    let mut node_count = block_count;
    let mut node_at_layer_count = block_count;
    assert!(branch >= 2);
    while node_at_layer_count > 1 {
        node_at_layer_count = ceil_div(node_at_layer_count, branch as u64);
        node_count += node_at_layer_count;
    }
    match node_count {
        0 => 1,
        val => val
    }
}

pub(crate) fn current_seek_pos(seekable: &mut dyn Seek) -> u64 {
    seekable.seek(SeekFrom::Current(0)).unwrap()
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
    fn accept(&self, var: T) -> Result<(), T>;
}