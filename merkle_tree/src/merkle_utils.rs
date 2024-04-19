#![forbid(unsafe_code)]

use std::fmt;
use std::io::{Seek, SeekFrom};

use std::ops::{RangeBounds, Bound, RangeInclusive, Range};

use crossbeam_channel::Sender as CrossbeamSender;

#[allow(non_camel_case_types)]
pub type branch_t = u16;
#[allow(non_camel_case_types)]
pub type block_t = u32;

pub(crate) const fn exp_ceil_log(number: u64, base: u16) -> u64 {
    let base_as_u64: u64 = base as u64;
    let mut result = 1;
    while result < number {
        result *= base_as_u64;
    }
    // return
    result
}
pub const fn node_count(file_size: u64, block_size: block_t, branch: branch_t) -> u64 {
    let block_count = file_size.div_ceil(block_size as u64);
    let mut node_count = block_count;
    let mut node_at_layer_count = block_count;
    assert!(branch >= 2);
    while node_at_layer_count > 1 {
        node_at_layer_count = node_at_layer_count.div_ceil(branch as u64);
        node_count += node_at_layer_count;
    }
    match node_count {
        0 => 1,
        val => val
    }
}

pub fn seek_len(seekable: &mut dyn Seek) -> u64 {
    let old_pos = seekable.stream_position().unwrap();
    let len = seekable.seek(SeekFrom::End(0)).unwrap();
    if old_pos != len {
        seekable.seek(SeekFrom::Start(old_pos)).unwrap();
    }
    // return
    len
}

#[derive(Debug, Copy, Clone)]
pub struct BlockRange {
    start: u64,
    end: u64,
    include_end: bool
}
impl BlockRange {
    #[inline]
    pub const fn new(start: u64, end: u64, include_end: bool) -> BlockRange {
        if include_end {
            assert!(end >= start);
        } else {
            assert!(end > start);
        }
        BlockRange {start, end, include_end}
    }
    #[inline]
    pub const fn range(&self) -> u64 {
        match self.include_end {
            true => self.end-self.start+1,
            false => self.end-self.start
        }
    }
    #[inline]
    pub const fn start(&self) -> u64 {
        self.start
    }
    #[inline]
    pub const fn end(&self) -> u64 {
        self.end
    }
    #[inline]
    pub const fn include_end(&self) -> bool {
        self.include_end
    }
}

impl PartialEq for BlockRange {
    fn eq(&self, other: &Self) -> bool {
        let start_match = self.start == other.start;
        let end_match = match (self.include_end, other.include_end) {
            (true, true) => self.end == other.end,
            (true, false) => match self.end.checked_add(1) {
                Some(self_end_exclusive) => self_end_exclusive == other.end,
                None => false
            },
            (false, true) => match other.end.checked_add(1) {
                Some(other_end_exclusive) => self.end == other_end_exclusive,
                None => false
            },
            (false, false) => self.end == other.end
        };
        start_match && end_match
    }
}
impl Eq for BlockRange {}

impl std::hash::Hash for BlockRange {
    fn hash<H: std::hash::Hasher> (&self, hasher: &mut H) {
        let range_end = match self.include_end {
            true => self.end,
            false => self.end-1
        };
        let range_tuple = self.start..=range_end;
        range_tuple.hash(hasher);
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HashRange {
    block_range: BlockRange,
    byte_range: BlockRange,
    hash_result: Box<[u8]>
}
impl HashRange {
    pub fn new(block_range: BlockRange,
            byte_range: BlockRange,
            hash_result: Box<[u8]>) -> HashRange {
        HashRange {block_range,
                byte_range,
                hash_result}
    }
    #[inline]
    pub fn block_range(&self) -> BlockRange {
        self.block_range
    }
    #[inline]
    pub fn byte_range(&self) -> BlockRange {
        self.byte_range
    }
    #[inline]
    pub fn hash_result(&self) -> &[u8] {
        self.hash_result.as_ref()
    }
}

pub trait Consumer<T> {
    fn accept(&self, var: T) -> Result<(), T>;
}

impl<T> Consumer<T> for CrossbeamSender<T> {
    fn accept(&self, var: T) -> Result<(), T> {
        match self.send(var) {
            Ok(()) => Ok(()),
            Err(e) => Err(e.into_inner())
        }
    }
}
