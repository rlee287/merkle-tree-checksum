#![forbid(unsafe_code)]

use std::fmt;
use std::io::{Read, Seek, SeekFrom};
use std::io::Result as IOResult;
use std::io::ErrorKind;

use std::convert::TryFrom;
use hex::{FromHex, FromHexError};
use arrayvec::{ArrayVec, CapacityError};

use std::ops::{Bound, Deref, Range, RangeBounds, RangeInclusive};

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
// Functions like normal `read`, but with additional guarantees:
// - Slice is always filled when there is enough data left to read
// - When not enough data is left, slice is filled up to returned length
// - File cursor will be at its original position if an error occurs
// expected_seek_loc provides a way to pass in current location, if available
// When provided, this saves a seek operation if the given slice was full
pub(crate) fn read_exact_vec<R: Read+Seek>(
        reader: &mut R, expected_seek_loc: Option<u64>, len: usize)
        -> IOResult<Vec<u8>> {
    // stream_position Result from seek, which only fails on negative locations
    let reader_pos_old = match expected_seek_loc {
        Some(given_pos) => {
            #[cfg(debug_assertions)]
            {
                // In debug mode, verify that the given seek loc is correct
                let actual_pos = reader.stream_position().unwrap();
                assert_eq!(actual_pos, given_pos);
            }
            given_pos
        }
        None => reader.stream_position().unwrap()
    };
    let mut vec_read_buf = vec![0x00; len];
    let read_exact_result = reader.read_exact(vec_read_buf.as_mut_slice());
    match read_exact_result {
        Ok(()) => Ok(vec_read_buf),
        Err(e) => {
            if e.kind() == ErrorKind::UnexpectedEof {
                // Read as much as possible
                /*
                 * - read guarantees same-pos-on-err but read_exact doesn't,
                 *   so reset seek pos
                 * - seek only fails on negative locations
                 */
                reader.seek(SeekFrom::Start(reader_pos_old)).unwrap();

                vec_read_buf.clear();
                let read_len_res = reader.read_to_end(&mut vec_read_buf);
                match read_len_res {
                    Ok(read_len) => {
                        debug_assert!(read_len < len);
                        vec_read_buf.resize(read_len, 0x00);
                        vec_read_buf.shrink_to_fit();
                        Ok(vec_read_buf)
                    }
                    Err(e) => {
                        // read_to_end may read nonzero bytes even if error occured
                        reader.seek(SeekFrom::Start(reader_pos_old)).unwrap();
                        Err(e)
                    }
                }
            } else {
                Err(e)
            }
        }
    }
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

// Wrapper struct to create immutable container of bytes on the stack
#[derive(Debug, Default, Clone, PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct HashData<const CAP: usize> {
    arr: ArrayVec<u8, CAP>
}
impl<const CAP: usize> HashData<CAP> {
    #[inline]
    pub fn try_new(data: &[u8]) -> Result<Self, CapacityError> {
        let arr = ArrayVec::try_from(data)?;
        Ok(Self{arr})
    }
}
impl<const CAP: usize> Deref for HashData<CAP> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.arr
    }
}
impl<const CAP: usize> AsRef<[u8]> for HashData<CAP> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.arr
    }
}
impl<const CAP: usize> FromHex for HashData<CAP> {
    type Error = FromHexError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        let hex_ref = hex.as_ref();
        if hex_ref.len() > 2*CAP {
            return Err(FromHexError::InvalidStringLength);
        }
        let mut backing_array = [0x00; CAP];
        let final_len = hex_ref.len()/2;

        hex::decode_to_slice(hex_ref, &mut backing_array[..final_len])?;

        let mut arr = ArrayVec::new();
        arr.try_extend_from_slice(&backing_array[..final_len]).unwrap();

        Ok(HashData{arr})
    }
}

pub(crate) const MAX_HASH_LEN: usize = 512/8;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HashRange {
    block_range: BlockRange,
    byte_range: BlockRange,
    hash_result: HashData<MAX_HASH_LEN>
}
impl HashRange {
    pub fn new(block_range: BlockRange,
            byte_range: BlockRange,
            hash_result: HashData<MAX_HASH_LEN>) -> Self {
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

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_read_exact_full() {
        let mut read_obj = Cursor::new(b"12345678");
        let read_result = read_exact_vec(&mut read_obj, Some(0), 4);
        assert_eq!(read_result.unwrap(), Vec::from(*b"1234"));
    }
    #[test]
    fn test_read_exact_partial() {
        let mut read_obj = Cursor::new(b"abcde");
        let read_result = read_exact_vec(&mut read_obj, Some(0), 16);
        assert_eq!(read_result.unwrap(), Vec::from(*b"abcde"));
    }
}
