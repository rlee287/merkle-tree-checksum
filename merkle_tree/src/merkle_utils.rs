use generic_array::{GenericArray, ArrayLength};
use std::fmt::{self, Write};

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

pub(crate) fn arr_to_hex_str<N>(arr: &GenericArray<u8, N>) -> String
where
    N: ArrayLength<u8>
{
    let mut return_str: String = "".to_string();
    for byte_val in arr {
        write!(return_str, "{:02x}", byte_val).unwrap();
    }
    return return_str;
}


#[derive(Debug,Copy,Clone)]
pub(crate) struct BlockRange {
    pub start: u64,
    pub end: u64
}
impl BlockRange {
    pub fn new(start: u64, end: u64) -> BlockRange {
        BlockRange {start: start, end: end}
    }
    pub fn range(&self) -> u64 {
        match self.start <= self.end {
            true  => self.end - self.start,
            false => self.start - self.end
        }
    }
}

impl fmt::Display for BlockRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}, {})", self.start, self.end)
    }
}