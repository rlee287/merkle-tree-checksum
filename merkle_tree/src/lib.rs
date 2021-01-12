#![forbid(unsafe_code)]

mod merkle_utils;

use std::io::prelude::*;
use std::io::BufReader;
use std::fs::File;
use std::cmp::max;
use std::convert::TryInto;
use digest::Digest;
use generic_array::{GenericArray};
use merkle_utils::*;
pub use merkle_utils::{node_count, Incrementable};

pub fn merkle_hash_file<T>(file: File, block_size: u32, branch: u16,
        write_out: &mut dyn Write, progress_tracker: &mut dyn Incrementable)
         -> GenericArray<u8, T::OutputSize>
where
    T: Digest
{
    // TODO: error handling
    type HashResult<T> = GenericArray<u8, <T as Digest>::OutputSize>;
    let file_len = file.metadata().unwrap().len();
    let block_count = max(1, ceil_div(file_len, block_size.into()));
    let effective_block_count = exp_ceil_log(block_count, branch);

    let mut file_buf = BufReader::with_capacity(
        (block_size*(branch as u32)).try_into().unwrap(), file);
    let mut hash_out = HashResult::<T>::default();
    let block_range = BlockRange::new(0, effective_block_count);
    merkle_tree_file_helper::<T>(&mut file_buf, block_size, block_count,
        block_range, branch, &mut hash_out, write_out, progress_tracker);
    return hash_out;
}

// TODO: static checking with https://github.com/project-oak/rust-verification-tools
// Block range includes the first and excludes the last
fn merkle_tree_file_helper<T>(file: &mut BufReader<File>,
        block_size: u32, block_count: u64, block_range: BlockRange,
        branch: u16,
        hash_out: &mut GenericArray<u8, T::OutputSize>,
        write_out: &mut dyn Write, progress_tracker: &mut dyn Incrementable)
where
    T: Digest
{
    type HashResult<T> = GenericArray<u8, <T as Digest>::OutputSize>;
    assert!(block_range.start < block_range.end);
    // Guaranteed by type specification
    //assert!(hash_out.len() == <T as Digest>::output_size());

    if block_range.start < block_count {
        let block_interval = block_range.range();
        let hash_result = match block_interval {
            1 => {
                let mut file_vec: Vec::<u8> = Vec::new();

                // First resize to block-size to read in a full block...
                file_vec.resize(block_size.try_into().unwrap(), 0);
                let current_pos = current_seek_pos(file);
                assert!(current_pos == block_range.start*(block_size as u64));
                let bytes_read = file.read(file_vec.as_mut_slice()).unwrap();
                // ...then shrink the vector to the number of bytes read, if needed
                if bytes_read < block_size.try_into().unwrap() {
                    // Default is irrelevant as we're shrinking
                    file_vec.resize(bytes_read, 0);
                    // Ensure that reading less than requested only occurs when EOF
                    assert!(block_range.start == block_count-1);
                }
                // Prepend 0x00
                file_vec.insert(0, 0x00);
                T::digest(file_vec.as_slice())
            }
            _ => {
                // power-of-branch check
                assert!(block_interval % (branch as u64) == 0);
                let block_increment = block_interval / (branch as u64);
                let mut hash_vector: Vec::<HashResult<T>> = Vec::new();
                hash_vector.resize(branch.into(), HashResult::<T>::default());
                // Compute the hash for each branch
                for incr_count in 0..(branch as u64) {
                    let incr_index: usize = incr_count.try_into().unwrap();
                    let slice_start = block_range.start + incr_count * block_increment;
                    let slice_end = block_range.start + (incr_count + 1) * block_increment;
                    let slice_range = BlockRange::new(slice_start, slice_end);
                    merkle_tree_file_helper::<T>(file, block_size, block_count, slice_range, branch, &mut hash_vector[incr_index], write_out, progress_tracker);
                }
                let mut combined_input = hash_vector.concat();
                // Prepend 0x01
                combined_input.insert(0, 0x01);
                T::digest(combined_input.as_slice())
            }
        };
        // Byte range start is always theoretical
        // Byte range end may differ due to EOF
        let start_byte = block_range.start*(block_size as u64);
        let end_byte_block = block_range.end*(block_size as u64)-1;
        let end_byte_file = match current_seek_pos(file) {
            0 => 0,
            val => val - 1
        };
        progress_tracker.incr();
        // [{tree_block_start}-{tree_block_end}] [{file_block_start}-{file_block_end}] {hash}
        writeln!(write_out,"[0x{:08x}-0x{:08x}] [0x{:08x}-0x{:08x}] {}",
            start_byte, end_byte_block, start_byte, end_byte_file,
            arr_to_hex_str(&hash_result)).unwrap();
        hash_out.copy_from_slice(hash_result.as_slice());
    }
}