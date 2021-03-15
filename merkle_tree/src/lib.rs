#![forbid(unsafe_code)]

mod merkle_utils;

use std::io::prelude::*;
use std::io::BufReader;
use std::cmp::min;
use std::convert::TryInto;

use digest::Digest;
use generic_array::{GenericArray};

use merkle_utils::*;
pub use merkle_utils::{node_count, seek_len, BlockRange, HashRange, Consumer};

pub fn merkle_hash_file<F, D, C>(mut file: F, block_size: u32, branch: u16,
        hash_queue: C)
         -> Box<[u8]>
where
    F: Read + Seek,
    D: Digest,
    C: Consumer<HashRange>
{
    let file_len = seek_len(&mut file);
    let block_count = match ceil_div(file_len, block_size.into()) {
        0 => 1,
        n => n
    };
    let effective_block_count = exp_ceil_log(block_count, branch);

    let buf_size: u32 = min(block_size*(branch as u32), 16*1024*1024);
    let mut file_buf: BufReader<F> = BufReader::with_capacity(
        buf_size.try_into().unwrap(), file);
    let block_range = BlockRange::new(0, effective_block_count, false);
    let hash_out = merkle_tree_file_helper::<F, D>(&mut file_buf,
        block_size, block_count, block_range, branch, &hash_queue).unwrap();
    drop(hash_queue);
    return hash_out.0.to_vec().into_boxed_slice();
}

// TODO: static checking with https://github.com/project-oak/rust-verification-tools
// Block range includes the first and excludes the last
fn merkle_tree_file_helper<F, T>(file: &mut BufReader<F>,
        block_size: u32, block_count: u64, block_range: BlockRange,
        branch: u16,
        hash_queue: &dyn Consumer<HashRange>)
        -> Option<(GenericArray<u8, T::OutputSize>, u64)>
where
    F: Read + Seek,
    T: Digest
{
    type HashResult<T> = GenericArray<u8, <T as Digest>::OutputSize>;
    assert!(block_range.start < block_range.end);
    // Guaranteed by type specification
    //assert!(hash_out.len() == <T as Digest>::output_size());

    if block_range.start < block_count {
        let block_interval = block_range.range();
        let mut current_pos = block_range.start*(block_size as u64);
        let hash_input = match block_interval {
            1 => {
                let block_size_as_usize: usize = block_size.try_into().unwrap();
                let mut file_vec: Vec::<u8> = Vec::with_capacity(block_size_as_usize+1);

                // First resize to block-size to read in a full block...
                file_vec.resize(block_size_as_usize, 0);
                // Should be optimized out in release mode
                #[cfg(debug_assertions)]
                {
                    let current_pos_actual = current_seek_pos(file);
                    debug_assert!(current_pos_actual == current_pos);
                }
                let bytes_read = file.read(file_vec.as_mut_slice()).unwrap();
                // ...then shrink the vector to the number of bytes read, if needed
                if bytes_read < block_size.try_into().unwrap() {
                    // Default is irrelevant as we're shrinking
                    file_vec.resize(bytes_read, 0);
                    // Ensure that reading less than requested only occurs when EOF
                    debug_assert!(block_range.start == block_count-1);
                }
                current_pos += bytes_read as u64;
                // Prepend 0x00
                file_vec.insert(0, 0x00);
                file_vec
            }
            _ => {
                // power-of-branch check
                assert!(block_interval % (branch as u64) == 0);
                let block_increment = block_interval / (branch as u64);
                let mut hash_vector: Vec::<HashResult<T>> = Vec::with_capacity(branch.into());
                // Compute the hash for each branch
                for incr_count in 0..(branch as u64) {
                    let slice_start = block_range.start + incr_count * block_increment;
                    let slice_end = block_range.start + (incr_count + 1) * block_increment;
                    let slice_range = BlockRange::new(slice_start, slice_end, false);
                    let subhash_res = merkle_tree_file_helper::<F, T>(file, block_size, block_count, slice_range, branch, hash_queue);
                    if subhash_res.is_some() {
                        let subhash = subhash_res.unwrap();
                        hash_vector.push(subhash.0);
                        current_pos = subhash.1;
                    } else {
                        // None -> out of range, and so will rest
                        break;
                    }
                }
                let mut combined_input = hash_vector.concat();
                // Prepend 0x01
                combined_input.insert(0, 0x01);
                combined_input
            }
        };
        let hash_result = T::digest(hash_input.as_slice());
        // Byte range start is theoretical from tree structure
        // Byte range end may differ due to EOF
        let start_byte = block_range.start;
        let end_byte_block = block_range.end-1;
        let end_byte_file = match current_pos {
            0 => 0,
            val => val - 1
        };
        #[cfg(debug_assertions)]
        {
            let end_byte_file_actual = match current_seek_pos(file) {
                0 => 0,
                val => val - 1
            };
            debug_assert_eq!(end_byte_file_actual, end_byte_file);
        }
        let block_range = BlockRange::new(start_byte, end_byte_block, true);
        let byte_range = BlockRange::new(start_byte, end_byte_file, true);
        let block_hash_result = HashRange::new(block_range, byte_range,hash_result.to_vec().into_boxed_slice());
        hash_queue.accept(block_hash_result).unwrap();
        return Some((hash_result, current_pos));
    } else {
        return None;
    }
}