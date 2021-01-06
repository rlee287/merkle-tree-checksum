#![forbid(unsafe_code)]

mod merkle_utils;

use std::io::prelude::*;
use std::io::SeekFrom;
use std::io::BufReader;
use std::fs::File;
use std::convert::TryInto;
use digest::Digest;
use generic_array::{GenericArray};
use merkle_utils::*;

pub fn merkle_hash_file<T>(file: File, block_size: u32, branch: u16) -> GenericArray<u8, T::OutputSize>
where
    T: Digest
{
    // TODO: error handling
    type HashResult<T> = GenericArray<u8, <T as Digest>::OutputSize>;
    let file_len = file.metadata().unwrap().len();
    let block_count = ceil_div(file_len, block_size.into());
    let effective_block_count = exp_ceil_log(block_count, branch);

    let mut file_buf = BufReader::new(file);
    let mut hash_out = HashResult::<T>::default();
    let block_range = BlockRange::new(0, effective_block_count);
    merkle_tree_file_helper::<T>(&mut file_buf, block_size, block_count,
        branch, &mut hash_out, block_range);
    return hash_out;
}

// TODO: static checking with https://github.com/project-oak/rust-verification-tools
// Block range includes the first and excludes the last
fn merkle_tree_file_helper<T>(file: &mut BufReader<File>,
        block_size: u32, block_count: u64,
        branch: u16, hash_out: &mut GenericArray<u8, T::OutputSize>,
        block_range: BlockRange)
where
    T: Digest
{
    type HashResult<T> = GenericArray<u8, <T as Digest>::OutputSize>;
    assert!(block_range.start < block_range.end);
    assert!(hash_out.len() == <T as Digest>::output_size());
    println!("Hashing blocks {}", block_range);

    if block_range.start < block_count {
        let block_interval = block_range.range();
        if block_interval == 1 {
            let mut file_vec: Vec::<u8> = Vec::new();

            // First resize to block-size to read in a full block...
            file_vec.resize(block_size.try_into().unwrap(), 0);
            let current_pos = file.seek(SeekFrom::Current(0)).unwrap();
            assert!(current_pos == block_range.start*(block_size as u64));
            println!("Reading bytes {}-{}", current_pos, current_pos+(block_size as u64)-1);
            let bytes_read = file.read(file_vec.as_mut_slice()).unwrap();
            // ...then shrink the vector to the number of bytes read, if needed
            if bytes_read < block_size.try_into().unwrap() {
                // Default is irrelevant as we're shrinking
                file_vec.resize(bytes_read, 0);
                // Ensure that reading less than requested only occurs when EOF
                assert!(block_range.start == block_count-1);
            }

            let hash_result = T::digest(file_vec.as_slice());
            //println!("Block hash is {:x}", hash_result);
            print_arr("Block hash is ", &hash_result);
            
            hash_out.copy_from_slice(hash_result.as_slice());
        } else {
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
                merkle_tree_file_helper::<T>(file, block_size, block_count, branch, &mut hash_vector[incr_index], slice_range);
            }
            let combined_input = hash_vector.concat();
            let hash_result = T::digest(combined_input.as_slice());
            hash_out.copy_from_slice(hash_result.as_slice());
        }
    }
}