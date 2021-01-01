#![forbid(unsafe_code)]

use std::io::prelude::*;
use std::io::SeekFrom; // temp
use std::fs::File;
use std::path::Path;
use sha2::{Sha256, Digest};
use std::convert::TryInto;
use generic_array::GenericArray;
use generic_array::typenum::U32;

pub type HashResult = GenericArray<u8, U32>;

fn ceil_div(num: u64, denom: u64) -> u64 {
    let result = num / denom;
    match num % denom {
        0 => result,
        _ => result + 1
    }
}

fn exp_ceil_log(number: u64, base: u16) -> u64 {
    let base_as_u64: u64 = base.into();
    let mut result = 1;
    while result < number {
        result = result * base_as_u64;
    }
    // return
    result
}
pub fn merkle_hash_file(path: &Path, block_size: u32, branch: u16) -> HashResult{
    // TODO: error handling
    let mut file: File = File::open(path).unwrap();
    let file_len = file.metadata().unwrap().len();
    println!("File is {} bytes long",file_len);
    let block_count = ceil_div(file_len, block_size.into());
    let effective_block_count = exp_ceil_log(block_count, branch);
    let mut hash_out: HashResult = HashResult::default();
    merkle_tree_file_helper(&mut file, block_size, block_count,
        branch, &mut hash_out, 0, effective_block_count);
    // return
    hash_out
}

// TODO: static checking with https://github.com/project-oak/rust-verification-tools
// Include the first and exclude the last
fn merkle_tree_file_helper(file: &mut File,
        block_size: u32, block_count: u64,
        branch: u16, hash_out: &mut HashResult,
        start_block: u64, end_block: u64) {
    assert!(end_block > start_block);
    assert!(hash_out.len() == sha2::Sha256::output_size());
    println!("Hashing blocks [{}:{})", start_block, end_block);

    if start_block < block_count {
        println!("Start is {}, block_count is {}", start_block, block_count);
        let block_interval = end_block - start_block;
        if block_interval == 1 {
            let mut file_vec: Vec::<u8> = Vec::new();

            // First resize to block-size to read in a full block...
            file_vec.resize(block_size.try_into().unwrap(), 0);
            let current_pos = file.seek(SeekFrom::Current(0)).unwrap();
            println!("Reading bytes {}-{}", current_pos, current_pos+(block_size as u64)-1);
            let bytes_read = file.read(file_vec.as_mut_slice()).unwrap();
            // ...then shrink the vector to the number of bytes read, if needed
            if bytes_read < block_size.try_into().unwrap() {
                // Default is irrelevant as we're shrinking
                file_vec.resize(bytes_read, 0);
                // Ensure that reading less than requested only occurs when EOF
                assert!(start_block == block_count-1);
            }

            // Type annotate to ensure the correct type
            let hash_result: HashResult = Sha256::digest(file_vec.as_slice());
            println!("Block hash is {:x}", hash_result);
            hash_out.copy_from_slice(hash_result.as_slice());
        } else {
            // power-of-branch check
            assert!(block_interval % (branch as u64) == 0);
            let block_increment = block_interval / (branch as u64);
            let mut hash_vector: Vec::<HashResult> = Vec::new();
            hash_vector.resize(branch.into(), HashResult::default());
            // Compute the hash for each branch
            for incr_count in 0..(branch as u64) {
                let incr_index: usize = incr_count.try_into().unwrap();
                let slice_start = start_block + incr_count * block_increment;
                let slice_end = start_block + (incr_count + 1) * block_increment;
                merkle_tree_file_helper(file, block_size, block_count, branch, &mut hash_vector[incr_index], slice_start, slice_end);
            }
            let combined_input = hash_vector.concat();
            let hash_result: HashResult = Sha256::digest(combined_input.as_slice());
            hash_out.copy_from_slice(hash_result.as_slice());
        }
    }
}