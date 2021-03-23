#![forbid(unsafe_code)]

mod merkle_utils;

use std::io::prelude::*;
use std::io::BufReader;
use std::cmp::min;
use std::convert::TryInto;
use num_iter::{range_step, range_step_inclusive};

use digest::Digest;
use generic_array::GenericArray;
use std::collections::BTreeMap;

use merkle_utils::*;
pub use merkle_utils::{node_count, seek_len, BlockRange, HashRange, Consumer};

// Hash Generation
pub fn merkle_hash_file<F, D, C>(mut file: F, block_size: u32, branch: u16,
        mut hash_queue: C)
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
        block_size, block_count, block_range, branch, &mut hash_queue).unwrap();
    drop(hash_queue);
    return hash_out.0.to_vec().into_boxed_slice();
}

// TODO: static checking with https://github.com/project-oak/rust-verification-tools
// Block range includes the first and excludes the last
// Second element of tuple is seek position
fn merkle_tree_file_helper<F, T>(file: &mut BufReader<F>,
        block_size: u32, block_count: u64, block_range: BlockRange,
        branch: u16,
        hash_queue: &mut dyn Consumer<HashRange>)
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
                for slice_start in range_step(
                        block_range.start,
                        block_range.start+block_increment*branch as u64,
                        block_increment) {
                    let slice_end = slice_start+block_increment;
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
        let start_block = block_range.start;
        let start_byte = block_range.start*block_size as u64;
        let end_block = block_range.end-1;
        let end_byte_file = match current_seek_pos(file) {
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
        let block_range = BlockRange::new(start_block, end_block, true);
        let byte_range = BlockRange::new(start_byte, end_byte_file, true);
        let block_hash_result = HashRange::new(block_range, byte_range,hash_result.to_vec().into_boxed_slice());
        hash_queue.accept(block_hash_result).unwrap();
        return Some((hash_result, current_pos));
    } else {
        return None;
    }
}

// Hash Verification
pub struct TreeVerificationHelper<D>
where
    D: Digest
{
    dummy_element: std::marker::PhantomData<D>,
    branch_factor: u16,
    max_block_count: u64,
    blocks_inserted: u64,
    /*
     * Key is block_size, value is block_start->Option<(used,hash_value)>
     * Once a hash_value is checked, it can be deleted
     * We definitely need inner map sorting property
     * Outer map sorting property not needed, but range_mut avoids need for (unsafe) split_at_mut type construction
     */
    entry_map_read: BTreeMap<u64, BTreeMap<u64, Option<Box<[u8]>>>>,
    entry_map_calc: BTreeMap<u64, BTreeMap<u64, Option<Box<[u8]>>>>
}

impl<D> TreeVerificationHelper<D>
where
    D: Digest
{
    pub fn new(branch_factor: u16, max_block_count: u64)
            -> TreeVerificationHelper<D> {
        assert!(branch_factor >= 2);
        let mut new_obj = TreeVerificationHelper::<D> {
            dummy_element: std::marker::PhantomData::<D>::default(),
            branch_factor: branch_factor,
            max_block_count: max_block_count,
            blocks_inserted: 0,
            entry_map_read: BTreeMap::new(),
            entry_map_calc: BTreeMap::new()
        };
        let mut size_iter = 1;
        while size_iter <= max_block_count {
            // Ensure that entries do not already exist
            new_obj.entry_map_read.insert(size_iter, BTreeMap::new())
                    .ok_or(()).unwrap_err();
            new_obj.entry_map_calc.insert(size_iter, BTreeMap::new())
                    .ok_or(()).unwrap_err();
            size_iter *= branch_factor as u64;
        }
        debug_assert_eq!(size_iter, exp_ceil_log(max_block_count, branch_factor));
        return new_obj;
    }

    // When inserting items into the tree, we want to take ownership on success
    // And return the object back to the previous context upon failure
    pub fn insert_leaf_hash(&mut self, leaf_hash: HashRange) -> Result<(), HashRange> {
        if leaf_hash.block_range.range() != 1 || leaf_hash.block_range.start >= self.max_block_count {
            return Err(leaf_hash);
        }
        if leaf_hash.hash_result.len() != D::output_size() {
            return Err(leaf_hash);
        }
        let read_map = self.entry_map_read.get_mut(&1).unwrap();
        let calc_map = self.entry_map_calc.get_mut(&1).unwrap();
        assert_eq!(read_map.len(), calc_map.len());
        let block_start = leaf_hash.block_range.start;
        if read_map.contains_key(&block_start)
                || calc_map.contains_key(&block_start) {
            return Err(leaf_hash);
        }
        assert!(self.blocks_inserted <= read_map.len().try_into().unwrap());
        let hash_result = leaf_hash.hash_result;
        // TODO: Rc, but only for the first level?
        read_map.insert(block_start,
            Some(hash_result.clone()));
        calc_map.insert(block_start,
            Some(hash_result));
        self.blocks_inserted += 1;
        return Ok(());
    }
    pub fn insert_nonleaf_read_hash(&mut self, nonleaf_hash: HashRange) -> Result<(), HashRange> {
        let block_range_size = nonleaf_hash.block_range.range();
        if exp_ceil_log(block_range_size, self.branch_factor) != block_range_size {
            return Err(nonleaf_hash);
        }
        if nonleaf_hash.block_range.start >= self.max_block_count
                || nonleaf_hash.block_range.start % block_range_size != 0 {
            return Err(nonleaf_hash);
        }
        let block_start = nonleaf_hash.block_range.start;
        if nonleaf_hash.hash_result.len() != D::output_size() {
            return Err(nonleaf_hash);
        }
        let read_map = self.entry_map_read.get_mut(&block_range_size).unwrap();
        if read_map.contains_key(&block_start) {
            return Err(nonleaf_hash);
        }
        let hash_result = nonleaf_hash.hash_result;
        read_map.insert(block_start, Some(hash_result));
        return Ok(());
    }

    // OK(bool): verification OK, true when no more hashes to verify
    // Err(BlockRange): the range which has a mismatched hash
    pub fn calc_and_verify(&mut self) -> Result<bool, BlockRange> {
        let mut scan_size_iter: u64 = 1;
        while !self.entry_map_calc.contains_key(&scan_size_iter) {
            scan_size_iter *= self.branch_factor as u64;
            assert!(scan_size_iter <= self.max_block_count);
        }
        if scan_size_iter == exp_ceil_log(
                self.max_block_count, self.branch_factor) {
            return Ok(true);
        }
        let mut range_size_next = scan_size_iter * self.branch_factor as u64;
        while range_size_next <= self.max_block_count {
            let mut iter_extract = self.entry_map_calc.range_mut(
                    scan_size_iter..=range_size_next);
            let (_, scan_dict) = iter_extract.next().unwrap();
            let (_, insert_dict) = iter_extract.next().unwrap();
            assert!(iter_extract.next().is_none());
            drop(iter_extract);

            // Start list to concatenate
            let mut blocks_concat: Vec<&[u8]>
                    = Vec::with_capacity(self.branch_factor.into());
            // Index to insert at higher level
            let mut blocks_concat_start: Option<u64> = None;
            // Detect if all remaining entries are None
            let mut has_some_at_level = false;
            let mut blocks_del: Vec<u64> = Vec::new();
            for (&block_start, hash_box) in scan_dict.iter() {
                if hash_box.is_none() {
                    continue;
                }
                if blocks_concat.len() == 0 {
                    // Start combining list
                    debug_assert!(blocks_concat_start.is_none());
                    if block_start % range_size_next == 0 {
                        let hash_get = hash_box.as_ref();
                        blocks_concat.push(hash_get.unwrap().as_ref());
                        blocks_concat_start = Some(block_start);
                    } else {
                        continue;
                    }
                } else {
                    debug_assert!(blocks_concat_start.is_some());
                    let offset: u64 = blocks_concat.len().try_into().unwrap();
                    let expected_pos = blocks_concat_start.unwrap()
                            + offset * scan_size_iter;
                    // Is the next block a continuation?
                    if block_start == expected_pos {
                        // Add it into the list
                        let hash_get = hash_box.as_ref();
                        blocks_concat.push(hash_get.unwrap().as_ref());
                        debug_assert!(blocks_concat.len() <= self.branch_factor.into());

                        let block_end = block_start + scan_size_iter;
                        // Done concatenating if full length or EOF
                        if blocks_concat.len() == self.branch_factor.into()
                                || block_end >= self.max_block_count {
                            // Compute combined hash and insert into next level
                            let mut hash_input = blocks_concat.concat();
                            hash_input.insert(0, 0x01);
                            let hash_result_arr = D::digest(hash_input.as_slice());

                            let hash_result_box = hash_result_arr.to_vec().into_boxed_slice();
                            // Verify that next-level hash matches
                            let hash_ref = self.entry_map_read
                                .get(&scan_size_iter).unwrap()
                                .get(&blocks_concat_start.unwrap()).unwrap()
                                .as_ref().unwrap();
                            if *hash_ref != hash_result_box {
                                return Err(BlockRange::new(
                                    blocks_concat_start.unwrap(),
                                    blocks_concat_start.unwrap()+range_size_next-1,
                                    true
                                ))
                            }

                            // Insert new hash and mark old ones for deletion
                            insert_dict.insert(blocks_concat_start.unwrap(), Some(hash_result_box));
                            for block_del in range_step_inclusive(
                                    blocks_concat_start.unwrap(),
                                    block_start, scan_size_iter) {
                                blocks_del.push(block_del);
                            }
                        }
                    } else {
                        blocks_concat.clear();
                        blocks_concat_start = None;
                        if hash_box.as_ref().is_some() {
                            // Only set this if we actually have elements left
                            has_some_at_level = true;
                        }
                        continue;
                    }
                }
            }
            // Handle partial concatenation at end here
            if !blocks_concat.is_empty() {
                // Only set this if we actually have elements left
                has_some_at_level = true;
            }
            blocks_concat.clear();
            // blocks_concat_start = None;

            let ref_dict = self.entry_map_read.get_mut(&scan_size_iter).unwrap();
            for block_del in blocks_del {
                // The unwrap already asserts entry was from map
                scan_dict.insert(block_del, None).unwrap();
                ref_dict.insert(block_del, None).unwrap();
            }
            // Second condition: no more blocks will be read in?
            /*if !has_some_at_level
                    && self.blocks_inserted == self.max_block_count {
                self.entry_map_calc.remove(&scan_size_iter).unwrap();
            }*/
            scan_size_iter *= self.branch_factor as u64;
            range_size_next *= self.branch_factor as u64;
        }
        return Ok(false);
    }
}