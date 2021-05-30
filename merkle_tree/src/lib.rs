#![forbid(unsafe_code)]

mod merkle_utils;

use std::io::prelude::*;
use std::io::{BufReader, SeekFrom};
use std::cmp::min;
use std::convert::TryInto;
use num_iter::{range_step, range_step_inclusive};

use digest::Digest;
use generic_array::GenericArray;
use std::collections::{BTreeSet, BTreeMap};
use range_union_find::{IntRangeUnionFind, OverlapType};

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
    file.seek(SeekFrom::Start(0)).unwrap();
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
                    if let Some(subhash) = subhash_res {
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
    // Location bound sanity checks when inserting nodes
    max_block_count: BTreeMap<u64, u64>,
    // Tracks nodes that have been verified
    blocks_checked: BTreeMap<u64, IntRangeUnionFind<u64>>,
    // Tracks nodes no longer needed (GC'ed) after being calculated with
    blocks_gc: BTreeMap<u64, IntRangeUnionFind<u64>>,
    /*
     * Key is block_size, value is block_start->Option<(used,hash_value)>
     * Once a hash_value is checked, it can be deleted
     * We definitely need inner map sorting property
     * Outer map sorting property not needed, but range_mut avoids need for (unsafe) split_at_mut type construction
     */
    entry_map_file: BTreeMap<u64, BTreeMap<u64, digest::Output<D>>>,
    entry_map_calc: BTreeMap<u64, BTreeMap<u64, digest::Output<D>>>
}

impl<D> TreeVerificationHelper<D>
where
    D: Digest
{
    pub fn new(branch_factor: u16, max_block_count: u64)
            -> TreeVerificationHelper<D> {
        assert!(branch_factor >= 2);
        let mut size_iter = 1;
        let mut block_counter = max_block_count;
        let mut entry_map_file = BTreeMap::new();
        let mut entry_map_calc = BTreeMap::new();
        let mut max_block_count_map = BTreeMap::new();
        let mut blocks_checked = BTreeMap::new();
        let mut blocks_gced = BTreeMap::new();
        while size_iter <= max_block_count {
            // Ensure that entries do not already exist
            entry_map_file.insert(size_iter, BTreeMap::new())
                    .ok_or(()).unwrap_err();
            entry_map_calc.insert(size_iter, BTreeMap::new())
                    .ok_or(()).unwrap_err();
            max_block_count_map.insert(size_iter, block_counter)
                    .ok_or(()).unwrap_err();
            blocks_checked.insert(size_iter, IntRangeUnionFind::new())
                    .ok_or(()).unwrap_err();
            blocks_gced.insert(size_iter, IntRangeUnionFind::new())
                    .ok_or(()).unwrap_err();
            block_counter = ceil_div(block_counter, branch_factor as u64);
            size_iter *= branch_factor as u64;
        }
        debug_assert_eq!(size_iter, exp_ceil_log(max_block_count, branch_factor));
        debug_assert_eq!(block_counter, 1);
        TreeVerificationHelper::<D> {
            dummy_element: std::marker::PhantomData::<D>::default(),
            branch_factor: branch_factor,
            max_block_count: max_block_count_map,
            blocks_checked: blocks_checked,
            blocks_gc: blocks_gced,
            entry_map_file: entry_map_file,
            entry_map_calc: entry_map_calc
        }
    }

    // Inserts a hash, calculated from a data block
    pub fn insert_leaf_calc_hash(&mut self, loc: u64, data: &[u8]) -> Result<(), ()> {
        // loc >= 0 by u64 type
        if loc >= *self.max_block_count.get(&1).unwrap() {
            return Err(());
        }
        let calc_map = self.entry_map_calc.get_mut(&1).unwrap();
        let blocks_deleted = self.blocks_gc.get(&1).unwrap();
        if calc_map.contains_key(&loc)
                || blocks_deleted.element_contained(&loc) {
            return Err(());
        }
        calc_map.insert(loc, D::digest(data));
        return Ok(());
    }
    // Inserts a hash which was previously read from the hash file
    // When inserting items into the tree, we want to take ownership on success
    // And return the object back to the previous context upon failure
    pub fn insert_file_hash(&mut self, file_hash: HashRange) -> Result<(), HashRange> {
        let block_range_size = file_hash.block_range.range();
        if exp_ceil_log(block_range_size, self.branch_factor) != block_range_size {
            return Err(file_hash);
        }
        let block_start = file_hash.block_range.start;
        let block_end = match file_hash.block_range.include_end {
            true => file_hash.block_range.end,
            false => file_hash.block_range.end - 1
        };
        // block_start >= 0 by u64 type
        if block_start >= *self.max_block_count.get(&block_range_size).unwrap()
                || block_start % block_range_size != 0 {
            return Err(file_hash);
        }
        if file_hash.hash_result.len() != D::output_size() {
            return Err(file_hash);
        }
        let file_map = self.entry_map_file.get_mut(&block_range_size).unwrap();
        let blocks_deleted = self.blocks_checked.get(&block_range_size).unwrap();
        let range_containment = blocks_deleted.range_contained(&(block_start..=block_end)).unwrap();
        if file_map.contains_key(&block_start) 
                || range_containment == OverlapType::Contained {
            return Err(file_hash);
        }
        assert_eq!(range_containment, OverlapType::Disjoint);
        let hash_result = GenericArray::from_exact_iter(
            file_hash.hash_result.into_vec()).unwrap();
        file_map.insert(block_start, hash_result);
        return Ok(());
    }

    fn nodes_equal(&self, start_pos: u64, size: u64) -> Option<bool> {
        assert_eq!(start_pos % size, 0);
        let file_entries = self.entry_map_file.get(&size).unwrap();
        let file_entry = file_entries.get(&start_pos)?;
        let calc_entries = self.entry_map_calc.get(&size).unwrap();
        let calc_entry = calc_entries.get(&start_pos)?;
        Some(file_entry == calc_entry)
    }

    // OK(bool): verification OK, true when no more hashes to verify
    // Err(BlockRange): the range which has a mismatched hash
    // This should definitely be split into yield+coroutines
    // TODO: rewrite all
    pub fn calc_and_verify(&mut self) -> Result<bool, BlockRange> {
        let max_leaf_count = *self.max_block_count.get(&1).unwrap();

        let mut scan_size_iter: u64 = 1;
        let mut range_size_next = self.branch_factor as u64;

        // HashSet instead?
        let mut blocks_del: BTreeSet<u64> = BTreeSet::new();
        while range_size_next <= max_leaf_count {
            debug_assert!(scan_size_iter * self.branch_factor as u64 == range_size_next);
            // Get the dictionary entries
            let mut iter_extract = self.entry_map_calc.range_mut(
                    scan_size_iter..=range_size_next);
            let (_, scan_calc_dict) = iter_extract.next().unwrap();
            let (_, insert_calc_dict) = iter_extract.next().unwrap();
            debug_assert!(iter_extract.next().is_none());
            drop(iter_extract);

            let ranges_checked = self.blocks_checked.get_mut(&scan_size_iter).unwrap();
            let ranges_gced = self.blocks_gc.get_mut(&scan_size_iter).unwrap();

            // Index to insert at higher level
            let mut blocks_concat_start: Option<u64> = None;
            let mut consecutive_run_ctr: u16 = 0;

            for (&iter_block_start, hash_calc_box) in scan_calc_dict.iter() {
                // Check existing hashes against hash file
                if !ranges_checked.element_contained(&iter_block_start) {
                    let file_dict = self.entry_map_file.get_mut(&scan_size_iter).unwrap();
                    let range_blocks = iter_block_start..iter_block_start+scan_size_iter;
                    let file_hash = file_dict.get(&iter_block_start);
                    if file_hash.is_some() {
                        if file_hash.unwrap() == hash_calc_box {
                            file_dict.remove(&iter_block_start).unwrap();
                            ranges_checked.insert_range(&range_blocks).unwrap();
                        } else {
                            return Err(BlockRange::from(range_blocks));
                        }
                    }
                }
                // TODO: insert check for Ok(true)
                if consecutive_run_ctr == 0 {
                    // Start combining list
                    debug_assert!(blocks_concat_start.is_none());
                    if iter_block_start % range_size_next == 0 {
                        blocks_concat_start = Some(iter_block_start);
                    } else {
                        continue;
                    }
                } else {
                    debug_assert!(blocks_concat_start.is_some());
                    let blocks_start_raw = blocks_concat_start.unwrap();
                    let expected_pos = blocks_start_raw
                            + consecutive_run_ctr as u64 * scan_size_iter;
                    // Is the next block a continuation?
                    if iter_block_start == expected_pos {
                        consecutive_run_ctr += 1;
                        debug_assert!(consecutive_run_ctr <= self.branch_factor);

                        let iter_block_end = iter_block_start + scan_size_iter;
                        // Done concatenating if full length or EOF
                        if consecutive_run_ctr == self.branch_factor
                                || iter_block_end >= max_leaf_count {
                            // Compute combined hash and insert into next level
                            let mut hash_input = range_step(
                                blocks_start_raw,
                                iter_block_end,
                                scan_size_iter)
                                .map(|index| scan_calc_dict.get(&index).unwrap().as_ref())
                                .collect::<Vec<&[u8]>>()
                                .concat();
                            hash_input.insert(0, 0x01);
                            let hash_result_arr = D::digest(hash_input.as_slice());
                            // Verify that next-level hash matches?
                            /*let hash_ref = self.entry_map_file
                                .get(&scan_size_iter).unwrap()
                                .get(&blocks_concat_start.unwrap()).unwrap();
                            if *hash_ref != hash_result_arr {
                                return Err(BlockRange::new(
                                    blocks_concat_start.unwrap(),
                                    blocks_concat_start.unwrap()+range_size_next,
                                    false
                                ))
                            }*/

                            // Insert new hash and mark old ones for deletion
                            insert_calc_dict.insert(blocks_concat_start.unwrap(), hash_result_arr);
                            for block_del in range_step_inclusive(
                                    blocks_concat_start.unwrap(),
                                    iter_block_start, scan_size_iter) {
                                blocks_del.insert(block_del);
                            }
                        }
                    } else {
                        consecutive_run_ctr = 0;
                        blocks_concat_start = None;
                        continue;
                    }
                }
            }
            // Handle partial concatenation at end here
            /*if consecutive_run_ctr != 0 {
                // Only set this if we actually have elements left
                consecutive_run_ctr = 0;
            }*/
            // blocks_concat_start = None;

            let mut actually_removed: BTreeSet<u64> = BTreeSet::new();
            for block_del in blocks_del.iter() {
                // The unwrap already asserts entry was in map
                if ranges_checked.element_contained(block_del) {
                    ranges_gced.insert_range(&(block_del..=block_del)).unwrap();
                    scan_calc_dict.remove(&block_del).unwrap();
                    actually_removed.insert(*block_del);
                }
            }
            blocks_del = &blocks_del - &actually_removed;


            scan_size_iter *= self.branch_factor as u64;
            range_size_next *= self.branch_factor as u64;
        }
        //let clog_leaf_count = exp_ceil_log(max_leaf_count, self.branch_factor);
        // TODO: check that everything has been deleted as redundant
        return Ok(false);
    }
}