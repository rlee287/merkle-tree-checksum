#![forbid(unsafe_code)]

use crate::merkle_utils::{ceil_div, exp_ceil_log, BlockRange, HashRange};
use crate::merkle_utils::{branch_t, block_t};

use num_iter::range_step;

use async_recursion::async_recursion;
use genawaiter::rc::{Co, Gen};

use std::collections::HashMap;

pub fn merkle_block_generator(file_len: u64, block_size: block_t, branch: branch_t) -> impl IntoIterator<Item = BlockRange> {
    assert!(block_size != 0);
    assert!(branch >= 2);
    let block_count = match ceil_div(file_len, block_size.into()) {
        0 => 1,
        n => n
    };
    let effective_block_count = exp_ceil_log(block_count, branch);

    let block_range = BlockRange::new(0, effective_block_count, false);
    Gen::new(|state| async move {
        merkle_block_generator_helper(&state,
            block_count, block_range, branch).await;
    })
}

#[async_recursion(?Send)]
async fn merkle_block_generator_helper(state: &Co<BlockRange>,
        block_count: u64, block_range: BlockRange,
        branch: branch_t) {
    if block_range.include_end() {
        assert!(block_range.start() <= block_range.end());
    } else {
        assert!(block_range.start() < block_range.end());
    }

    let block_interval = block_range.range();
    if block_range.start() < block_count {
        if block_range.range() == 1 {
            state.yield_(BlockRange::new(
                block_range.start(), block_range.start(), true)).await;
        } else {
            assert!(block_interval % (branch as u64) == 0);
            let block_increment = block_interval / (branch as u64);
            // Compute the hash for each branch
            for slice_start in range_step(
                    block_range.start(),
                    block_range.start()+block_increment*branch as u64,
                    block_increment) {
                let slice_end = slice_start+block_increment;
                let slice_range = BlockRange::new(slice_start, slice_end, false);
                merkle_block_generator_helper(state, block_count, slice_range, branch).await;
            }
            let start_block = block_range.start();
            let end_block = block_range.end()-match block_range.include_end() {
                true => 0,
                false => 1
            };
            state.yield_(BlockRange::new(start_block, end_block, true)).await;
        }
    }
}

pub fn reorder_hashrange_iter<T, U> (ref_ordered_iter: T, mut hashrange_iter: U) -> impl IntoIterator<Item = HashRange>
where
    T: Iterator<Item = BlockRange>,
    U: Iterator<Item = HashRange>
{
    Gen::new(|state| async move {
        // TODO: a binary heap would be better but I don't know how to impl Ord for BlockRange;
        let mut ooo_block_storage = HashMap::<BlockRange, HashRange>::new();
        for expected_block in ref_ordered_iter {
            let mut yielded_element = false;
            while !yielded_element {
                if ooo_block_storage.contains_key(&expected_block) {
                    let stored_hashrange = ooo_block_storage.remove(&expected_block).unwrap();
                    yielded_element = true;
                    state.yield_(stored_hashrange).await;
                } else {
                    let next_hashrange = hashrange_iter.next().unwrap();
                    if next_hashrange.block_range() == expected_block {
                        yielded_element = true;
                        state.yield_(next_hashrange).await;
                    } else {
                        ooo_block_storage.insert(next_hashrange.block_range(), next_hashrange).ok_or(()).unwrap_err();
                    }
                }
            }
        }
        assert!(ooo_block_storage.is_empty());
        assert!(hashrange_iter.next().is_none());
    })
}