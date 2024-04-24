#![forbid(unsafe_code)]

use crate::merkle_utils::{exp_ceil_log, BlockRange, HashRange};
use crate::merkle_utils::{branch_t, block_t};

use num_iter::range_step;

use genawaiter::rc::{Co, Gen};

use std::collections::HashMap;
use std::hash::Hash;

pub fn merkle_block_generator(file_len: u64, block_size: block_t, branch: branch_t) -> impl IntoIterator<Item = BlockRange> {
    assert!(block_size != 0);
    assert!(branch >= 2);
    let block_count = match file_len.div_ceil(block_size.into()) {
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
                Box::pin(merkle_block_generator_helper(state, block_count, slice_range, branch)).await;
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

// Iterator that reorders iterator I_B with type B and extractable key type A to match iterator I_A
// The iterators should be the same length, and I_A should never repeat
// TODO: a binary heap would be better but I don't know how to impl Ord for BlockRange;
#[derive(Debug, Clone)]
struct ReorderHashIter<A, B, IterA, IterB, F>
where
    A: PartialEq+Eq,
    F: Fn(&B) -> A,
    IterA: Iterator<Item = A>,
    IterB: Iterator<Item = B>
{
    iter_ordered: IterA,
    iter_to_reorder: IterB,
    func_extract: F,
    reorder_hashmap: HashMap<A, B>
}
impl<A, B, IterA, IterB, F> ReorderHashIter<A, B, IterA, IterB, F>
where
    A: PartialEq+Eq,
    F: Fn(&B) -> A,
    IterA: Iterator<Item = A>,
    IterB: Iterator<Item = B>
{
    pub fn new<IntoIterA, IntoIterB>(ref_ordered_iter: IntoIterA, reordered_iter: IntoIterB, extractor_func: F) -> Self
    where
        IntoIterA: IntoIterator<Item = A, IntoIter = IterA>,
        IntoIterB: IntoIterator<Item = B, IntoIter = IterB>
    {
        Self {
            iter_ordered: ref_ordered_iter.into_iter(),
            iter_to_reorder: reordered_iter.into_iter(),
            func_extract: extractor_func,
            reorder_hashmap: HashMap::new()
        }
    }
}
impl<A, B, IterA, IterB, F> Iterator for ReorderHashIter<A, B, IterA, IterB, F>
where
    A: Hash+PartialEq+Eq,
    F: Fn(&B) -> A,
    IterA: Iterator<Item = A>,
    IterB: Iterator<Item = B>
{
    type Item = B;

    fn next(&mut self) -> Option<Self::Item> {
        let next_expected_key = match self.iter_ordered.next() {
            Some(k) => k,
            None => return None
        };
        loop {
            if self.reorder_hashmap.contains_key(&next_expected_key) {
                let stored_obj = self.reorder_hashmap.remove(&next_expected_key).unwrap();
                return Some(stored_obj);
            } else {
                let unordered_next = match self.iter_to_reorder.next() {
                    Some(v) => v,
                    None => return None
                };
                let unordered_key = (self.func_extract)(&unordered_next);
                if unordered_key == next_expected_key {
                    return Some(unordered_next);
                } else {
                    assert!(self.reorder_hashmap.insert(unordered_key, unordered_next).is_none());
                }
            }
        }
    }
}

pub fn reorder_hashrange_iter<T, U> (ref_ordered_iter: T, hashrange_iter: U) -> impl IntoIterator<Item = HashRange>
where
    T: Iterator<Item = BlockRange>,
    U: Iterator<Item = HashRange>
{
    ReorderHashIter::new(ref_ordered_iter, hashrange_iter, |hashrange| hashrange.block_range())
}