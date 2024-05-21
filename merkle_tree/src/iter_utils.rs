#![forbid(unsafe_code)]

use crate::merkle_utils::{BlockRange, HashRange};
use crate::merkle_utils::{branch_t, block_t};

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;

#[derive(Debug, Clone)]
struct TreeBlockIter {
    iter_stash: VecDeque<BlockRange>,
    branch: branch_t,
    iter_block_ctr: u64,
    leaf_block_count: u64
}
impl TreeBlockIter {
    pub fn new(leaf_block_count: u64, branch: branch_t) -> Self {
        assert!(branch >= 2);
        Self {
            iter_stash: VecDeque::new(),
            branch,
            iter_block_ctr: 0,
            leaf_block_count
        }
    }
}
impl Iterator for TreeBlockIter {
    type Item = BlockRange;

    fn next(&mut self) -> Option<Self::Item> {
        // Check the stash first in order to properly unwind at the end
        match self.iter_stash.pop_front() {
            Some(val) => Some(val),
            None => {
                // Separately handle the case of leaf_block_count being 0
                if self.iter_block_ctr >= self.leaf_block_count {
                    if self.iter_block_ctr > self.leaf_block_count {
                        return None;
                    }
                    if self.leaf_block_count > 0 {
                        return None;
                    }
                }
                // Construct the next single block
                let next_single = BlockRange::new(self.iter_block_ctr, self.iter_block_ctr, true);

                let branch_as_u64 = u64::from(self.branch);

                // Construct non-leaf nodes at the end of larger sections
                let single_end_pt = self.iter_block_ctr + 1;
                let mut div_tester = branch_as_u64;
                while div_tester <= self.leaf_block_count {
                    // Round down to next multiple
                    let larger_interval_start = (self.iter_block_ctr / (div_tester)) * div_tester;
                    if single_end_pt % div_tester == 0 {
                        // Non-leaf node at end of section
                        self.iter_stash.push_back(BlockRange::new(larger_interval_start, single_end_pt, false));
                    } else if single_end_pt >= self.leaf_block_count {
                        // Non-leaf node at end of entire file, possibly truncated tree
                        let larger_interval_end = larger_interval_start + div_tester;
                        self.iter_stash.push_back(BlockRange::new(larger_interval_start, larger_interval_end, false));
                    }
                    div_tester *= branch_as_u64;
                }
                // Add the root if we haven't already walked it back from a non-truncated tree
                if let Some(last) = self.iter_stash.back() {
                    if single_end_pt >= self.leaf_block_count && last.start() != 0 {
                        self.iter_stash.push_back(BlockRange::new(0, div_tester, false));
                    }
                }
                self.iter_block_ctr += 1;
                return Some(next_single);
            }
        }
    }
}

pub fn merkle_block_generator(file_len: u64, block_size: block_t, branch: branch_t) -> impl IntoIterator<Item = BlockRange> {
    assert!(block_size != 0);
    assert!(branch >= 2);

    let block_count = file_len.div_ceil(block_size.into());
    TreeBlockIter::new(block_count, branch)
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

#[cfg(test)]
mod test {
    use super::*;

    use crate::merkle_utils::exp_ceil_log;

    use num_iter::range_step;

    // Based on the old genawaiter impl but with vec building instead
    fn merkle_block_generator_ref_impl(file_len: u64, block_size: block_t, branch: branch_t) -> Vec<BlockRange> {
        assert!(block_size != 0);
        assert!(branch >= 2);
        let block_count = match file_len.div_ceil(block_size.into()) {
            0 => 1,
            n => n
        };
        let effective_block_count = exp_ceil_log(block_count, branch);

        let block_range = BlockRange::new(0, effective_block_count, false);

        let mut ret_vec = Vec::new();
        merkle_block_generator_helper(&mut ret_vec,
                block_count, block_range, branch);
        ret_vec
    }

    fn merkle_block_generator_helper(state: &mut Vec<BlockRange>,
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
                state.push(BlockRange::new(
                    block_range.start(), block_range.start(), true));
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
                    merkle_block_generator_helper(state, block_count, slice_range, branch);
                }
                let start_block = block_range.start();
                let end_block = block_range.end()-match block_range.include_end() {
                    true => 0,
                    false => 1
                };
                state.push(BlockRange::new(start_block, end_block, true));
            }
        }
    }
    // Verify equivalence between old recursive impl and new impl
    #[test]
    fn block_iter_equivalences_clean() {
        let ref_vec: Vec<_> = merkle_block_generator_ref_impl(16, 1, 4);
        let new_vec: Vec<_> = merkle_block_generator(16, 1, 4).into_iter().collect();
        assert_eq!(ref_vec, new_vec);
    }

    #[test]
    fn block_iter_equivalences_ragged() {
        let ref_vec: Vec<_> = merkle_block_generator_ref_impl(21, 1, 4);
        let new_vec: Vec<_> = merkle_block_generator(21, 1, 4).into_iter().collect();
        assert_eq!(ref_vec, new_vec);
    }

    #[test]
    fn block_iter_equivalences_empty() {
        let ref_vec: Vec<_> = merkle_block_generator_ref_impl(0, 1, 4);
        let new_vec: Vec<_> = merkle_block_generator(0, 1, 4).into_iter().collect();
        assert_eq!(ref_vec, new_vec);
    }

    #[test]
    fn block_iter_equivalences_ranging() {
        for i in 0..=32 {
            let ref_vec: Vec<_> = merkle_block_generator_ref_impl(i, 1, 2);
            let new_vec: Vec<_> = merkle_block_generator(i, 1, 2).into_iter().collect();
            assert_eq!(ref_vec, new_vec);
        }
    }

    #[test]
    fn block_iter_equivalences_ragged_blocksize() {
        let ref_vec: Vec<_> = merkle_block_generator_ref_impl(21, 2, 4);
        let new_vec: Vec<_> = merkle_block_generator(21, 2, 4).into_iter().collect();
        assert_eq!(ref_vec, new_vec);
    }
}
