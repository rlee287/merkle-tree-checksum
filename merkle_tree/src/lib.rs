#![forbid(unsafe_code)]

mod merkle_utils;
mod thread_pool;

use std::io::prelude::*;
use std::io::SeekFrom;
use std::convert::TryInto;
use num_iter::range_step;

use digest::Digest;
use generic_array::GenericArray;

use merkle_utils::*;
pub use merkle_utils::{node_count, seek_len, BlockRange, HashRange, Consumer};
pub use merkle_utils::{branch_t, block_t};

use async_recursion::async_recursion;
use genawaiter::rc::{Co, Gen};

use thread_pool::{Awaitable, DummyAwaitable};
use thread_pool::{PoolEvaluator, DummyEvaluator, ThreadPoolEvaluator};
extern crate num_cpus;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum HelperErrSignal {
    FileEOF,
    ConsumerErr
}

#[derive(Debug)]
enum EvaluatorUnion {
    Dummy(DummyEvaluator),
    ThreadPool(ThreadPoolEvaluator)
}
impl EvaluatorUnion {
    fn make_dummy() -> Self {
        Self::Dummy(DummyEvaluator::new())
    }
    fn make_threadpool(num_threads: usize) -> Self {
        Self::ThreadPool(ThreadPoolEvaluator::new(num_threads))
    }
}
impl PoolEvaluator for EvaluatorUnion {
    fn compute<T, F>(&self, func: F) -> Box<dyn Awaitable<T>>
    where
        T: 'static + Send + std::fmt::Debug,
        F: 'static + Send + Fn() -> T
    {
        match self {
            Self::Dummy(eval) => eval.compute(func),
            Self::ThreadPool(eval) => eval.compute(func)
        }
    }
}

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

pub fn merkle_hash_file<F, D, C>(mut file: F,
        block_size: block_t, branch: branch_t,
        hash_queue: C, multithread: bool) -> Option<Box<[u8]>>
where
    F: Read + Seek,
    D: Digest + 'static,
    C: Consumer<HashRange> + Send + Clone + 'static
{
    assert!(block_size != 0);
    assert!(branch >= 2);
    file.seek(SeekFrom::Start(0)).unwrap();
    let file_len = seek_len(&mut file);
    let block_count = match ceil_div(file_len, block_size.into()) {
        0 => 1,
        n => n
    };
    let effective_block_count = exp_ceil_log(block_count, branch);
    let block_range = BlockRange::new(0, effective_block_count, false);

    let threadpool_obj = match multithread {
        true => {
            let thread_count = match num_cpus::get() {
                1 => 1,
                n => n-1
            };
            EvaluatorUnion::make_threadpool(thread_count)
        }
        false => EvaluatorUnion::make_dummy()
    };
    let mut hash_out_awaitable = merkle_tree_file_helper::<_, D, _>(&mut file,
        block_size, block_count, block_range, branch,
        hash_queue, &threadpool_obj);
    let hash_out_result = hash_out_awaitable.await_().as_ref();
    let hash_out = hash_out_result.ok()?;
    debug_assert_eq!(file_len, hash_out.1);
    return Some(hash_out.0.to_vec().into_boxed_slice());
}

type HashArray<T> = GenericArray<u8, <T as Digest>::OutputSize>;
type HashResult<T> = Result<(HashArray<T>, u64), HelperErrSignal>;
// TODO: static checking with https://github.com/project-oak/rust-verification-tools
// Block range includes the first and excludes the last
// Second element of tuple is seek position
fn merkle_tree_file_helper<F, D, C>(file: &mut F,
        block_size: block_t, block_count: u64, block_range: BlockRange,
        branch: branch_t,
        hash_queue: C,
        threadpool: &EvaluatorUnion)
        -> Box<dyn Awaitable<HashResult<D>>>
where
    F: Read + Seek,
    D: Digest + 'static,
    C: Consumer<HashRange> + Send + Clone + 'static,
{
    if block_range.include_end() {
        assert!(block_range.start() <= block_range.end());
    } else {
        assert!(block_range.start() < block_range.end());
    }

    let start_block = block_range.start();
    let end_block = block_range.end()-match block_range.include_end() {
        true => 0,
        false => 1
    };
    let block_interval = block_range.range();

    let start_byte = block_range.start()*block_size as u64;
    // Defer end_byte calculation until after file read

    if block_range.start() < block_count {
        let mut current_pos = block_range.start()*(block_size as u64);
        // TODO: reduce indirection
        if block_interval == 1 {
            let block_size_as_usize: usize = block_size.try_into().unwrap();
            let mut file_vec: Vec::<u8> = vec![0x00; block_size_as_usize+1];
    
            // Initial size to block_size to read in a full block...
            // 0x00 already prepended before reading in file contents
            //file_vec[0] = 0x00;
            // Should be optimized out in release mode
            #[cfg(debug_assertions)]
            {
                let current_pos_actual = file.stream_position().unwrap();
                debug_assert_eq!(current_pos_actual, current_pos);
            }
            let bytes_read = read_into_slice(file, Some(current_pos), &mut file_vec[1..]).unwrap();
            // ...then shrink the vector to the number of bytes read, if needed
            if bytes_read < block_size.try_into().unwrap() {
                // Default is irrelevant as we're shrinking
                file_vec.resize(bytes_read+1, 0);
                // Ensure that reading less than requested only occurs when EOF
                debug_assert_eq!(block_range.start(), block_count-1);
            }
            current_pos += bytes_read as u64;
            let end_byte_file = current_pos.saturating_sub(1);
            #[cfg(debug_assertions)]
            {
                let end_byte_file_actual = file.stream_position().unwrap().saturating_sub(1);
                debug_assert_eq!(end_byte_file_actual, end_byte_file);
            }
            let hash_future = threadpool.compute(move || {
                let block_range = BlockRange::new(start_block, end_block, true);
                let byte_range = BlockRange::new(start_byte, end_byte_file, true);

                let hash_result = D::digest(file_vec.as_slice());
                let block_hash_result = HashRange::new(block_range, byte_range,hash_result.to_vec().into_boxed_slice());

                if hash_queue.accept(block_hash_result).is_ok() {
                    return Ok((hash_result, current_pos));
                } else {
                    return Err(HelperErrSignal::ConsumerErr);
                }
            });
            return hash_future;
        } else {
            // power-of-branch check
            assert!(block_interval % (branch as u64) == 0);
            let block_increment = block_interval / (branch as u64);
            let mut subhash_awaitables: Vec<_> = Vec::with_capacity(branch.into());
            for slice_start in range_step(
                    block_range.start(),
                    block_range.start()+block_increment*branch as u64,
                    block_increment) {
                let slice_end = slice_start+block_increment;
                let slice_range = BlockRange::new(slice_start, slice_end, false);
                subhash_awaitables.push(merkle_tree_file_helper::<F, D, C>(file, 
                    block_size, block_count, slice_range, branch, 
                    hash_queue.clone(), threadpool));
            }
            let mut hash_input: Vec<u8> = Vec::with_capacity(
                <D as Digest>::output_size()*subhash_awaitables.len()+1);
            hash_input.insert(0, 0x01);
            for mut awaitable in subhash_awaitables {
                match awaitable.await_() {
                    Ok(subhash) => {
                        hash_input.extend(subhash.0.clone());
                        current_pos = subhash.1;
                    },
                    Err(HelperErrSignal::FileEOF) => {
                        // None -> out of range, and so will the rest
                        // break drops awaitable and rest of subhash_awaitables
                        break;
                    },
                    Err(HelperErrSignal::ConsumerErr) => {
                        let dummy_err = DummyAwaitable::new(Err(HelperErrSignal::ConsumerErr));
                        return Box::new(dummy_err);
                    }
                }
            }
            let end_byte_file = current_pos.saturating_sub(1);
            #[cfg(debug_assertions)]
            {
                let end_byte_file_actual = file.stream_position().unwrap().saturating_sub(1);
                debug_assert_eq!(end_byte_file_actual, end_byte_file);
            }
            let hash_future = threadpool.compute(move || {
                let block_range = BlockRange::new(start_block, end_block, true);
                let byte_range = BlockRange::new(start_byte, end_byte_file, true);

                let hash_result = D::digest(hash_input.as_slice());
                let block_hash_result = HashRange::new(block_range, byte_range,hash_result.to_vec().into_boxed_slice());

                if hash_queue.accept(block_hash_result).is_ok() {
                    return Ok((hash_result, current_pos));
                } else {
                    return Err(HelperErrSignal::ConsumerErr);
                }
            });
            return hash_future;
        }
    } else {
        let dummy_err = DummyAwaitable::new(Err(HelperErrSignal::FileEOF));
        return Box::new(dummy_err);
    }
}
