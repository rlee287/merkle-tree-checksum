#![forbid(unsafe_code)]

mod merkle_utils;
mod iter_utils;
mod thread_pool;

use std::io::prelude::*;
use std::io::SeekFrom;
use std::convert::TryInto;
use num_iter::range_step;

use digest::{Digest, OutputSizeUser};
use generic_array::GenericArray;

use merkle_utils::*;
pub use merkle_utils::{node_count, seek_len, BlockRange, HashRange, Consumer};
pub use merkle_utils::{branch_t, block_t};

pub use iter_utils::*;

use thread_pool::{Awaitable, DummyAwaitable};
use thread_pool::{FnEvaluator, DummyEvaluator, ThreadPoolEvaluator};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum HelperErrSignal {
    FileEOF,
    FileReadErr,
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
    fn make_threadpool(name: String, num_threads: usize) -> Self {
        Self::ThreadPool(ThreadPoolEvaluator::new(name, num_threads))
    }
}
impl FnEvaluator for EvaluatorUnion {
    fn compute<T, F>(&self, func: F) -> Box<dyn Awaitable<T>>
    where
        T: 'static + Send,
        F: 'static + Send + Fn() -> T
    {
        match self {
            Self::Dummy(eval) => eval.compute(func),
            Self::ThreadPool(eval) => eval.compute(func)
        }
    }
}

pub fn merkle_hash_file<F, D, C>(mut file: F,
        block_size: block_t, branch: branch_t,
        hash_queue: C, thread_count: usize) -> Option<Box<[u8]>>
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

    let threadpool_obj = match thread_count {
        0 => EvaluatorUnion::make_dummy(),
        _ => EvaluatorUnion::make_threadpool(
            "merkle_tree_threadpool".to_owned(), thread_count)
    };
    let hash_out_result = merkle_tree_file_helper::<_, D, _>(&mut file,
        block_size, block_count, block_range, branch,
        hash_queue, &threadpool_obj).await_();
    let hash_out = hash_out_result.ok()?;
    debug_assert_eq!(file_len, hash_out.1);
    return Some(hash_out.0.to_vec().into_boxed_slice());
}

type HashArray<T> = GenericArray<u8, <T as OutputSizeUser>::OutputSize>;
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

            // Should be optimized out in release mode
            #[cfg(debug_assertions)]
            {
                let current_pos_actual = file.stream_position().unwrap();
                debug_assert_eq!(current_pos_actual, current_pos);
            }


            let file_read_result = read_exact_vec(file, Some(current_pos),
                block_size_as_usize);
            let file_vec: Vec<u8>;

            if file_read_result.is_err() {
                let read_err = DummyAwaitable::new(Err(HelperErrSignal::FileReadErr));
                return Box::new(read_err)
            } else {
                file_vec = file_read_result.unwrap();
            }

            current_pos += file_vec.len() as u64;
            let end_byte_file = current_pos.saturating_sub(1);
            #[cfg(debug_assertions)]
            {
                let end_byte_file_actual = file.stream_position().unwrap().saturating_sub(1);
                debug_assert_eq!(end_byte_file_actual, end_byte_file);
            }
            let hash_future = threadpool.compute(move || {
                let block_range = BlockRange::new(start_block, end_block, true);
                let byte_range = BlockRange::new(start_byte, end_byte_file, true);

                // Prepend 0x00 to the data when hashing
                let mut digest_obj = D::new_with_prefix(&[0x00]);
                digest_obj.update(file_vec.as_slice());
                let hash_result = digest_obj.finalize();
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
            let mut hash_input: Vec<digest::Output<D>> = Vec::with_capacity(
                subhash_awaitables.len());
            for awaitable in subhash_awaitables {
                match awaitable.await_() {
                    Ok(subhash) => {
                        hash_input.push(subhash.0);
                        current_pos = subhash.1;
                    },
                    Err(HelperErrSignal::FileEOF) => {
                        // None -> out of range, and so will the rest
                        // break drops awaitable and rest of subhash_awaitables
                        // The rest of the awaitables are DummyAwaitables,
                        // so dropping them does not hang up a channel
                        break;
                    },
                    Err(HelperErrSignal::FileReadErr) => {
                        let dummy_err = DummyAwaitable::new(Err(HelperErrSignal::FileReadErr));
                        return Box::new(dummy_err);
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

                //let hash_result = D::digest(hash_input.as_slice());
                let mut digest_obj = D::new_with_prefix(&[0x01]);
                for hash in hash_input.iter() {
                    digest_obj.update(hash);
                }
                let hash_result = digest_obj.finalize();
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
