#![forbid(unsafe_code)]

mod merkle_utils;
mod iter_utils;
mod thread_pool;

use std::thread::Result as ThreadResult;
use std::panic::UnwindSafe;

use thread_pool::{EagerThreadPool, Joinable};

use std::io::prelude::*;
use std::io::SeekFrom;
use std::convert::TryInto;
use num_iter::range_step;

use digest::{Digest, OutputSizeUser};
use generic_array::GenericArray;

use merkle_utils::*;
pub use merkle_utils::{node_count, seek_len, BlockRange, HashData, HashRange, Consumer};
pub use merkle_utils::{branch_t, block_t};

pub use iter_utils::*;
use thread_pool::{DummyHandle, ThreadPoolTaskHandle};

use ambassador::Delegate;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum HelperErrSignal {
    FileEOF,
    FileReadErr,
    ConsumerErr
}

#[derive(Debug)]
#[derive(Delegate)]
#[delegate(Joinable<T>)]
enum EitherJoinable<T> {
    Dummy(DummyHandle<T>),
    Thread(ThreadPoolTaskHandle<T>)
}
impl<T> From<DummyHandle<T>> for EitherJoinable<T> {
    fn from(value: DummyHandle<T>) -> Self {
        Self::Dummy(value)
    }
}
impl<T> From<ThreadPoolTaskHandle<T>> for EitherJoinable<T> {
    fn from(value: ThreadPoolTaskHandle<T>) -> Self {
        Self::Thread(value)
    }
}

pub fn merkle_hash_file<F, D, C>(mut file: F,
        block_size: block_t, branch: branch_t,
        hash_queue: C, thread_count: usize) -> Option<HashData<64>>
where
    F: Read + Seek,
    D: Digest + 'static,
    <D::OutputSize as generic_array::ArrayLength<u8>>::ArrayType: UnwindSafe,
    C: Consumer<HashRange> + Clone + Send + UnwindSafe + 'static
{
    assert!(block_size != 0);
    assert!(branch >= 2);
    assert!(<D as Digest>::output_size() <= merkle_utils::MAX_HASH_LEN);
    file.seek(SeekFrom::Start(0)).unwrap();
    let file_len = seek_len(&mut file);
    let block_count = match file_len.div_ceil(block_size.into()) {
        0 => 1,
        n => n
    };
    let effective_block_count = exp_ceil_log(block_count, branch);
    let block_range = BlockRange::new(0, effective_block_count, false);

    let threadpool_obj = match thread_count {
        0 => None,
        n => Some(EagerThreadPool::new(n))
    };
    let hash_out_result = merkle_tree_file_helper::<_, D, _>(&mut file,
        block_size, block_count, block_range, branch,
        hash_queue, threadpool_obj.as_ref()).join().unwrap();
    let hash_out = hash_out_result.ok()?;
    debug_assert_eq!(file_len, hash_out.1);
    return Some(HashData::try_new(&hash_out.0).unwrap());
}

type HashArray<T> = GenericArray<u8, <T as OutputSizeUser>::OutputSize>;
// Second element of tuple is seek position
type HashResult<T> = Result<(HashArray<T>, u64), HelperErrSignal>;

fn merkle_tree_file_helper<F, D, C>(file: &mut F,
        block_size: block_t, block_count: u64, block_range: BlockRange,
        branch: branch_t,
        hash_queue: C,
        threadpool: Option<&EagerThreadPool>)
        -> EitherJoinable<ThreadResult<HashResult<D>>>
where
    F: Read + Seek,
    D: Digest + 'static,
    <D::OutputSize as generic_array::ArrayLength<u8>>::ArrayType: UnwindSafe,
    C: Consumer<HashRange> + Clone + Send + UnwindSafe + 'static,
{
    assert!(<D as Digest>::output_size() <= merkle_utils::MAX_HASH_LEN);
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

            if let Ok(vec) = file_read_result {
                file_vec = vec;
            } else {
                // Err() for returned error, Ok() for no panic
                let read_err = DummyHandle::new(Ok(Err(HelperErrSignal::FileReadErr)));
                return read_err.into()
            }

            current_pos += file_vec.len() as u64;
            let end_byte_file = current_pos.saturating_sub(1);
            #[cfg(debug_assertions)]
            {
                let end_byte_file_actual = file.stream_position().unwrap().saturating_sub(1);
                debug_assert_eq!(end_byte_file_actual, end_byte_file);
            }

            let hash_closure = move || {
                let block_range = BlockRange::new(start_block, end_block, true);
                let byte_range = BlockRange::new(start_byte, end_byte_file, true);

                // Prepend 0x00 to the data when hashing
                let mut digest_obj = D::new_with_prefix([0x00]);
                digest_obj.update(file_vec.as_slice());
                let hash_result = digest_obj.finalize();
                let block_hash_result = HashRange::new(block_range, byte_range,HashData::try_new(&hash_result).unwrap());

                if hash_queue.accept(block_hash_result).is_ok() {
                    return Ok((hash_result, current_pos));
                } else {
                    return Err(HelperErrSignal::ConsumerErr);
                }
            };
            let hash_future = match threadpool {
                Some(threadpool) => threadpool.enqueue_task(hash_closure).into(),
                // Ok() for no panic
                None => DummyHandle::new(Ok(hash_closure())).into()
            };
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
                subhash_awaitables.len()*<D as Digest>::output_size());
            for awaitable in subhash_awaitables {
                match awaitable.join().unwrap() {
                    Ok(subhash) => {
                        hash_input.extend(subhash.0);
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
                        // Err() for returned error, Ok() for no panic
                        let dummy_err = DummyHandle::new(Ok(Err(HelperErrSignal::FileReadErr)));
                        return dummy_err.into();
                    },
                    Err(HelperErrSignal::ConsumerErr) => {
                        // Err() for returned error, Ok() for no panic
                        let dummy_err = DummyHandle::new(Ok(Err(HelperErrSignal::ConsumerErr)));
                        return dummy_err.into();
                    }
                }
            }
            let end_byte_file = current_pos.saturating_sub(1);
            #[cfg(debug_assertions)]
            {
                let end_byte_file_actual = file.stream_position().unwrap().saturating_sub(1);
                debug_assert_eq!(end_byte_file_actual, end_byte_file);
            }
            let hash_closure = move || {
                let block_range = BlockRange::new(start_block, end_block, true);
                let byte_range = BlockRange::new(start_byte, end_byte_file, true);

                let mut digest_obj = D::new_with_prefix([0x01]);
                digest_obj.update(hash_input.as_slice());
                let hash_result = digest_obj.finalize();
                let block_hash_result = HashRange::new(block_range, byte_range, HashData::try_new(&hash_result).unwrap());

                if hash_queue.accept(block_hash_result).is_ok() {
                    return Ok((hash_result, current_pos));
                } else {
                    return Err(HelperErrSignal::ConsumerErr);
                }
            };
            let hash_future = match threadpool {
                Some(threadpool) => threadpool.enqueue_task(hash_closure).into(),
                // Ok() for no panic
                None => DummyHandle::new(Ok(hash_closure())).into()
            };
            return hash_future;
        }
    } else {
        // Err() for returned error, Ok() for no panic
        let dummy_err = DummyHandle::new(Ok(Err(HelperErrSignal::FileEOF)));
        return dummy_err.into();
    }
}
