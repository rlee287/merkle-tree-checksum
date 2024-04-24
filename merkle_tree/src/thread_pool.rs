#![forbid(unsafe_code)]

use ambassador::delegatable_trait;

use std::thread::{self, JoinHandle};
use std::thread::Result as ThreadResult;
use std::panic::{catch_unwind, UnwindSafe};
use std::sync::{Arc, Mutex, Condvar};

use crossbeam_channel::{Sender, Receiver, bounded};

use std::fmt::Debug;

#[delegatable_trait]
pub(crate) trait Joinable<T> {
    fn join(self) -> T;
}

#[derive(Debug)]
pub(crate) struct ThreadPoolTaskHandle<T> {
    thread_out: Arc<Mutex<Option<T>>>,
    thread_waiter: Arc<Condvar>
}
impl<T> ThreadPoolTaskHandle<T> {
    fn new(thread_out: Arc<Mutex<Option<T>>>, thread_waiter: Arc<Condvar>) -> Self {
        Self {thread_out, thread_waiter}
    }
}
impl<T> Joinable<T> for ThreadPoolTaskHandle<T> {
    fn join(self) -> T {
        /*
         * Try to get lock for the current state
         * If locked, the thread executor is finishing up (thus still executing)
         * Propagate panics from the task as well if mutex is poisoned
         */
        let state_guard = self.thread_out.lock().unwrap();
        // Use condvar to block until task is complete
        let mut state_guard = self.thread_waiter.wait_while(state_guard, |out| out.is_none()).unwrap();
        // The wrapped state must be Some() by now
        state_guard.take().unwrap()
    }
}

#[derive(Debug)]
pub(crate) struct DummyHandle<T> {
    data: T
}
impl<T> DummyHandle<T> {
    pub fn new(data: T) -> Self {
        Self {data}
    }
}
impl<T> Joinable<T> for DummyHandle<T> {
    fn join(self) -> T {
        self.data
    }
}

#[derive(Debug)]
pub(crate) struct EagerAsyncThreadPool {
    thread_handles: Vec<JoinHandle<()>>,
    task_tx: Option<Sender<Box<dyn FnOnce()+Send>>>
}
impl EagerAsyncThreadPool {
    pub fn new(thread_count: usize) -> Self {
        let (tx, rx) = bounded(16);
        let mut handle_vec = Vec::with_capacity(thread_count);
        for i in 0..thread_count {
            let rx_copy: Receiver<Box<dyn FnOnce()+Send>> = rx.clone();
            handle_vec.push(thread::Builder::new()
                .name(format!("eager_async_threadpool-{}", i))
                .spawn(move || {
                    while let Ok(func) = rx_copy.recv() {
                        func();
                    }
                })
            .unwrap());
        }
        Self {thread_handles: handle_vec, task_tx: Some(tx)}
    }
    pub fn enqueue_task<T: Send+'static>(&self, func: impl FnOnce() -> T + UnwindSafe + Send + 'static) -> ThreadPoolTaskHandle<ThreadResult<T>> {
        let tx_handle = self.task_tx.as_ref().unwrap();
        let state_handle = Arc::new(Mutex::new(None));
        let state_waiter = Arc::new(Condvar::new());
        let state_handle_thread = state_handle.clone();
        let state_waiter_thread = state_waiter.clone();

        tx_handle.send(Box::new(move || {
            let return_value = catch_unwind(func);

            // After calling user code, update the state accordingly
            let mut state_guard = state_handle_thread.lock().unwrap();
            *state_guard = Some(return_value);
            // Send wake signal now, after the result is stored in the state
            // Either notify_one or notify_all work because there should only be
            // one other handle
            state_waiter_thread.notify_all();
        })).unwrap();
        ThreadPoolTaskHandle::new(state_handle, state_waiter)
    }
}

impl Drop for EagerAsyncThreadPool {
    fn drop(&mut self) {
        // Drop the send handle, which should hang up the recv channels in the threads
        self.task_tx = None;
        // Join the threads to wait for tasks to finish
        let handle_vec = std::mem::replace(&mut self.thread_handles, Vec::new());
        for handle in handle_vec {
            handle.join().unwrap();
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::time::{Duration, Instant};
    use std::thread::sleep;

    #[test]
    fn test_threadpool_basic() {
        let threadpool = EagerAsyncThreadPool::new(3);
        let mut result_handles: Vec<_> = Vec::new();

        let start_instant = Instant::now();

        for i in 0..=8 {
            result_handles.push(threadpool.enqueue_task(move || {
                sleep(Duration::from_millis(100));
                i*i
            }));
        }

        let mut result_data: Vec<_> = result_handles.into_iter().map(|future| future.join()).collect::<Result<Vec<_>, _>>().unwrap();

        let end_instant = Instant::now();
        let time_duration = end_instant - start_instant;
        println!("{}", time_duration.as_secs_f64());

        result_data.sort();
        assert_eq!(&result_data, &[0, 1, 4, 9, 16, 25, 36, 49, 64]);
        // Time delay should be 100ms*(9.div_ceil(3))+overhead
        //assert!(time_duration < Duration::from_millis(310));
    }
}