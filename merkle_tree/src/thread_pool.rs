#![forbid(unsafe_code)]

use std::thread::{self, JoinHandle};
use std::sync::{Arc, Mutex, TryLockError};
use std::future::Future;

use std::ops::{Deref, DerefMut};

use crossbeam_channel::{Sender, Receiver, bounded};

use std::fmt::Debug;

#[derive(Debug)]
enum ThreadPoolTaskState<T> {
    Unpolled,
    Polled(std::task::Waker),
    Complete(T),
    ValueExtracted
}

#[derive(Debug)]
pub(crate) struct ThreadPoolTaskHandle<T> {
    state: Arc<Mutex<ThreadPoolTaskState<T>>>
}
impl<T> ThreadPoolTaskHandle<T> {
    fn new(state: Arc<Mutex<ThreadPoolTaskState<T>>>) -> Self {
        Self {state}
    }
}
impl<T: Unpin> Future for ThreadPoolTaskHandle<T> {
    type Output = T;

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        /*
         * Try to get lock for the current state
         * If locked, the thread executor is finishing up (thus still executing)
         * Propagate panics from the task as well if mutex is poisoned
         */
        let mut state_guard = match self.state.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => {return std::task::Poll::Pending},
            Err(TryLockError::Poisoned(e)) => {panic!("Task panicked: {}", e)}
        };
        match *state_guard {
            // The `Future` trait does not specify what `poll` must return after completion
            // Since we already yielded the final value it makes the most sense to panic
            // We should never hit this case anyways if the futures are .awaited
            ThreadPoolTaskState::ValueExtracted => panic!("TaskHandle polled again after completion"),
            ThreadPoolTaskState::Complete(_) => {
                // Replace the stored state and then extract the final value
                let state_w_completed = std::mem::replace(state_guard.deref_mut(), ThreadPoolTaskState::ValueExtracted);
                match state_w_completed {
                    ThreadPoolTaskState::Complete(val) => std::task::Poll::Ready(val),
                    _ => unreachable!()
                }
            },
            ThreadPoolTaskState::Unpolled | ThreadPoolTaskState::Polled(_) => {
                // Replace the stored waker
                let waker = cx.waker();
                *state_guard.deref_mut() = ThreadPoolTaskState::Polled(waker.clone());
                std::task::Poll::Pending
            }
        }
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
    pub fn enqueue_task<T: Unpin+Send+'static>(&self, func: impl FnOnce() -> T + Send + 'static) -> ThreadPoolTaskHandle<T> {
        let tx_handle = self.task_tx.as_ref().unwrap();
        let state_handle = Arc::new(Mutex::new(ThreadPoolTaskState::Unpolled));
        let state_handle_thread = state_handle.clone();
        tx_handle.send(Box::new(move || {
            let return_value = func();

            // After calling user code, update the state accordingly
            let mut state_guard = state_handle_thread.lock().unwrap();
            let mut waker_to_poll = None;
            match state_guard.deref() {
                ThreadPoolTaskState::Unpolled => {
                    // If we weren't polled before then just update the state
                    *state_guard.deref_mut() = ThreadPoolTaskState::Complete(return_value);
                },
                ThreadPoolTaskState::Polled(_) => {
                    // If we were polled before then we need to wake the waker
                    // Replace state and extract the waker to be signalled later
                    let state_polled = std::mem::replace(state_guard.deref_mut(), ThreadPoolTaskState::Complete(return_value));
                    match state_polled {
                        ThreadPoolTaskState::Polled(waker) => {
                            waker_to_poll = Some(waker);
                        },
                        _ => unreachable!()
                    }
                },
                // Neither of these states are reachable if we just finished
                ThreadPoolTaskState::Complete(_) => unreachable!(),
                ThreadPoolTaskState::ValueExtracted => unreachable!(),
            };
            // Send wake signal now, after the result is stored in the state
            if let Some(waker) = waker_to_poll {
                waker.wake();
            }
        })).unwrap();
        ThreadPoolTaskHandle::new(state_handle)
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
    use pollster::block_on;

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

        let mut result_data: Vec<_> = result_handles.into_iter().map(|future| block_on(future)).collect();

        let end_instant = Instant::now();
        let time_duration = end_instant - start_instant;
        println!("{}", time_duration.as_secs_f64());

        result_data.sort();
        assert_eq!(&result_data, &[0, 1, 4, 9, 16, 25, 36, 49, 64]);
        // Time delay should be 100ms*(9.div_ceil(3))+overhead
        //assert!(time_duration < Duration::from_millis(310));
    }
}