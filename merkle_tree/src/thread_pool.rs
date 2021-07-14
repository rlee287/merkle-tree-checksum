use threadpool::ThreadPool;

use std::sync::mpsc::{sync_channel, SyncSender, Receiver};
//use std::sync::{Arc, Mutex, Condvar};
//use arc_swap::ArcSwapOption;

// Like the std Future but do not implement await using poll
pub(crate) trait Awaitable<T> {
    fn await_(self) -> T;
}

// A dummy awaitable that is immediately ready
#[derive(Debug, Clone)]
pub(crate) struct DummyAwaitable<T> {
    value: T
}
impl<T> DummyAwaitable<T> {
    pub fn new(val: T) -> DummyAwaitable<T> {
        DummyAwaitable {value: val}
    }
}
impl<T> Awaitable<T> for DummyAwaitable<T> {
    fn await_(self) -> T {
        self.value
    }
}

#[derive(Debug)]
struct RecvAwaitable<T> {
    recv_channel: Receiver<T>
}
impl<T> RecvAwaitable<T> {
    pub fn new() -> (SyncSender<T>, RecvAwaitable<T>) {
        let (tx, rx) = sync_channel(1);
        (tx, RecvAwaitable{recv_channel: rx})
    }
}
impl<T> Awaitable<T> for RecvAwaitable<T> {
    fn await_(self) -> T {
        self.recv_channel.recv().unwrap()
    }
}
// TODO: using mutexes and condvars may have less overhead if I can figure out how to split the read and write halves

pub(crate) trait PoolEvaluator {
    fn compute<T, F>(&self, func: F) -> Box<dyn Awaitable<T>>
    where
        T: 'static + Send,
        F: 'static + Send + Fn() -> T;
}

#[derive(Debug)]
pub(crate) struct DummyEvaluator {}
impl DummyEvaluator {
    fn new() -> DummyEvaluator {
        DummyEvaluator {}
    }
}
impl PoolEvaluator for DummyEvaluator {
    fn compute<T, F> (&self, func: F) -> Box<dyn Awaitable<T>> 
    where
        T: 'static,
        F: Fn() -> T
    {
        Box::new(DummyAwaitable::new(func()))
    }
}

pub(crate) struct ThreadPoolEvaluator {
    threadpool: ThreadPool
}
impl ThreadPoolEvaluator {
    pub fn new(thread_count: usize) -> ThreadPoolEvaluator {
        ThreadPoolEvaluator{threadpool: ThreadPool::new(thread_count)}
    }
}
// TODO: Rust 1.53 bug report of misleading error message without T: Send
impl PoolEvaluator for ThreadPoolEvaluator {
    fn compute<T, F> (&self, func: F) -> Box<dyn Awaitable<T>> 
    where
        T: 'static + Send,
        F: 'static + Send + Fn() -> T
    {
        let (tx, awaitable) = RecvAwaitable::new();
        self.threadpool.execute(move || {
            let computation_result = func();
            tx.send(computation_result).unwrap();
        });
        Box::new(awaitable)
    }
}