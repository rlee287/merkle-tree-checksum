#![forbid(unsafe_code)]

use threadpool::ThreadPool;

use std::sync::mpsc::{sync_channel, SyncSender, Receiver};
use std::sync::{Mutex, Condvar};
use crate::merkle_utils::Consumer;

use std::marker::PhantomData;
use std::fmt::Debug;

// Like the std Future but do not implement await using poll
pub(crate) trait Awaitable<T> {
    fn await_(self: Box<Self>) -> T;
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
    fn await_(self: Box<Self>) -> T {
        self.value
    }
}

#[derive(Debug)]
pub struct ConsumeOnce<T, C>
where
    T: Debug,
    C: Consumer<T>
{
    phantom_t: PhantomData<T>,
    sender: C
}
impl<T, C: Consumer<T>> ConsumeOnce<T, C>
where
    T: Debug,
    C: Consumer<T>
{
    pub fn new(sender: C) -> ConsumeOnce<T, C> {
        ConsumeOnce{phantom_t: PhantomData::default(), sender}
    }
    pub fn send(self, item: T) -> Result<(), T> {
        self.sender.accept(item)
    }
}

#[derive(Debug)]
pub(crate) struct RecvAwaitable<T> {
    recv_channel: Receiver<T>
}
pub(crate) fn new_recv_awaitable<T: Debug>() -> (ConsumeOnce<T, SyncSender<T>>, RecvAwaitable<T>) {
    let (tx, rx) = sync_channel(1);
    (ConsumeOnce::new(tx), RecvAwaitable {recv_channel: rx})
}
impl<T: Debug> Awaitable<T> for RecvAwaitable<T> {
    fn await_(self: Box<Self>) -> T {
        self.recv_channel.recv().unwrap()
    }
}
// TODO: using mutexes and condvars may have less overhead if I can figure out how to split the read and write halves

pub(crate) trait PoolEvaluator {
    fn compute<T, F>(&self, func: F) -> Box<dyn Awaitable<T>>
    where
        T: 'static + Send + Debug,
        F: Fn() -> T + 'static + Send,
    ;
}

// Dummy evaluator that runs everything in-sync
#[derive(Debug)]
pub(crate) struct DummyEvaluator {}
impl DummyEvaluator {
    pub fn new() -> DummyEvaluator {
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

// Evaluator using a thread pool
#[derive(Debug)]
pub(crate) struct ThreadPoolEvaluator {
    threadpool: ThreadPool
}
impl ThreadPoolEvaluator {
    pub fn new(name: String, thread_count: usize) -> ThreadPoolEvaluator {
        ThreadPoolEvaluator{
            threadpool: ThreadPool::with_name(name, thread_count)
        }
    }
}
// TODO: Rust 1.53 bug report of misleading error message without T: Send?
impl PoolEvaluator for ThreadPoolEvaluator {
    fn compute<T, F> (&self, func: F) -> Box<dyn Awaitable<T>>
    where
        T: 'static + Send + Debug,
        F: 'static + Send + Fn() -> T
    {
        let (tx, awaitable) = new_recv_awaitable();
        self.threadpool.execute(move || {
            let computation_result = func();
            tx.send(computation_result).unwrap();
        });
        Box::new(awaitable)
    }
}