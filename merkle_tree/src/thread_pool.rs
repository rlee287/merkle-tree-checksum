use threadpool::ThreadPool;

use std::sync::mpsc::{sync_channel, SyncSender, Receiver};

// Like the std Future but do not implement await using poll
// Remove the mut part?
pub(crate) trait Awaitable<T> {
    fn await_(&mut self) -> &T;
}

impl<T, A: Awaitable<T>> Awaitable<T> for Box<A> {
    fn await_(&mut self) -> &T {
        A::await_(self)
    }
}

/*pub(crate) struct BoxedAwaitable<T> {
    inner: Box<dyn Awaitable<T>>
}
impl<T> BoxedAwaitable<T> {
    pub fn new(inner: Box<dyn Awaitable<T>>) -> BoxedAwaitable<T>{
        BoxedAwaitable {inner}
    }
}
impl<T> Awaitable<T> for BoxedAwaitable<T> {
    fn await_(self) -> T {
        (*self.inner).await_()
    }
}*/

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
    fn await_(&mut self) -> &T {
        &self.value
    }
}

#[derive(Debug)]
pub(crate) struct RecvAwaitable<T> {
    recv_channel: Receiver<T>,
    recv_storage: Option<T>
}
impl<T> RecvAwaitable<T> {
    pub fn new() -> (SyncSender<T>, RecvAwaitable<T>) {
        let (tx, rx) = sync_channel(1);
        (tx, RecvAwaitable{recv_channel: rx, recv_storage: None})
    }
}
impl<T> Awaitable<T> for RecvAwaitable<T> {
    fn await_(&mut self) -> &T {
        if self.recv_storage.is_none() {
            let recv_value = self.recv_channel.recv().unwrap();
            self.recv_storage = Some(recv_value);
        }
        match &self.recv_storage {
            Some(val) => val,
            None => {
                unreachable!()
            }
        }
    }
}
// TODO: using mutexes and condvars may have less overhead if I can figure out how to split the read and write halves

pub(crate) trait PoolEvaluator {
    fn compute<T, F>(&self, func: F) -> Box<dyn Awaitable<T>>
    where
        T: 'static + Send,
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
    pub fn new(thread_count: usize) -> ThreadPoolEvaluator {
        ThreadPoolEvaluator{threadpool: ThreadPool::new(thread_count)}
    }
}
// TODO: Rust 1.53 bug report of misleading error message without T: Send?
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