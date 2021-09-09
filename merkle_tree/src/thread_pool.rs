#![forbid(unsafe_code)]

use threadpool::ThreadPool;

use oneshot::Receiver as OneshotReceiver;

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

impl<T> Awaitable<T> for OneshotReceiver<T> {
    fn await_(self: Box<Self>) -> T {
        (*self).recv().unwrap()
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
        let (tx, awaitable) = oneshot::channel();
        self.threadpool.execute(move || {
            let computation_result = func();
            tx.send(computation_result).unwrap();
        });
        Box::new(awaitable)
    }
}