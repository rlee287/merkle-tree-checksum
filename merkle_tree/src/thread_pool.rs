#![forbid(unsafe_code)]

use std::thread;

use oneshot::Receiver as OneshotReceiver;
use crossbeam_channel::{Sender, bounded};

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

pub(crate) trait FnEvaluator {
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
impl FnEvaluator for DummyEvaluator {
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
    thread_handles: Vec<Option<thread::JoinHandle<()>>>,
    send_fn: Option<Sender<Box<dyn FnOnce() + Send>>>
    //threads_active: AtomicUsize
}
impl ThreadPoolEvaluator {
    pub fn new(name: String, thread_count: usize) -> ThreadPoolEvaluator {
        let mut handle_vec = Vec::with_capacity(thread_count);
        let (tx, rx) = bounded::<Box<dyn FnOnce() + Send>>(2*thread_count);
        for i in 0..thread_count {
            let rx_copy = rx.clone();
            handle_vec.push(Some(thread::Builder::new()
                .name(format!("{}-{}", name, i))
                .spawn(move || {
                    while let Ok(func) = rx_copy.recv() {
                        func();
                    }
                })
            .unwrap()))
        }
        ThreadPoolEvaluator{
            thread_handles: handle_vec,
            send_fn: Some(tx)
        }
    }
}
// TODO: Rust 1.53 bug report of misleading error message without T: Send?
#[allow(unused_must_use)]
impl FnEvaluator for ThreadPoolEvaluator {
    fn compute<T, F> (&self, func: F) -> Box<dyn Awaitable<T>>
    where
        T: 'static + Send,
        F: 'static + Send + Fn() -> T
    {
        let (tx, awaitable) = oneshot::channel();
        if let Some(ref sender) = self.send_fn {
            sender.send(Box::new(move || {
                let computation_result = func();
                // Deliberately ignore error case of other side hanging up
                tx.send(computation_result);
            }));
        } else {
            panic!("ThreadPoolEvaluator sender is None");
        }
        Box::new(awaitable)
    }
}
impl Drop for ThreadPoolEvaluator {
    fn drop(&mut self) {
        drop(self.send_fn.take().unwrap());
        for handle in &mut self.thread_handles {
            handle.take().unwrap().join().unwrap();
        }
    }
}