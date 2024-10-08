#![forbid(unsafe_code)]

use std::thread::{self, JoinHandle};
use std::thread::Result as ThreadResult;
use std::panic::{catch_unwind, UnwindSafe};
use std::sync::{Arc, Mutex, Condvar};

#[cfg(feature = "hwlocality")]
use std::sync::OnceLock;
#[cfg(feature = "hwlocality")]
use hwlocality::Topology;
#[cfg(feature = "hwlocality")]
use hwlocality::errors::RawHwlocError;
#[cfg(feature = "hwlocality")]
use hwlocality::topology::support::{DiscoverySupport, FeatureSupport};
#[cfg(feature = "hwlocality")]
use hwlocality::object::depth::NormalDepth;
#[cfg(feature = "hwlocality")]
use hwlocality::topology::DistributeFlags;
#[cfg(feature = "hwlocality")]
use hwlocality::cpu::cpuset::CpuSet;
#[cfg(feature = "hwlocality")]
use hwlocality::cpu::binding::CpuBindingFlags;

use crossbeam_deque::{Injector, Worker, Stealer};

use std::fmt::Debug;
use std::sync::atomic::{AtomicU32, Ordering};

#[cfg(feature = "hwlocality")]
static TOPOLOGY: OnceLock<Result<Topology, RawHwlocError>> = OnceLock::new();

pub(crate) trait Joinable<T> {
    fn join(self) -> T;
}

#[derive(Debug)]
pub(crate) struct ThreadPoolTaskHandle<T> {
    // Holds the result from the thread, when it's ready
    thread_out: Arc<Mutex<Option<T>>>,
    // Condition variable used to block on the result being ready
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

#[cfg(feature = "hwlocality")]
fn get_cpu_affinities(topology: &Topology, thread_count: usize) -> Option<Vec<CpuSet>> {
    // Check that we have the required featureset
    if !topology.supports(FeatureSupport::discovery, DiscoverySupport::pu_count) {
        return None;
    }
    let Some(cpu_support) = topology.feature_support().cpu_binding() else {
        return None;
    };
    if !(cpu_support.get_thread() && cpu_support.set_thread()) {
        return None;
    }
    topology.distribute_items(
        &[&topology.root_object()],
        thread_count,
        NormalDepth::MAX,
        DistributeFlags::empty()).ok()
}

#[derive(Debug)]
pub(crate) struct EagerThreadPool {
    thread_handles: Vec<JoinHandle<()>>,
    task_injector: Arc<Injector<Box<dyn FnOnce()+Send>>>,
    // Lowest bit cleared when waiting on tasks to be enqueued
    // Highest bit set to signal pool shutdown
    // TODO: unsure if consistent total ordering is needed, using SeqCst just in case
    task_status: Arc<AtomicU32>,
}
impl EagerThreadPool {
    const TASK_WAITING_BITMASK: u32 = 0x00000001;
    const POOL_SHUTDOWN_BITMASK: u32 = 0x80000000;
    // Lightly modified from crossbeam-deque documentation
    // These don't take &self because we want to call these inside threads
    fn find_task<T>(
        local: &Worker<T>,
        global: &Injector<T>,
        stealers: &[Stealer<T>],
    ) -> Option<T> {
        // Pop a task from the local queue, if not empty.
        // Otherwise, look for a task elsewhere.
        local.pop().or_else(|| Self::find_nonlocal_task(local, global, stealers))
    }
    fn find_nonlocal_task<T>(
        local: &Worker<T>,
        global: &Injector<T>,
        stealers: &[Stealer<T>],
    ) -> Option<T> {
        // Look for a task elsewhere, assuming local queue is empty.
        std::iter::repeat_with(|| {
            // Try stealing a batch of tasks from the global queue.
            global.steal_batch_and_pop(local)
                // Or try stealing a task from one of the other threads.
                .or_else(|| stealers.iter().map(|s| s.steal()).collect())
        })
        // Loop while no task was stolen and any steal operation needs to be retried.
        .find(|s| !s.is_retry())
        // Extract the stolen task, if there is one.
        .and_then(|s| s.success())
    }
    pub fn new(thread_count: usize) -> Self {
        let injector: Arc<Injector<Box<dyn FnOnce() + Send>>> = Arc::new(Injector::new());
        let task_status = Arc::new(AtomicU32::new(0));

        // Fail gracefully if we can't get CPU binding info for whatever reason
        let mut handle_vec = Vec::with_capacity(thread_count);
        #[cfg(feature = "hwlocality")]
        let thread_binding_infos = {
            let topology = TOPOLOGY.get_or_init(Topology::new);
            match topology {
                Ok(topo_ref) => {
                    let cpusets = get_cpu_affinities(&topo_ref, thread_count);
                    match cpusets {
                        Some(vec) => Some(vec),
                        None => None
                    }
                }
                Err(_) => None
            }
        };

        // Create worker and stealer queues
        let mut worker_vec = Vec::new();
        for _ in 0..thread_count {
            let worker = Worker::new_fifo();
            worker_vec.push(worker);
        }

        let stealer_vec = Arc::new(worker_vec.iter().map(|w| w.stealer()).collect::<Vec<_>>());

        for i in 0..thread_count {
            #[cfg(feature = "hwlocality")]
            let thread_binding_info = thread_binding_infos.as_ref()
                .map(|vec| {
                    let mut cpuset = vec[i].clone();
                    cpuset.singlify();
                    cpuset
                });

            let task_status_thread = task_status.clone();
            let worker = worker_vec.pop().unwrap();
            let injector_thread = injector.clone();
            let stealer_vec_thread = stealer_vec.clone();

            handle_vec.push(thread::Builder::new()
                .name(format!("eager_threadpool-{}", i))
                .spawn(move || {
                    #[cfg(feature = "hwlocality")]
                    if let Some(cpuset) = thread_binding_info {
                        let tid = hwlocality::current_thread_id();
                        let topo = TOPOLOGY.get_or_init(Topology::new).as_ref().unwrap();

                        // Do the actual thread binding-if this fails we at most
                        // have degraded performance
                        let _ = topo.bind_thread_cpu(tid, &cpuset, CpuBindingFlags::empty());
                    }
                    loop {
                        match Self::find_task(&worker, &injector_thread, &stealer_vec_thread) {
                            Some(func) => (func)(),
                            None => {
                                // Task could have been enqueued here, such that we incorrectly cleared the waiting flag...
                                let old_task_status = task_status_thread.fetch_and(!Self::TASK_WAITING_BITMASK, Ordering::SeqCst);
                                // ...so check other places one more time before blocking
                                if let Some(func) = Self::find_nonlocal_task(&worker, &injector_thread, &stealer_vec_thread) {
                                    (func)();
                                } else if (old_task_status & Self::POOL_SHUTDOWN_BITMASK) != 0 {
                                    // Break out of loop on shutdown+no tasks left
                                    // Can check against old value because our fetch_and would not touch that bit
                                    break;
                                } else {
                                    // If this wakes spuriously, then we check for tasks again
                                    // We also rely on wake to recheck pool status and finish any remaining tasks on shutdown
                                    // Only block if no tasks+not doing shutdown
                                    atomic_wait::wait(&task_status_thread, 0);
                                }
                            }
                        }
                    }
                })
            .unwrap());
        }
        Self {thread_handles: handle_vec, task_injector: injector, task_status}
    }
    pub fn enqueue_task<T: Send+'static>(&self, func: impl FnOnce() -> T + UnwindSafe + Send + 'static) -> ThreadPoolTaskHandle<ThreadResult<T>> {
        let state_handle = Arc::new(Mutex::new(None));
        let state_waiter = Arc::new(Condvar::new());
        let state_handle_thread = state_handle.clone();
        let state_waiter_thread = state_waiter.clone();

        self.task_injector.push(Box::new(move || {
            let return_value = catch_unwind(func);

            // After calling user code, update the state accordingly
            let mut state_guard = state_handle_thread.lock().unwrap();
            *state_guard = Some(return_value);
            // Send wake signal now, after the result is stored in the state
            // Either notify_one or notify_all work because there should only be
            // one other handle
            state_waiter_thread.notify_all();
        }));
        self.task_status.fetch_or(Self::TASK_WAITING_BITMASK, Ordering::SeqCst);
        // Enqueued one task -> wake one thread, avoiding thundering herd
        // Spurious wakeups reduce impact of potential incorrect-blocking bugs in threadpool
        atomic_wait::wake_one(Arc::as_ptr(&self.task_status));

        ThreadPoolTaskHandle::new(state_handle, state_waiter)
    }
}

impl Drop for EagerThreadPool {
    fn drop(&mut self) {
        // Signal threadpool winding down, including that tasks are waiting
        // Even if there are no more tasks we still want threads to check again
        self.task_status.store(Self::POOL_SHUTDOWN_BITMASK | Self::TASK_WAITING_BITMASK, Ordering::SeqCst);
        // Wake all threads that may be waiting for new tasks
        atomic_wait::wake_all(Arc::as_ptr(&self.task_status));
        // Join the threads to wait for tasks to finish
        let handle_vec = std::mem::take(&mut self.thread_handles);
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
        let threadpool = EagerThreadPool::new(3);
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