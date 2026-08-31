//! Linux process-signal bridge for the production route runtime.
//!
//! The installing thread blocks `SIGINT` and `SIGTERM` before the worker is
//! spawned. Threads created afterwards inherit that mask, so the composition
//! root must install this bridge before it creates any other worker. The
//! signal worker consumes the blocked signals through `signalfd` and forwards
//! only a monotonic shutdown request to the route runtime.

use crate::RouteShutdownTokenV1;
use nix::sys::signal::{SigSet, SigmaskHow, Signal};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const SIGNAL_POLL_INTERVAL_V1: Duration = Duration::from_millis(10);

/// Maximum time an explicit teardown waits for the signal worker to finish.
pub const PRODUCTION_SIGNAL_JOIN_TIMEOUT_V1: Duration = Duration::from_secs(1);

const JOIN_POLL_INTERVAL_V1: Duration = Duration::from_millis(2);

static SIGNAL_BRIDGE_ACTIVE_V1: AtomicBool = AtomicBool::new(false);

/// Fail-closed error from production signal installation or teardown.
///
/// Variants deliberately omit OS error values, paths and runtime payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProductionSignalBridgeErrorV1 {
    /// A process signal bridge is already active or its failed teardown left
    /// the process signal mask intentionally blocked.
    #[error("production signal bridge is already active")]
    AlreadyInstalled,
    /// The calling thread's signal mask could not be changed.
    #[error("production signal mask is unavailable")]
    SignalMaskUnavailable,
    /// The Linux signal descriptor could not be created.
    #[error("production signal consumer is unavailable")]
    SignalConsumerUnavailable,
    /// The bounded signal worker could not be spawned.
    #[error("production signal worker is unavailable")]
    WorkerSpawnUnavailable,
    /// Reading or validating a consumed signal failed.
    #[error("production signal consumption failed")]
    SignalConsumptionFailed,
    /// The route runtime rejected the monotonic shutdown request.
    #[error("production shutdown control is unavailable")]
    ShutdownControlUnavailable,
    /// The worker did not finish within the fixed teardown bound.
    #[error("production signal worker teardown timed out")]
    WorkerJoinTimedOut,
    /// The worker panicked instead of returning a typed result.
    #[error("production signal worker terminated unexpectedly")]
    WorkerTerminatedUnexpectedly,
    /// The installing thread's exact previous mask could not be restored.
    #[error("production signal mask restoration failed")]
    SignalMaskRestoreFailed,
}

/// Process-lifetime bridge from blocked Linux signals to route shutdown.
///
/// This guard is intentionally neither `Send` nor `Sync`: POSIX signal masks
/// are thread-local, so teardown and restoration must happen on the same
/// thread that installed the bridge. Call [`Self::install`] before spawning
/// any runtime, RPC, Relay or actuator worker so every child inherits the
/// blocked `SIGINT`/`SIGTERM` mask.
pub struct ProductionSignalBridgeV1 {
    worker: Option<JoinHandle<Result<(), ProductionSignalBridgeErrorV1>>>,
    stop: Option<Sender<()>>,
    previous_mask: Option<SigSet>,
    failed_closed: bool,
    thread_bound: PhantomData<Rc<()>>,
}

impl core::fmt::Debug for ProductionSignalBridgeV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("ProductionSignalBridgeV1([redacted])")
    }
}

impl ProductionSignalBridgeV1 {
    /// Blocks `SIGINT`/`SIGTERM` and starts their sole process consumer.
    ///
    /// Installation is globally exclusive. If setup fails after blocking the
    /// signals, this function restores the exact preceding mask. If that
    /// restoration itself fails, exclusivity remains latched so no later
    /// caller can mistake the process for a correctly installed bridge.
    pub fn install(shutdown: RouteShutdownTokenV1) -> Result<Self, ProductionSignalBridgeErrorV1> {
        SIGNAL_BRIDGE_ACTIVE_V1
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ProductionSignalBridgeErrorV1::AlreadyInstalled)?;

        let watched = watched_signals();
        let previous_mask = match watched.thread_swap_mask(SigmaskHow::SIG_BLOCK) {
            Ok(mask) => mask,
            Err(_) => {
                SIGNAL_BRIDGE_ACTIVE_V1.store(false, Ordering::Release);
                return Err(ProductionSignalBridgeErrorV1::SignalMaskUnavailable);
            }
        };

        let signal_fd =
            match SignalFd::with_flags(&watched, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK) {
                Ok(signal_fd) => signal_fd,
                Err(_) => {
                    return Err(failed_install(
                        &previous_mask,
                        ProductionSignalBridgeErrorV1::SignalConsumerUnavailable,
                    ));
                }
            };

        let (stop_tx, stop_rx) = mpsc::channel();
        let worker = match thread::Builder::new()
            .name("dom-signal-v1".to_owned())
            .spawn(move || run_signal_worker(signal_fd, shutdown, stop_rx))
        {
            Ok(worker) => worker,
            Err(_) => {
                return Err(failed_install(
                    &previous_mask,
                    ProductionSignalBridgeErrorV1::WorkerSpawnUnavailable,
                ));
            }
        };

        Ok(Self {
            worker: Some(worker),
            stop: Some(stop_tx),
            previous_mask: Some(previous_mask),
            failed_closed: false,
            thread_bound: PhantomData,
        })
    }

    /// Stops the consumer within the fixed bound and restores the prior mask.
    ///
    /// A timeout, panic or worker failure deliberately leaves the watched
    /// signals blocked and keeps global installation latched. This prevents a
    /// teardown failure from unexpectedly reactivating the default terminating
    /// signal action. The composition root must join every worker spawned
    /// after installation before calling this method, because their inherited
    /// masks cannot be restored by another thread. A successful call is
    /// idempotent.
    pub fn shutdown(&mut self) -> Result<(), ProductionSignalBridgeErrorV1> {
        if self.failed_closed {
            return Err(ProductionSignalBridgeErrorV1::WorkerTerminatedUnexpectedly);
        }

        if self.previous_mask.is_none() {
            return Ok(());
        }

        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }

        if let Some(worker) = self.worker.as_ref() {
            wait_until_finished(worker)?;
        }

        if let Some(worker) = self.worker.take() {
            match worker.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    self.failed_closed = true;
                    return Err(error);
                }
                Err(_) => {
                    self.failed_closed = true;
                    return Err(ProductionSignalBridgeErrorV1::WorkerTerminatedUnexpectedly);
                }
            }
        }

        let previous_mask = self
            .previous_mask
            .as_ref()
            .ok_or(ProductionSignalBridgeErrorV1::SignalMaskRestoreFailed)?;
        if previous_mask.thread_set_mask().is_err() {
            return Err(ProductionSignalBridgeErrorV1::SignalMaskRestoreFailed);
        }

        self.previous_mask = None;
        SIGNAL_BRIDGE_ACTIVE_V1.store(false, Ordering::Release);
        Ok(())
    }

    #[cfg(test)]
    fn worker_pthread_for_test(&self) -> nix::sys::pthread::Pthread {
        use std::os::unix::thread::JoinHandleExt as _;

        self.worker
            .as_ref()
            .expect("test bridge must have a worker")
            .as_pthread_t()
    }
}

impl Drop for ProductionSignalBridgeV1 {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

fn watched_signals() -> SigSet {
    let mut watched = SigSet::empty();
    watched.add(Signal::SIGINT);
    watched.add(Signal::SIGTERM);
    watched
}

fn failed_install(
    previous_mask: &SigSet,
    original: ProductionSignalBridgeErrorV1,
) -> ProductionSignalBridgeErrorV1 {
    if previous_mask.thread_set_mask().is_ok() {
        SIGNAL_BRIDGE_ACTIVE_V1.store(false, Ordering::Release);
        original
    } else {
        ProductionSignalBridgeErrorV1::SignalMaskRestoreFailed
    }
}

fn run_signal_worker(
    signal_fd: SignalFd,
    shutdown: RouteShutdownTokenV1,
    stop: Receiver<()>,
) -> Result<(), ProductionSignalBridgeErrorV1> {
    loop {
        consume_pending_signals(&signal_fd, &shutdown)?;

        match stop.recv_timeout(SIGNAL_POLL_INTERVAL_V1) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => {
                consume_pending_signals(&signal_fd, &shutdown)?;
                return Ok(());
            }
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
}

fn consume_pending_signals(
    signal_fd: &SignalFd,
    shutdown: &RouteShutdownTokenV1,
) -> Result<(), ProductionSignalBridgeErrorV1> {
    loop {
        let info = match signal_fd.read_signal() {
            Ok(Some(info)) => info,
            Ok(None) => return Ok(()),
            Err(_) => {
                let _ = shutdown.request_shutdown();
                return Err(ProductionSignalBridgeErrorV1::SignalConsumptionFailed);
            }
        };

        let signal = info.ssi_signo;
        if signal != Signal::SIGINT as u32 && signal != Signal::SIGTERM as u32 {
            let _ = shutdown.request_shutdown();
            return Err(ProductionSignalBridgeErrorV1::SignalConsumptionFailed);
        }

        shutdown
            .request_shutdown()
            .map_err(|_| ProductionSignalBridgeErrorV1::ShutdownControlUnavailable)?;
    }
}

fn wait_until_finished(
    worker: &JoinHandle<Result<(), ProductionSignalBridgeErrorV1>>,
) -> Result<(), ProductionSignalBridgeErrorV1> {
    let deadline = Instant::now() + PRODUCTION_SIGNAL_JOIN_TIMEOUT_V1;
    while !worker.is_finished() {
        let now = Instant::now();
        if now >= deadline {
            return Err(ProductionSignalBridgeErrorV1::WorkerJoinTimedOut);
        }
        thread::sleep(JOIN_POLL_INTERVAL_V1.min(deadline.saturating_duration_since(now)));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RouteRunControlV1, SystemRouteRunControlV1};
    use nix::sys::pthread::pthread_kill;
    use std::sync::mpsc;

    #[test]
    fn real_signals_wake_and_teardown_is_bounded_and_fail_closed() {
        let original_mask = SigSet::thread_get_mask().expect("read original signal mask");

        for signal in [Signal::SIGTERM, Signal::SIGINT] {
            let (mut control, shutdown) = SystemRouteRunControlV1::new();
            let mut bridge = ProductionSignalBridgeV1::install(shutdown)
                .expect("install production signal bridge");

            let duplicate = ProductionSignalBridgeV1::install(RouteShutdownTokenV1::new())
                .expect_err("duplicate bridge must fail closed");
            assert_eq!(duplicate, ProductionSignalBridgeErrorV1::AlreadyInstalled);

            let (woke_tx, woke_rx) = mpsc::channel();
            let waiter = thread::spawn(move || {
                let started = Instant::now();
                control
                    .wait(Duration::from_secs(5))
                    .expect("wait on route shutdown control");
                let requested = control
                    .shutdown_requested()
                    .expect("read shutdown request after wake");
                woke_tx
                    .send((requested, started.elapsed()))
                    .expect("report wake result");
            });

            pthread_kill(bridge.worker_pthread_for_test(), signal)
                .expect("send real signal to the consuming worker");

            let (requested, elapsed) = woke_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("signal must wake the route control");
            assert!(requested);
            assert!(elapsed < Duration::from_secs(2));
            waiter.join().expect("join route-control waiter");

            bridge.shutdown().expect("bounded signal teardown");
            assert_eq!(
                SigSet::thread_get_mask().expect("read restored signal mask"),
                original_mask
            );
            bridge
                .shutdown()
                .expect("successful teardown is idempotent");
        }

        let (_control, shutdown) = SystemRouteRunControlV1::new();
        let mut bridge = ProductionSignalBridgeV1::install(shutdown)
            .expect("install bridge for bounded teardown test");
        bridge
            .stop
            .take()
            .expect("real worker stop channel")
            .send(())
            .expect("stop real signal worker");
        bridge
            .worker
            .take()
            .expect("real signal worker")
            .join()
            .expect("real signal worker must not panic")
            .expect("real signal worker must stop cleanly");

        let (release_tx, release_rx) = mpsc::channel();
        bridge.worker = Some(thread::spawn(move || {
            release_rx.recv().expect("release bounded test worker");
            Ok(())
        }));

        let started = Instant::now();
        assert_eq!(
            bridge.shutdown(),
            Err(ProductionSignalBridgeErrorV1::WorkerJoinTimedOut)
        );
        assert!(started.elapsed() >= PRODUCTION_SIGNAL_JOIN_TIMEOUT_V1);
        let blocked_mask = SigSet::thread_get_mask().expect("read fail-closed mask");
        assert!(blocked_mask.contains(Signal::SIGINT));
        assert!(blocked_mask.contains(Signal::SIGTERM));
        assert_eq!(
            ProductionSignalBridgeV1::install(RouteShutdownTokenV1::new())
                .expect_err("timed-out teardown must retain exclusivity"),
            ProductionSignalBridgeErrorV1::AlreadyInstalled
        );

        release_tx.send(()).expect("release bounded test worker");
        bridge
            .shutdown()
            .expect("retry joins worker and restores exact mask");
        assert_eq!(
            SigSet::thread_get_mask().expect("read final restored signal mask"),
            original_mask
        );
    }
}
