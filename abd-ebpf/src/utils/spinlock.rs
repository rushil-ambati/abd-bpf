use core::intrinsics::atomic_xchg_seqcst;

use abd_common::map_types::SpinLock;
use aya_log_ebpf::{debug, error};

use super::common::{BpfResult, PacketCtx};

pub const MAX_SPIN_LOCK_ITER_RETRY_LIMIT: u32 = 5;

/// Try to acquire a spin lock.
///
/// # Errors
///
/// If the lock is already held, it will return an error with the number of retries.
#[allow(clippy::inline_always)]
#[inline(always)]
pub fn try_spin_lock_acquire<C: PacketCtx>(ctx: &C, lock: &mut SpinLock) -> BpfResult<()> {
    let mut retries = 0;
    let retry_limit = MAX_SPIN_LOCK_ITER_RETRY_LIMIT;

    while retries < retry_limit
        && unsafe { atomic_xchg_seqcst(core::ptr::from_mut::<SpinLock>(lock), 1) } != 0
    {
        retries += 1;
    }

    if retries < retry_limit {
        debug!(ctx, "Acquired spin lock after {} retries", retries);
        Ok(())
    } else {
        error!(ctx, "Failed to acquire spin lock after {} retries", retries);
        Err(C::ABORT)
    }
}

/// Release a spin lock.
#[allow(clippy::inline_always)]
#[inline(always)]
pub fn spin_lock_release(lock: &mut SpinLock) {
    unsafe { atomic_xchg_seqcst(core::ptr::from_mut::<SpinLock>(lock), 0) };
}
