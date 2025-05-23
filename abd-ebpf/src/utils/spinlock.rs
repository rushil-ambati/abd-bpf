use core::intrinsics::atomic_xchg_seqcst;

use abd_common::map_types::SpinLock;

use super::error::AbdError;

pub const MAX_SPIN_LOCK_ITER_RETRY_LIMIT: u32 = 5;

/// Try to acquire a spin lock.
#[inline(always)]
pub fn try_spin_lock_acquire(lock: &mut SpinLock) -> Result<(), AbdError> {
    let mut retries = 0;
    let retry_limit = MAX_SPIN_LOCK_ITER_RETRY_LIMIT;

    while retries < retry_limit
        && unsafe { atomic_xchg_seqcst(core::ptr::from_mut::<SpinLock>(lock), 1) } != 0
    {
        retries += 1;
    }

    if retries < retry_limit {
        Ok(())
    } else {
        Err(AbdError::LockRetryLimitHit)
    }
}

/// Release a spin lock.
#[inline(always)]
pub fn spin_lock_release(lock: &mut SpinLock) {
    unsafe { atomic_xchg_seqcst(core::ptr::from_mut::<SpinLock>(lock), 0) };
}
