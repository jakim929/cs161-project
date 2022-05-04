#ifndef CHICKADEE_K_WAIT_HH
#define CHICKADEE_K_WAIT_HH
#include "kernel.hh"
#include "k-waitstruct.hh"

// k-wait.hh
//    Defines `waiter` and `wait_queue` member functions.
//    `k-waitstruct.hh` defines the `waiter` and `wait_queue` types.
//    (Separating the structures and functions into different header files
//    avoids problems with circular dependencies.)


inline waiter::waiter() {
}

inline waiter::~waiter() {
    // optional error-checking code
}

inline void waiter::prepare(wait_queue& wq) {
    auto irqs = wq.lock_.lock();
    p_ = current();
    assert(p_->pstate_ != proc::ps_blocked);
    p_->pstate_ = proc::ps_blocked;
    wq_ = &wq;
    wq_->q_.push_back(this);
    wq_->lock_.unlock(irqs);
}

inline void waiter::block() {
    assert(p_ == current());

    if (p_->pstate_ == proc::ps_blocked) {
        p_->yield();
    } else {

    }
    assert(p_->pstate_ == proc::ps_runnable);
    clear();
    // your code here
}

inline void waiter::clear() {
    assert(p_);
    auto irqs = wq_->lock_.lock();
    wake();
    if (links_.is_linked()) links_.erase();
    wq_->lock_.unlock(irqs);
}

inline void waiter::wake() {
    p_->wake();
}


// waiter::block_until(wq, predicate)
//    Block on `wq` until `predicate()` returns true.
template <typename F>
inline void waiter::block_until(wait_queue& wq, F predicate) {
    while (true) {
        prepare(wq);
        if (predicate()) {
            break;
        }
        block();
    }
    clear();
}

// waiter::block_until(wq, predicate, lock, irqs)
//    Block on `wq` until `predicate()` returns true. The `lock`
//    must be locked; it is unlocked before blocking (if blocking
//    is necessary). All calls to `predicate` have `lock` locked,
//    and `lock` is locked on return.
template <typename F>
inline void waiter::block_until(wait_queue& wq, F predicate,
                                spinlock& lock, irqstate& irqs) {
    while (true) {
        prepare(wq);
        if (predicate()) {
            break;
        }
        lock.unlock(irqs);
        block();
        irqs = lock.lock();
    }
    clear();
}

// waiter::block_until(wq, predicate, guard)
//    Block on `wq` until `predicate()` returns true. The `guard`
//    must be locked on entry; it is unlocked before blocking (if
//    blocking is necessary) and locked on return.
template <typename F>
inline void waiter::block_until(wait_queue& wq, F predicate,
                                spinlock_guard& guard) {
    block_until(wq, predicate, guard.lock_, guard.irqs_);
}

// wait_queue::wake_all()
//    Lock the wait queue, then clear it by waking all waiters.
inline void wait_queue::wake_all() {
    spinlock_guard guard(lock_);
    while (auto w = q_.pop_front()) {
        w->wake();
    }
}

inline void waiter::block_until_woken(wait_queue& wq) {
    prepare(wq);
    block();
    clear();
}

inline void wait_queue::wake_all_for_tgid(pid_t tgid) {
    spinlock_guard guard(lock_);
    waiter* w = q_.front();
    while(w) {
        if (w->p_->tgid_ == tgid) {
            waiter* to_wake = w;
            w = q_.next(w);
            to_wake->links_.erase();
            to_wake->wake();
        } else {
            w = q_.next(w);
        }
    }
}

#endif
