#include "kernel.hh"
#include "k-futex.hh"
#include "k-wait.hh"
#include "k-waitstruct.hh"

void futex_store::wait(uintptr_t addr, int val) {
  int* futex_addr = reinterpret_cast<int*>(addr);
  spinlock_guard guard(list_lock_);
  for (size_t i = 0; i < NFUTEX; i++) {
    spinlock_guard futex_guard(list_[i].lock_);
    if (list_[i].addr_ == addr) {
      if (*futex_addr != val) {
        return;
      }
      assert(!list_[i].wq_.q_.empty());
      guard.unlock();
      waiter().block_until_woken(list_[i].wq_, futex_guard);
      return;
    }
  }

  if (*futex_addr != val) {
    return;
  }

  for (size_t i = 0; i < NFUTEX; i++) {
    spinlock_guard futex_guard(list_[i].lock_);
    if (list_[i].addr_ == 0) {
      list_[i].addr_ = addr;
      assert(list_[i].wq_.q_.empty());
      guard.unlock();
      waiter().block_until_woken(list_[i].wq_, futex_guard);
      return;
    }
  }
}

void futex_store::wake_n(uintptr_t addr, size_t n) {
  spinlock_guard guard(list_lock_);
  for (size_t i = 0; i < NFUTEX; i++) {
    spinlock_guard futex_guard(list_[i].lock_);
    if (list_[i].addr_ == addr) {
      list_[i].wq_.wake_n(n);
      if (list_[i].wq_.q_.empty()) {
        list_[i].addr_ = 0;
      }
      return;
    }
  }
  return;
}

void futex_store::wake_one(uintptr_t addr) {
  spinlock_guard guard(list_lock_);
  for (size_t i = 0; i < NFUTEX; i++) {
    spinlock_guard futex_guard(list_[i].lock_);
    if (list_[i].addr_ == addr) {
      list_[i].wq_.wake_one();
      if (list_[i].wq_.q_.empty()) {
        list_[i].addr_ = 0;
      }
      return;
    }
  }
}
