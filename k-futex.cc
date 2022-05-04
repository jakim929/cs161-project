#include "kernel.hh"
#include "k-futex.hh"
#include "k-wait.hh"
#include "k-waitstruct.hh"

void futex_store::wait(uintptr_t addr) {
  spinlock_guard guard(list_lock_);
  futex* f;
  f = get_futex(addr, guard);
  if (!f) {
    for (size_t i = 0; i < NFUTEX; i++) {
      if (list_[i].addr == 0) {
        list_[i].addr = addr;
        assert(list_[i].wq_.q_.empty());
        f = &list_[i];
        break;
      }
    }
  }
  assert(f);
  guard.unlock();

  waiter().block_until_woken(f->wq_);
}

void futex_store::wake_all(uintptr_t addr) {
  spinlock_guard guard(list_lock_);
  futex* f = get_futex(addr, guard);
  if (!f) {
    return;
  }
  
  f->wq_.wake_all();
  assert(f->wq_.q_.empty());
  f->addr = 0;
  return;
}

// TODO: convert to hash table
futex* futex_store::get_futex(uintptr_t addr, spinlock_guard& guard) {
  for (size_t i = 0; i < NFUTEX; i++) {
    if (list_[i].addr == addr) {
      return &list_[i];
    }
  }
  return nullptr;
}