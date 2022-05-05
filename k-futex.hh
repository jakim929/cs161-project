#ifndef CHICKADEE_KFUTEX_HH
#define CHICKADEE_KFUTEX_HH

#include "kernel.hh"

struct futex {
  wait_queue wq_;
  uintptr_t addr_;
};

#define NFUTEX 16

struct futex_store {
  spinlock list_lock_;
  futex list_[NFUTEX];

  futex* get_futex(uintptr_t addr, spinlock_guard &guard);

  void wake_n(uintptr_t addr, size_t n);
  void wake_all(uintptr_t addr);
  void wake_one(uintptr_t addr);

  void wait(uintptr_t addr);
};

#endif
