
#ifndef CHICKADEE_KSHM_HH
#define CHICKADEE_KSHM_HH

#include "kernel.hh"

struct shm {
  int id_;
  void* kptr_;
  int ref_count_;
  spinlock ref_count_lock_;
};

struct shm_mapping {
  uintptr_t va_;
  shm* shm_;
};

#define NSHM 16

struct shm_store {
  shm* list_[NSHM];
  spinlock list_lock_;
};

#endif
