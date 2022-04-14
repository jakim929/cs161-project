#include "kernel.hh"

threadgroup* tgtable[NTHREADGROUP];            // array of process descriptor pointers
spinlock tgtable_lock;

threadgroup::threadgroup() {
}

pid_t threadgroup::assign_to_empty_tgid(spinlock_guard &guard, threadgroup* tg) {
  for (pid_t i = 1; i < NTHREADGROUP; i++) {
    if (tgtable[i] == nullptr) {
      tgtable[i] = tg;
      tg->tgid_ = i;
      return i;
    }
  }
  return -1;
}

void threadgroup::init(pid_t tgid, pid_t ppid, x86_64_pagetable* pt) {
  tgid_ = tgid;
  pagetable_ = pt;
  ppid_ = ppid;
  init_fd_table();
}

void threadgroup::init_fd_table() {
  for (int i = 0; i < N_FILE_DESCRIPTORS; i++) {
    fd_table_[i] = nullptr;
  }
}

void threadgroup::add_proc_to_thread_list(proc* p) {
  spinlock_guard guard(thread_list_lock_);
  thread_list_.push_back(p);
}

void threadgroup::copy_fd_table_from_threadgroup(threadgroup* tg) {
    spinlock_guard fd_guard(tg->fd_table_lock_);
    for (int i = 0; i < N_FILE_DESCRIPTORS; i++) {
        file* file = tg->fd_table_[i];
        if (file) {
            spinlock_guard guard(file->ref_count_lock_);
            file->ref_count_++;
            fd_table_[i] = file;
        }
    }
}
