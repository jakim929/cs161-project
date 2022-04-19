#include "kernel.hh"
#include "k-wait.hh"

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

bool threadgroup::is_exited(spinlock_guard &guard) {
  return thread_list_.front() == nullptr;
}

void threadgroup::exit(int status) {
  
}

void threadgroup::exit_cleanup(int status) {
  // First assert that there are no running threads
  {
    spinlock_guard guard(thread_list_lock_);
    assert(thread_list_.front() == nullptr);
  }
  {
    spinlock_guard guard(process_hierarchy_lock);
    spinlock_guard tgtable_guard(tgtable_lock);
    threadgroup* parent = tgtable[ppid_];
    tgtable_guard.unlock();



    threadgroup* child = children_list_.pop_front();
    while (child) {
        child->ppid_ = 1;
        tgtable[1]->children_list_.push_back(child);
        child = children_list_.pop_front();
    }

    {
        spinlock_guard fd_table_guard(fd_table_lock_);
        for (int i = 0; i < N_FILE_DESCRIPTORS; i++) {
            if (fd_table_[i]) {
              // TODO, replace current() with more reasonable
                current()->close_fd(i, fd_table_guard);
            }
        }
    }

    x86_64_pagetable* original_pagetable = pagetable_;
    kfree_all_user_mappings(original_pagetable);
    set_pagetable(early_pagetable);
    kfree_pagetable(original_pagetable);
    pagetable_ = early_pagetable;
    process_exit_status_ = status;
    is_exited_ = true;

    parent->process_wq_.wake_all();

    {
      spinlock_guard timer_guard(timer_lock);
      parent->interrupt_sleep_ = true;
      timer_queue.wake_all();
    }
  }
}

int threadgroup::waitpid(pid_t tgid, int* stat, int options) {
  threadgroup* wait_child = nullptr;
  if (tgid != 0) {
      spinlock_guard guard(process_hierarchy_lock);
      wait_child = get_child(tgid, guard);
      if (!wait_child) {
          return E_CHILD;
      }
      if (!wait_child->is_exited_) {
          if (options == W_NOHANG) {
              return E_AGAIN;
          } else {
              waiter().block_until(process_wq_, [&] () {
                  return wait_child->is_exited_.load() == true;
              }, guard);
          }
      }
      wait_child->sibling_links_.erase();
  } else {
      spinlock_guard guard(process_hierarchy_lock);
      if (children_list_.empty()) {
          return E_CHILD;
      }
      wait_child = get_any_exited_child(guard);

      if (!wait_child) {
          if (options == W_NOHANG) {
              return E_AGAIN;
          } else {
              waiter().block_until(process_wq_, [&] () {
                wait_child = get_any_exited_child(guard);
                return !!wait_child;
              }, guard);
          }
      }
      wait_child->sibling_links_.erase();
  }

  pid_t freed_tgid = wait_child->tgid_;
  if (stat != nullptr) {
      *stat = wait_child->process_exit_status_;
  }
  {
      spinlock_guard guard(tgtable_lock);
      tgtable[freed_tgid] = nullptr;
  }
  kfree(wait_child);
  return freed_tgid;
}

threadgroup* threadgroup::get_child(pid_t tgid, spinlock_guard &guard) {
    threadgroup* child = nullptr;
    for (threadgroup* tg = children_list_.front(); tg; tg = children_list_.next(tg)) {
        if (tg->tgid_ == tgid) {
            child = tg;
            break;
        }
    }
    return child;
}

threadgroup* threadgroup::get_any_exited_child(spinlock_guard &guard) {
    threadgroup* wait_child = nullptr;
    for (threadgroup* tg = children_list_.front(); tg; tg = children_list_.next(tg)) {
      if (tg->is_exited_.load()) {
        wait_child = tg;
        break;
      }
    }
    return wait_child;
}
