#include "u-lib.hh"
#include <atomic>


extern uint8_t end[];

// mutex implementation from https://eli.thegreenplace.net/2018/basics-of-futexes

int cmpxchg(std::atomic<int>* atom, int expected, int desired) {
  int ep = expected;
  
  (*atom).compare_exchange_strong(ep, desired);
  return ep; // originally returned *ep! 
}

class mutex {
public:
  mutex() : atom_(0) {}

  void lock() {
    int pid = sys_gettid();
    int c = cmpxchg(&atom_, 0, 1);
    // If the lock was previously unlocked, there's nothing else for us to do.
    // Otherwise, we'll probably have to wait.
    if (c != 0) {
      do {
        // If the mutex is locked, we signal that we're waiting by setting the
        // atom to 2. A shortcut checks is it's 2 already and avoids the atomic
        // operation in this case.
        if (c == 2 || cmpxchg(&atom_, 1, 2) != 0) {
          // Here we have to actually sleep, because the mutex is actually
          // locked. Note that it's not necessary to loop around this syscall;
          // a spurious wakeup will do no harm since we only exit the do...while
          // loop when atom_ is indeed 0.
          sys_futex((void*) &atom_, FUTEX_WAIT, 2);
          //make_syscall(SYSCALL_FUTEX, (int*)&atom_, FUTEX_WAIT, 2, 0, 0, 0);
        }
        // We're here when either:
        // (a) the mutex was in fact unlocked (by an intervening thread).
        // (b) we slept waiting for the atom and were awoken.
        //
        // So we try to lock the atom again. We set teh state to 2 because we
        // can't be certain there's no other thread at this exact point. So we
        // prefer to err on the safe side.
      } while ((c = cmpxchg(&atom_, 0, 2)) != 0);
    }
  }

  void unlock() {
    if (atom_.fetch_sub(1) != 1) {
      atom_.store(0);
      sys_futex((void*) &atom_, FUTEX_WAKE, 1);
    }
  }

private:
  // 0 means unlocked
  // 1 means locked, no waiters
  // 2 means locked, there are waiters in lock()
  std::atomic<int> atom_;
};

 struct function_args {
    mutex lock;
    int sum;
};

static int add_to_locked_shared_value(void* x) {
    int pid = sys_gettid();

    function_args* arg = (function_args*) x;

    console_printf("starting pid[%d]\n", pid);

    for (int i = 0; i < 100000; i++) {
      arg->lock.lock();
      int j = arg->sum + 1;
      int k = 0;
      // spin for a small but different amount of time per thread
      // trying to increase chance of race condition by making critical section wider
      while(k < 100 - pid) {
        k++;
      }
      arg->sum = j;
      arg->lock.unlock();
    }

    console_printf("exiting pid[%d] \n", pid);
    sys_texit(0);
}

static int add_to_unlocked_shared_value(void* x) {
    int pid = sys_gettid();

    function_args* arg = (function_args*) x;

    console_printf("starting pid[%d]\n", pid);
    for (int i = 0; i < 100000; i++) {
      int j = arg->sum + 1;
      int k = 0;
      // spin for a small but different amount of time per thread
      while(k < 100 - pid) {
        k++;
      }
      arg->sum = j;
    }
    console_printf("exiting pid[%d] \n", pid);
    sys_texit(0);
}

static void test_sum(int (*func)(void*)) {
    char* stack1 = reinterpret_cast<char*>(
        round_up(reinterpret_cast<uintptr_t>(end), PAGESIZE) + 16 * PAGESIZE
    );
    int r = sys_page_alloc(stack1);

    char* stack2 = reinterpret_cast<char*>(
        round_up(reinterpret_cast<uintptr_t>(end), PAGESIZE) + 17 * PAGESIZE
    );
    r = sys_page_alloc(stack2);

    char* stack3 = reinterpret_cast<char*>(
        round_up(reinterpret_cast<uintptr_t>(end), PAGESIZE) + 18 * PAGESIZE
    );
    r = sys_page_alloc(stack3);

    char* stack4 = reinterpret_cast<char*>(
        round_up(reinterpret_cast<uintptr_t>(end), PAGESIZE) + 19 * PAGESIZE
    );
    r = sys_page_alloc(stack4);

    struct function_args args;
    args.sum = 0;

    sys_clone(func, &args, stack1 + PAGESIZE);
    sys_clone(func, &args, stack2 + PAGESIZE);
    sys_clone(func, &args, stack3 + PAGESIZE);
    sys_clone(func, &args, stack4 + PAGESIZE);

    sys_msleep(10000);
    console_printf("Sum result! %d\n", args.sum);

    sys_texit(0);
}

void process_main() {
    console_printf("starting mutex test!\n");
    pid_t p = sys_fork();
    assert_ge(p, 0);
    if (p == 0) {
      console_printf("Trying to sum without lock\n");
      test_sum(add_to_unlocked_shared_value);
    }
    pid_t ch = sys_waitpid(p);

    p = sys_fork();
    assert_ge(p, 0);
    if (p == 0) {
      console_printf("Trying to sum with lock\n");
      test_sum(add_to_locked_shared_value);
    }
    ch = sys_waitpid(p);
    console_printf("testmutex done!");
    sys_exit(0);
}