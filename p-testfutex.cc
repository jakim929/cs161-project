#include "u-lib.hh"
#include <atomic>


extern uint8_t end[];

std::atomic<int> test_val = 1;

std::atomic_flag message_lock;
std::atomic<int> phase = 0;
const char* shared;

static void message(const char* x) {
    while (message_lock.test_and_set()) {
        pause();
    }
    console_printf("T%d (P%d): %s\n", sys_gettid(), sys_getpid(), x);
    message_lock.clear();
}

void wait_on_futex_value(int* futex_addr, int expected_val, int desired_val) {
  while (1) {
    int futex_rc = sys_futex((void*) futex_addr, FUTEX_WAIT, (uint64_t) expected_val);
    if (futex_rc != 0) {
      if (futex_rc != E_AGAIN) {
        message("ERROR!");
        sys_exit(1);
      }
    } else if (futex_rc == 0) {
      if (*futex_addr == desired_val) {
        // This is a real wakeup.
        return;
      }
    }
  }
}

void wake_futex_blocking(int* futex_addr) {
  while (1) {
    int futex_rc = sys_futex((void*) futex_addr, FUTEX_WAKE, (uint64_t) 1);
    if (futex_rc == -1) {
      message("futex wake error");
      sys_exit(1);
    } else if (futex_rc > 0) {
      return;
    }
  }
}

// memory location starts at 1
// thread1a waits until location has value 2, then sets value to 3, then returns
// thread1b sleeps 1000ms, then sets the value to 2, then returns

static int thread1a(void* x) {
        int pid = sys_gettid();
    assert_eq(pid, 4);
    message("starting thread1a");

    wait_on_futex_value((int*) &test_val, 1, 2);
        message("thread1a waking up!!\n");

    int expected = 2;
    int new_val = 3;
    assert(test_val.compare_exchange_strong(expected, new_val));
    sys_texit(0);
}

static int thread1b(void*) {
    int pid = sys_gettid();
    assert_eq(pid, 5);
    message("starting thread1b, about to start sleeping");
    sys_msleep(1000);
    message("waking from sleep, setting value to 2");
    
    int expected = 1;
    int new_val = 2;
    assert(test_val.compare_exchange_strong(expected, new_val));
    wake_futex_blocking((int*) &test_val);
    sys_texit(0);
}


static void test1() {
    char* stack1 = reinterpret_cast<char*>(
        round_up(reinterpret_cast<uintptr_t>(end), PAGESIZE) + 16 * PAGESIZE
    );
    int r = sys_page_alloc(stack1);

    char* stack2 = reinterpret_cast<char*>(
        round_up(reinterpret_cast<uintptr_t>(end), PAGESIZE) + 20 * PAGESIZE
    );
    r = sys_page_alloc(stack2);

    sys_clone(&thread1a, (void*) &test_val, stack1 + PAGESIZE);
    sys_clone(&thread1b, (void*) &test_val, stack2 + PAGESIZE);
    sys_texit(0);
}

void process_main() {
    // test1

    pid_t p = sys_fork();
    assert_ge(p, 0);
    if (p == 0) {
        int pid = sys_gettid();
        assert_eq(pid, 3);
        test1();
    }
        int pid = sys_gettid();
        assert_eq(pid, 2);
    console_printf("child no = %d\n", p);
    pid_t ch = sys_waitpid(p);
    assert_eq(ch, p);
    sys_exit(0);
}
