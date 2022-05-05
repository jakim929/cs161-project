#include "u-lib.hh"
#include <atomic>


extern uint8_t end[];

uint8_t* heap_top;
uint8_t* stack_bottom;

std::atomic<int> test_val = 1;

void wait_on_futex_value(int* futex_addr, int expected_val, int desired_val) {
  while (1) {
    int futex_rc = sys_futex((void*) futex_addr, FUTEX_WAIT, (uint64_t) expected_val);
    if (futex_rc != 0) {
      if (futex_rc != E_AGAIN) {
        console_printf("ERROR!\n");
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
      console_printf("futex wake error\n");
      sys_exit(1);
    } else if (futex_rc > 0) {
      return;
    }
  }
}

// memory location starts at 1
// thread1a waits until location has value 2, then sets value to 3, then returns
// thread1b sleeps 1000ms, then sets the value to 2, then returns

void process_main() {
    heap_top = reinterpret_cast<uint8_t*>(
        round_up(reinterpret_cast<uintptr_t>(end), PAGESIZE)
    );
    int shmid = sys_shmget();
    uintptr_t shmaddr = sys_shmat(shmid, heap_top);
    std::atomic<int>* shared_val = reinterpret_cast<std::atomic<int>*>(shmaddr);
    *shared_val = 1;

    pid_t p = sys_fork();
    assert_ge(p, 0);
    if (p == 0) {
      console_printf("starting parent\n");
      wait_on_futex_value((int*) shared_val, 1, 2);
      console_printf("parent waking up!!\n");
      int expected = 2;
      int new_val = 3;
      assert(shared_val->compare_exchange_strong(expected, new_val));
      console_printf("parent finished\n");
      sys_exit(0);
    }

    console_printf("starting child\n");
    sys_msleep(1000);
    console_printf("waking from sleep, setting value to 2\n");
    
    int expected = 1;
    int new_val = 2;
    assert(shared_val->compare_exchange_strong(expected, new_val));
    wake_futex_blocking((int*) shared_val);
    console_printf("child finished\n");

    sys_exit(0);
}
