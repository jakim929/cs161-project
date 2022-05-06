#include "u-lib.hh"
#include <atomic>

extern uint8_t end[];

uint8_t* heap_top;
uint8_t* stack_bottom;

void process_main() {
    heap_top = reinterpret_cast<uint8_t*>(
        round_up(reinterpret_cast<uintptr_t>(end), PAGESIZE)
    );

    int shmid = sys_shmget();
    uintptr_t shmaddr = sys_shmat(shmid, heap_top);
    int* shared_val = reinterpret_cast<int*>(shmaddr);

    int unshared_val = 10;

    pid_t p = sys_fork();
    if (p == 0) {
      *shared_val = 15;
      unshared_val = 12;
      sys_exit(1);
    }

    sys_msleep(1000);
    sys_yield();

    console_printf("Shared value : %d\n", *shared_val);
    assert_eq(unshared_val, 10);
    assert_eq(*shared_val, 15);
    assert_gt(shmid, 0);
    console_printf("testshm successful\n");
    sys_exit(1);
}
