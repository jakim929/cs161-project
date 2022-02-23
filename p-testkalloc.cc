#include "u-lib.hh"

extern uint8_t end[];

uint8_t* heap_top;
uint8_t* stack_bottom;

void process_main() {
    // Your code here!
    // Running `testkalloc` should cause the kernel to run buddy allocator
    // tests. How you make this work is up to you.

    sys_consoletype(CONSOLE_MEMVIEWER);

    (void) sys_fork();
    (void) sys_fork();

    heap_top = reinterpret_cast<uint8_t*>(
        round_up(reinterpret_cast<uintptr_t>(end), PAGESIZE)
    );

    stack_bottom = reinterpret_cast<uint8_t*>(
        round_down(rdrsp() - 1, PAGESIZE)
    );

    while(true) {
        for (uint8_t* addr = heap_top ; addr < stack_bottom; addr += PAGESIZE) {
            if (addr != (uint8_t*) 0x200000) {
                if (sys_testkalloc(addr, 0, 0) == 0) {
                    sys_testfree(heap_top, stack_bottom);
                    sys_yield();

                }
            }
        }
        sys_pause();
    }

    // while(true) {
    //     for (uint8_t* addr = heap_top ; addr < stack_bottom; addr += PAGESIZE) {
    //         if (addr != (uint8_t*) 0x200000) {
    //             if (sys_testkalloc(addr, 0, 0) == 0) {
    //                 break;
    //             }
    //         }

    //     }
    //     sys_testfree(heap_top, stack_bottom);

    //     // ASKTF: 0x200000 maps to 0x400000?
    //     // sys_testkalloc((void*) 0x200000, 0, 0);
    //     // sys_testfree((void*) 0x200000, (void*) 0x201000);

    //     sys_yield();
    //     sys_pause();
    // }

    sys_exit(0);
}
