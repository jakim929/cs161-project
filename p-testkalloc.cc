#include "u-lib.hh"

void process_main() {
    // Your code here!
    // Running `testkalloc` should cause the kernel to run buddy allocator
    // tests. How you make this work is up to you.

    sys_consoletype(CONSOLE_MEMVIEWER);

    while(true) {
        sys_testkalloc();
    }

    sys_exit(0);
}
