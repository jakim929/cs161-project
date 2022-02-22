#include "kernel.hh"
#include "k-ahci.hh"
#include "k-apic.hh"
#include "k-chkfs.hh"
#include "k-chkfsiter.hh"
#include "k-devices.hh"
#include "k-vmiter.hh"
#include "obj/k-firstprocess.h"

// kernel.cc
//
//    This is the kernel.

// # timer interrupts so far on CPU 0
std::atomic<unsigned long> ticks;

static void tick();
static void boot_process_start(pid_t pid, pid_t ppid, const char* program_name);
void init_process_start(pid_t pid, pid_t ppid);

// kernel_start(command)
//    Initialize the hardware and processes and start running. The `command`
//    string is an optional string passed from the boot loader.

void kernel_start(const char* command) {
    init_hardware();
    consoletype = CONSOLE_NORMAL;
    console_clear();

    // set up process descriptors
    for (pid_t i = 0; i < NPROC; i++) {
        ptable[i] = nullptr;
    }

    // start initial kernel process
    init_process_start(1, 1);

    // start first user process
    boot_process_start(2, 1, CHICKADEE_FIRST_PROCESS);

    // start running processes
    cpus[0].schedule(nullptr);
}

// proc::init_process_fn
void init_process_fn() {
    while(true) {
        current()->yield();
    }
}

void init_process_start(pid_t pid, pid_t ppid) {
    proc* p = knew<proc>();
    p->init_kernel(pid, ppid, &init_process_fn);
    {
        spinlock_guard guard(ptable_lock);
        assert(!ptable[pid]);
        ptable[pid] = p;
    }
    cpus[pid % ncpu].enqueue(p);
}

// boot_process_start(pid, name)
//    Load application program `name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.
//    Only called at initial boot time.

void boot_process_start(pid_t pid, pid_t ppid, const char* name) {
    // look up process image in initfs
    memfile_loader ld(memfile::initfs_lookup(name), kalloc_pagetable());
    assert(ld.memfile_ && ld.pagetable_);
    int r = proc::load(ld);
    assert(r >= 0);

    // allocate process, initialize memory
    proc* p = knew<proc>();
    p->init_user(pid, ppid, ld.pagetable_);
    p->regs_->reg_rip = ld.entry_rip_;

    void* stkpg = kalloc(PAGESIZE);
    assert(stkpg);
    vmiter(p, MEMSIZE_VIRTUAL - PAGESIZE).map(stkpg, PTE_PWU);
    p->regs_->reg_rsp = MEMSIZE_VIRTUAL;

    vmiter(p, 0xB8000).map(0xB8000, PTE_PWU);

    // add to process table (requires lock in case another CPU is already
    // running processes)
    {
        spinlock_guard guard(ptable_lock);
        assert(!ptable[pid]);
        ptable[pid] = p;
    }

    {
        spinlock_guard guard(process_hierarchy_lock);
        ptable[1]->children_list_.push_back(p);
    }

    // add to run queue
    cpus[pid % ncpu].enqueue(p);
}

// proc::exception(reg)
//    Exception handler (for interrupts, traps, and faults).
//
//    The register values from exception time are stored in `reg`.
//    The processor responds to an exception by saving application state on
//    the current CPU stack, then jumping to kernel assembly code (in
//    k-exception.S). That code transfers the state to the current kernel
//    task's stack, then calls proc::exception().

void proc::exception(regstate* regs) {
    // It can be useful to log events using `log_printf`.
    // Events logged this way are stored in the host's `log.txt` file.
    //log_printf("proc %d: exception %d @%p\n", id_, regs->reg_intno, regs->reg_rip);

    // Record most recent user-mode %rip.
    if ((regs->reg_cs & 3) != 0) {
        recent_user_rip_ = regs->reg_rip;
    }

    // Show the current cursor location.
    consolestate::get().cursor();


    // Actually handle the exception.
    switch (regs->reg_intno) {

    case INT_IRQ + IRQ_TIMER: {
        cpustate* cpu = this_cpu();
        if (cpu->cpuindex_ == 0) {
            tick();
        }
        lapicstate::get().ack();
        regs_ = regs;
        yield_noreturn();
        break;                  /* will not be reached */
    }

    case INT_PF: {              // pagefault exception
        // Analyze faulting address and access type.
        uintptr_t addr = rdcr2();
        const char* operation = regs->reg_errcode & PFERR_WRITE
                ? "write" : "read";
        const char* problem = regs->reg_errcode & PFERR_PRESENT
                ? "protection problem" : "missing page";

        if ((regs->reg_cs & 3) == 0) {
            panic_at(*regs, "Kernel page fault for %p (%s %s)!\n",
                     addr, operation, problem);
        }

        error_printf(CPOS(24, 0), 0x0C00,
                     "Process %d page fault for %p (%s %s, rip=%p)!\n",
                     id_, addr, operation, problem, regs->reg_rip);
        pstate_ = proc::ps_faulted;
        yield();
        break;
    }

    case INT_IRQ + IRQ_KEYBOARD:
        keyboardstate::get().handle_interrupt();
        break;

    default:
        if (sata_disk && regs->reg_intno == INT_IRQ + sata_disk->irq_) {
            sata_disk->handle_interrupt();
        } else {
            panic_at(*regs, "Unexpected exception %d!\n", regs->reg_intno);
        }
        break;                  /* will not be reached */

    }

    // return to interrupted context
}


// proc::syscall(regs)
//    System call handler.
//
//    The register values from system call time are stored in `regs`.
//    The return value from `proc::syscall()` is returned to the user
//    process in `%rax`.

uintptr_t proc::run_syscall(regstate* regs) {
    //log_printf("proc %d: syscall %ld @%p\n", id_, regs->reg_rax, regs->reg_rip);

    // Record most recent user-mode %rip.
    recent_user_rip_ = regs->reg_rip;

    switch (regs->reg_rax) {

    case SYSCALL_CONSOLETYPE:
        if (consoletype != (int) regs->reg_rdi) {
            console_clear();
        }
        consoletype = regs->reg_rdi;
        return 0;

    case SYSCALL_PANIC:
        panic_at(*regs, "process %d called sys_panic()", id_);
        break;                  // will not be reached

    case SYSCALL_GETPID:
        return id_;

    case SYSCALL_GETPPID: {
        spinlock_guard guard(process_hierarchy_lock);
        log_printf("SYSCALL_GETPPID for process %d => %d\n", id_, ppid_);
        return ppid_;
    }

    case SYSCALL_YIELD:
        yield();
        return 0;

    case SYSCALL_PAGE_ALLOC: {
        uintptr_t addr = regs->reg_rdi;
        if (addr >= VA_LOWEND || addr & 0xFFF) {
            return -1;
        }
        void* pg = kalloc(PAGESIZE);
        if (!pg || vmiter(this, addr).try_map(ka2pa(pg), PTE_PWU) < 0) {
            return -1;
        }
        return 0;
    }

    case SYSCALL_PAUSE: {
        sti();
        for (uintptr_t delay = 0; delay < 1000000; ++delay) {
            pause();
        }
        return 0;
    }

    case SYSCALL_EXIT: {
        syscall_exit(regs);
        // should never reach
        assert(false);
    }

    case SYSCALL_FORK:
        return syscall_fork(regs);

    case SYSCALL_READ:
        return syscall_read(regs);

    case SYSCALL_WRITE:
        return syscall_write(regs);

    case SYSCALL_READDISKFILE:
        return syscall_readdiskfile(regs);

    case SYSCALL_SYNC: {
        int drop = regs->reg_rdi;
        // `drop > 1` asserts that no data blocks are referenced (except
        // possibly superblock and FBB blocks). This can only be ensured on
        // tests that run as the first process.
        if (drop > 1 && strncmp(CHICKADEE_FIRST_PROCESS, "test", 4) != 0) {
            drop = 1;
        }
        return bufcache::get().sync(drop);
    }

    case SYSCALL_MAP_CONSOLE: {
        uintptr_t addr = reinterpret_cast<uintptr_t>(regs->reg_rdi);
        if (addr > VA_LOWMAX || (addr % PAGESIZE) != 0) {
            return E_INVAL;
        }

        if (vmiter(this, addr).try_map(addr, PTE_PWU) < 0) {
            return E_INVAL;
        }
        return 0;
    }

    case SYSCALL_MSLEEP:    
        return syscall_msleep(regs);

    case SYSCALL_NASTYALLOC:
        return syscall_nastyalloc(1000);

    case SYSCALL_TESTKALLOC: {
        uintptr_t heap_top = regs->reg_rdi;
        uintptr_t stack_bottom = regs->reg_rsi;
        uintptr_t mode = regs->reg_rdx;
        return syscall_testkalloc(heap_top, stack_bottom, (int) mode);
    }

    case SYSCALL_TESTFREE: {
        uintptr_t heap_top = regs->reg_rdi;
        uintptr_t stack_bottom = regs->reg_rsi;
        return syscall_testfree(heap_top, stack_bottom);
    }

    default:
        // no such system call
        log_printf("%d: no such system call %u\n", id_, regs->reg_rax);
        return E_NOSYS;

    }
}

uintptr_t proc::syscall(regstate* regs) {
    uintptr_t retval = run_syscall(regs);
    assert(stack_canary_ == STACK_CANARY_VALUE);
    return retval;
}

int proc::syscall_nastyalloc(int n) {
    int test[1000];
    for (int i = 0; i < 800; i++) {
        test[i] = i;
    }
    // Recursive method
    // if (n == 0) {
    //     return n;
    // }
    // syscall_nastyalloc(n - 1);
    return test[4];
}

int proc::syscall_testkalloc(uintptr_t heap_top, uintptr_t stack_bottom, int mode) {
    // assert(allocator.max_order_allocable(20480, 1000000) == 12);
    // assert(allocator.max_order_allocable(20480, 1000000) == 12);
    // assert(allocator.max_order_allocable(20480, 20480 + 4096) == 12);
    // assert(allocator.max_order_allocable(24576, 1000000) == 13);
    // assert(allocator.max_order_allocable(24576, 24576 + 8192) == 13); 
    // assert(allocator.max_order_allocable(24576, 24576 + 4096) == 12);
    // assert(allocator.max_order_allocable(24576, 24576 + 1024) == 12);

    // assert(allocator.get_desired_order(4095) == 12);
    // assert(allocator.get_desired_order(4096) == 12);
    // assert(allocator.get_desired_order(4097) == 13);
    // assert(allocator.get_desired_order(15360) == 14);
    // assert(allocator.get_desired_order(1028) == 12);
    // assert(allocator.get_desired_order(1 << 20) == 20);
    // assert(allocator.get_desired_order((1 << 20) + 1) == 21);
    // assert(allocator.get_desired_order((1 << 20) - 1) == 20);
    void* pg = kalloc(PAGESIZE);
    if (pg == nullptr || vmiter(this, heap_top).try_map(ka2pa(pg), PTE_PWU) < 0) {
        return 0;
    }

    return 1;
}

int proc::syscall_testfree(uintptr_t heap_top, uintptr_t stack_bottom) {
    for (vmiter it(pagetable_, 0); it.low(); it.next()) {
        if (it.user() &&  it.va() >= heap_top && it.va() < stack_bottom) {
            // CHANGE WHEN VARIABLE SIZE IS SUPPORTED
            it.kfree_page();
        }
    }
    return 0;
}

int proc::syscall_msleep(regstate* regs) {
    uint64_t end_time = (uint64_t) ticks.load() + (regs->reg_rdi + 9) / 10;
    while(long(end_time - ticks.load()) > 0) {
        yield();
    }
    return 0;
}

// proc::syscall_fork(regs)
//    Handle fork system call.

int proc::syscall_fork(regstate* regs) {
    int error_code = 0;
    proc* child;
    x86_64_pagetable* child_pagetable;
    pid_t pid = -1;
    irqstate irqs;

    child = knew<proc>();
    if (child == nullptr) {
        log_printf("fork_failed: child == nullptr \n");
        error_code = E_NOMEM;
        goto bad_fork_return;
    }

    irqs = ptable_lock.lock();
    for (int i = 1; i < NPROC; i++) {
        if (ptable[i] == nullptr) {
            pid = i;
            break;
        }
    }
    if (pid >= 0) {
        ptable[pid] = child;
    }
    ptable_lock.unlock(irqs);    

    if (pid < 0) {
        log_printf("fork_failed: pid < 0 \n");
        error_code = E_AGAIN;
        goto bad_fork_free_proc;
    }

    child_pagetable = kalloc_pagetable();
    if (child_pagetable == nullptr) {
        error_code = E_NOMEM;
        log_printf("fork_failed: child_pagetable != nullptr \n");
        goto bad_fork_free_pid;
    }
    
    // Enable interrupts before copying data
    sti();

    // copy over from parent pagetable
    for (vmiter it(pagetable_, 0); it.low(); it.next()) {
        if (it.user()) {
            if (it.va() == (uintptr_t) console) {
                // Map console to the same PA
                (void) vmiter(child_pagetable, it.va()).try_map(it.pa(), it.perm());
            } else if (it.va() == 0xB8000 && it.pa() == 0xB8000) {
                (void) vmiter(child_pagetable, it.va()).try_map(it.pa(), it.perm());
            } else {
                // CHANGE WHEN VARIABLE SIZE IS SUPPORTED
                void* kp = kalloc(PAGESIZE);
                if (kp == nullptr || vmiter(child_pagetable, it.va()).try_map(kp, it.perm()) < 0) {
                    if (kp != nullptr) {
                        kfree(kp);
                    }
                    error_code = E_NOMEM;
                    goto bad_fork_free_mem;
                }
                memcpy(kp, (void*) it.va(), PAGESIZE);
            }
        }
    }

    child->init_user(pid, id_, child_pagetable);
    {
        spinlock_guard guard(process_hierarchy_lock);
        children_list_.push_back(child);
    }

    // Copy parent registers into child struct proc
    memcpy(child->regs_, regs, sizeof(regstate));

    // Return 0 to child
    child->regs_->reg_rax = 0;

    // Enqueue process onto a CPU's run queue
    cpus[pid % ncpu].enqueue(child);

    return pid;

    bad_fork_free_mem: {
        assert(child_pagetable != nullptr);
        kfree_all_user_mappings(child_pagetable);
        kfree_pagetable(child_pagetable);
        child_pagetable = nullptr;
    }

    bad_fork_free_pid: {
        assert(child_pagetable == nullptr);
        assert(pid > 0);
        irqs = ptable_lock.lock();
        ptable[pid] = nullptr;
        ptable_lock.unlock(irqs);    
        pid = -1;
    }

    bad_fork_free_proc: {
        assert(pid < 0);
        assert(child != nullptr);
        kfree(child);
        child = nullptr;
    }

    bad_fork_return: {
        assert(child == nullptr);
    }
    
    return error_code;
}

void proc::syscall_exit(regstate* regs) {
    // Remove current process from process table
    auto irqs = ptable_lock.lock();
    ptable[id_] = nullptr;
    proc* parent = ptable[ppid_];
    ptable_lock.unlock(irqs);
    log_printf("exiting process %d\n", id_);

    {
        spinlock_guard guard(process_hierarchy_lock);
        log_printf("erasing for %d\n", id_);
        sibling_links_.erase();
        proc* child = children_list_.pop_front();
        while (child) {
            log_printf("updating process %d parent to %d\n", child->id_, 1);
            child->ppid_ = 1;
            parent->children_list_.push_back(child);
            child = children_list_.pop_front();
        }
    }

    x86_64_pagetable* original_pagetable = pagetable_;
    kfree_all_user_mappings(original_pagetable);
    set_pagetable(early_pagetable);
    kfree_pagetable(original_pagetable);
    pagetable_ = early_pagetable;

    pstate_ = ps_blank;

    yield_noreturn();
}


// proc::syscall_read(regs), proc::syscall_write(regs),
// proc::syscall_readdiskfile(regs)
//    Handle read and write system calls.

uintptr_t proc::syscall_read(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    uintptr_t addr = regs->reg_rsi;
    size_t sz = regs->reg_rdx;

    // Your code here!
    // * Read from open file `fd` (reg_rdi), rather than `keyboardstate`.
    // * Validate the read buffer.
    auto& kbd = keyboardstate::get();
    auto irqs = kbd.lock_.lock();

    // mark that we are now reading from the keyboard
    // (so `q` should not power off)
    if (kbd.state_ == kbd.boot) {
        kbd.state_ = kbd.input;
    }

    // yield until a line is available
    // (special case: do not block if the user wants to read 0 bytes)
    while (sz != 0 && kbd.eol_ == 0) {
        kbd.lock_.unlock(irqs);
        yield();
        irqs = kbd.lock_.lock();
    }

    // read that line or lines
    size_t n = 0;
    while (kbd.eol_ != 0 && n < sz) {
        if (kbd.buf_[kbd.pos_] == 0x04) {
            // Ctrl-D means EOF
            if (n == 0) {
                kbd.consume(1);
            }
            break;
        } else {
            *reinterpret_cast<char*>(addr) = kbd.buf_[kbd.pos_];
            ++addr;
            ++n;
            kbd.consume(1);
        }
    }

    kbd.lock_.unlock(irqs);
    return n;
}

uintptr_t proc::syscall_write(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    uintptr_t addr = regs->reg_rsi;
    size_t sz = regs->reg_rdx;

    // Your code here!
    // * Write to open file `fd` (reg_rdi), rather than `consolestate`.
    // * Validate the write buffer.
    auto& csl = consolestate::get();
    spinlock_guard guard(csl.lock_);
    size_t n = 0;
    while (n < sz) {
        int ch = *reinterpret_cast<const char*>(addr);
        ++addr;
        ++n;
        console_printf(0x0F00, "%c", ch);
    }
    return n;
}

uintptr_t proc::syscall_readdiskfile(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    const char* filename = reinterpret_cast<const char*>(regs->reg_rdi);
    unsigned char* buf = reinterpret_cast<unsigned char*>(regs->reg_rsi);
    size_t sz = regs->reg_rdx;
    off_t off = regs->reg_r10;

    if (!sata_disk) {
        return E_IO;
    }

    // read root directory to find file inode number
    auto ino = chkfsstate::get().lookup_inode(filename);
    if (!ino) {
        return E_NOENT;
    }

    // read file inode
    ino->lock_read();
    chkfs_fileiter it(ino);

    size_t nread = 0;
    while (nread < sz) {
        // copy data from current block
        if (bcentry* e = it.find(off).get_disk_entry()) {
            unsigned b = it.block_relative_offset();
            size_t ncopy = min(
                size_t(ino->size - it.offset()),   // bytes left in file
                chkfs::blocksize - b,              // bytes left in block
                sz - nread                         // bytes left in request
            );
            memcpy(buf + nread, e->buf_ + b, ncopy);
            e->put();

            nread += ncopy;
            off += ncopy;
            if (ncopy == 0) {
                break;
            }
        } else {
            break;
        }
    }

    ino->unlock_read();
    ino->put();
    return nread;
}


// memshow()
//    Draw a picture of memory (physical and virtual) on the CGA console.
//    Switches to a new process's virtual memory map every 0.25 sec.
//    Uses `console_memviewer()`, a function defined in `k-memviewer.cc`.

static void memshow() {
    static unsigned long last_redisplay = 0;
    static unsigned long last_switch = 0;
    static int showing = 1;

    // redisplay every 0.04 sec
    if (last_redisplay != 0 && ticks - last_redisplay < HZ / 25) {
        return;
    }
    last_redisplay = ticks;

    // switch to a new process every 0.5 sec
    if (ticks - last_switch >= HZ / 2) {
        showing = (showing + 1) % NPROC;
        last_switch = ticks;
    }

    spinlock_guard guard(ptable_lock);

    int search = 0;
    while ((!ptable[showing]
            || !ptable[showing]->pagetable_
            || ptable[showing]->pagetable_ == early_pagetable)
           && search < NPROC) {
        showing = (showing + 1) % NPROC;
        ++search;
    }

    console_memviewer(ptable[showing]);
    if (!ptable[showing]) {
        console_printf(CPOS(10, 26), 0x0F00, "   VIRTUAL ADDRESS SPACE\n"
            "                          [All processes have exited]\n"
            "\n\n\n\n\n\n\n\n\n\n\n");
    }
}


// tick()
//    Called once every tick (0.01 sec, 1/HZ) by CPU 0. Updates the `ticks`
//    counter and performs other periodic maintenance tasks.

void tick() {
    // Update current time
    ++ticks;

    // Update display
    if (consoletype == CONSOLE_MEMVIEWER) {
        memshow();
    }
}
