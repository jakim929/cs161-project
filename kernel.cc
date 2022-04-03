#include "kernel.hh"
#include "k-ahci.hh"
#include "k-apic.hh"
#include "k-chkfs.hh"
#include "k-chkfsiter.hh"
#include "k-devices.hh"
#include "k-vmiter.hh"
#include "k-vfs.hh"
#include "obj/k-firstprocess.h"

// kernel.cc
//
//    This is the kernel.

// # timer interrupts so far on CPU 0
std::atomic<unsigned long> ticks;
spinlock timer_lock;
timingwheel timer_queue;

int total_resume_count = 0;

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

    for (int i = 0; i < N_GLOBAL_OPEN_FILES; i++) {
        open_file_table[i] = nullptr;
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
    proc* p = ptable[1];
    int stat;
    while(true) {       
        int result = p->waitpid(0, &stat, 0);
        if (result < 0) {
            {
                spinlock_guard ptable_guard(ptable_lock);
                spinlock_guard hierarchy_guard(process_hierarchy_lock);
                if (ptable[2] == nullptr && p->children_list_.empty()) {
                    hierarchy_guard.unlock();
                    ptable_guard.unlock();
                    process_halt();
                }
            }
            p->yield();
        }
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

    kb_c_vnode* keyboard_console_vnode = knew<kb_c_vnode>();
    assert(keyboard_console_vnode);
    file* kbc_file = knew<file>(keyboard_console_vnode, VFS_FILE_READ | VFS_FILE_WRITE);
    assert(kbc_file);
    {
        spinlock_guard guard(open_file_table_lock);
        assert(!open_file_table[0]);
        open_file_table[0] = kbc_file;
        kbc_file->id_ = 0;
    }
    for (int i = 0; i < N_FILE_DESCRIPTORS; i++) {
        p->fd_table_[i] = nullptr;
    }

    p->fd_table_[0] = kbc_file;
    p->fd_table_[1] = kbc_file;
    p->fd_table_[2] = kbc_file;

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
    p->init_fd_table();
    p->regs_->reg_rip = ld.entry_rip_;

    // not locking because init process MUST exist
    assert(ptable[1]);
    p->copy_fd_table_from_proc(ptable[1]);

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

    case SYSCALL_OPEN:
        return syscall_open(regs);

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

    case SYSCALL_WAITPID:    
        return syscall_waitpid(regs);

    case SYSCALL_DUP2:
        return syscall_dup2(regs);

    case SYSCALL_CLOSE:
        return syscall_close(regs);

    case SYSCALL_PIPE:
        return syscall_pipe(regs);

    case SYSCALL_EXECV:
        return syscall_execv(regs);

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
    spinlock_guard guard(timer_lock);
    interrupt_sleep_ = false;
    waiter().block_until(*timer_queue.get_wq_for_time(end_time), [&] () {
        // this is called with `x_lock` held
        if (interrupt_sleep_) {
            log_printf("ABOUT TO INTERRUPT!\n");
        }
        return long(end_time - ticks.load()) <= 0 || interrupt_sleep_;
    }, guard);
    if (interrupt_sleep_) {
        return E_INTR;
    }
    // while(long(end_time - ticks.load()) > 0) {
    //     yield();
    // }

    return 0;
}

// Assumes process_hierarchy_lock is locked
proc* proc::get_child(pid_t pid) {
    proc* child = nullptr;
    for (proc* p = children_list_.front(); p; p = children_list_.next(p)) {
        if (p->id_ == pid) {
            child = p;
            break;
        }
    }
    return child;
}

// Assumes process_hierarchy_lock is locked
proc* proc::get_any_exited_child() {
    proc* child = nullptr;
    for (proc* p = children_list_.front(); p; p = children_list_.next(p)) {
        if (p->pstate_ == ps_exited) {
            child = p;
            break;
        }
    }
    return child;
}

int proc::waitpid(pid_t pid, int* stat, int options) {
    proc* wait_child = nullptr;
    if (pid != 0) {
        spinlock_guard guard(process_hierarchy_lock);
        wait_child = get_child(pid);
        if (!wait_child) {
            return E_CHILD;
        }
        if (wait_child->pstate_ != ps_exited) {
            if (options == W_NOHANG) {
                return E_AGAIN;
            } else {
                waiter().block_until(wq_, [&] () {
                    return wait_child->pstate_ == ps_exited;
                }, guard);
                // while (wait_child->pstate_ != ps_exited) {
                //     guard.unlock();
                //     yield();
                //     guard.lock();
                // }
            }
        }
        wait_child->sibling_links_.erase();

    } else {
        spinlock_guard guard(process_hierarchy_lock);
        if (children_list_.empty()) {
            return E_CHILD;
        }
        wait_child = get_any_exited_child();
        if (!wait_child) {
            if (options == W_NOHANG) {
                return E_AGAIN;
            } else {
                waiter().block_until(wq_, [&] () {
                    for (proc* child = children_list_.front(); child; child = children_list_.next(child)) {
                        if (child->pstate_ == ps_exited) {
                            wait_child = child;
                            break;
                        }
                    }
                    return !!wait_child;
                }, guard);
                // while (!wait_child) {
                //     guard.unlock();
                //     yield();
                //     guard.lock();
                //     wait_child = get_any_exited_child();
                // }
            }
        }
        wait_child->sibling_links_.erase();
    }
    pid_t freed_pid = wait_child->id_;
    if (stat != nullptr) {
        *stat = wait_child->exit_status_;
    }
    {
        spinlock_guard guard(ptable_lock);
        ptable[freed_pid] = nullptr;
    }
    total_resume_count += wait_child->resume_count_;
    log_printf("proc [%d] resume count: %d total: %d\n", freed_pid, wait_child->resume_count_, total_resume_count);
    kfree(wait_child);
    return freed_pid;
}

int proc::syscall_waitpid(regstate* regs) {
    pid_t pid = regs->reg_rdi;
    int* stat = (int*) regs->reg_rsi;
    int options = (int) regs->reg_rdx;

    return waitpid(pid, stat, options);

    // assert(options == W_NOHANG);
}

int proc::close_fd(int fd, spinlock_guard& guard) {
    // log_printf("PROCESS %d TRYING TO CLOSE %d\n", id_, fd);
    file* open_file = fd_table_[fd];
    if (!open_file) {
        return E_BADF;
    }

    fd_table_[fd] = nullptr;
    {
        spinlock_guard ref_count_guard(open_file->ref_count_lock_);
        open_file->ref_count_--;
        assert(open_file->ref_count_ >= 0);
        if (open_file->ref_count_ == 0) {
            // no one should be using vnode at this point
            {
                spinlock_guard open_file_table_guard(open_file_table_lock);
                open_file_table[open_file->id_] = nullptr;
            }
            open_file->vfs_close();
            kfree(open_file);
        }
    }
    return 0;
}

bool proc::is_valid_string(char* str, size_t max_char) {
    for (int i = 0; i < max_char; i++) {
        if (str[i] == '\0') {
            return true;
        }
    }
    return false;
}

bool proc::is_valid_pathname(uintptr_t pathname) {
    if (!pathname) {
        return false;
    }
    vmiter it(this, pathname);
    if (!it.user()) {
        return false;
    }
    char* name = reinterpret_cast<char*>(pathname);
    // max name size currently allowed is 64;
    if (name[0] == '\0') {
        return false;
    }
    for (int i = 1; i < 64; i++) {
        vmiter it2(this, reinterpret_cast<uintptr_t>(&name[i]));
        if (!it2.user()) {
            return false;
        }
        if (name[i] == '\0') {
            return true;
        } 
    }

    return false;
}

int proc::get_available_open_file_table_id(spinlock_guard& guard) {
    for (int i = 0; i < N_GLOBAL_OPEN_FILES; i++) {
        if (open_file_table[i] == nullptr) {
            return i;
        }
    }
    return -1;
}

int proc::add_to_open_file_table(file* f) {
    spinlock_guard guard(open_file_table_lock);
    return add_to_open_file_table(f, guard);
}

int proc::add_to_open_file_table(file* f, spinlock_guard& guard) {
    int id = get_available_open_file_table_id(guard);
    if (id < 0) {
        return -1;
    }
    open_file_table[id] = f;
    f->id_ = id;
    return id;
}

int proc::syscall_open(regstate* regs) {
    int errno;
    uintptr_t pathname_ptr = regs->reg_rdi;
    uint64_t flag = regs->reg_rsi;
    if (!is_valid_pathname(pathname_ptr)) {
        return E_FAULT;
    }

    char* pathname = reinterpret_cast<char*>(pathname_ptr);

    int memfile_id = memfile::initfs_lookup(pathname, flag & OF_CREATE);
    if (memfile_id < 0) {
        return memfile_id;
    }

    memfile* found_memfile = &memfile::initfs[memfile_id];

    if (flag & OF_TRUNC) {
        spinlock_guard guard(found_memfile->lock_);
        found_memfile->set_length(0);
    }

    vnode* v;
    file* f;
    int open_file_id = -1;
    int fd = -1;
    uint64_t is_read = (flag & OF_READ) ? VFS_FILE_READ : 0;
    uint64_t is_write = (flag & OF_WRITE) ? VFS_FILE_WRITE : 0;

    // TODO: cleanup on failure
    v = knew<memfile_vnode>(found_memfile);
    if (!v) {
        errno = E_NOMEM;
        goto open_fail_return;
    }

    f = knew<file>(v, is_read | is_write);
    if (!f) {
        errno = E_NOMEM;
        goto open_fail_free_vnode;
    }
    
    open_file_id = add_to_open_file_table(f);
    if (open_file_id < 0) {
        errno = E_NFILE;
        goto open_fail_free_file;
    }

    fd = assign_to_open_fd(f);
    if (fd < 0) {
        return E_NFILE;
        goto open_fail_free_open_file_table_slot;
    }
    return fd;

    open_fail_free_fd_table_slot: {
        spinlock_guard guard(fd_table_lock_);
        fd_table_[fd] = nullptr;
    }

    open_fail_free_open_file_table_slot: {
        spinlock_guard guard(open_file_table_lock);
        open_file_table[open_file_id] = nullptr;
    }

    open_fail_free_file: {
        kfree(f);
    }

    open_fail_free_vnode: {
        kfree(v);
    }
    
    open_fail_return : {

    }

    return errno;
}

int proc::syscall_close(regstate* regs) {
    int fd = regs->reg_rdi;
    assert(fd >= 0 && fd < N_FILE_DESCRIPTORS);
    spinlock_guard guard(fd_table_lock_);
    return close_fd(fd, guard);
}

bool proc::is_valid_fd(int fd) {
    return fd >= 0 && fd < N_FILE_DESCRIPTORS;
}

int proc::syscall_dup2(regstate* regs) {
    int oldfd = regs->reg_rdi;
    int newfd = regs->reg_rsi;

    if (!is_valid_fd(oldfd) || !is_valid_fd(oldfd)) {
        return E_BADF;
    }

    spinlock_guard guard(fd_table_lock_);
    file* file_to_dup = fd_table_[oldfd];
    file* open_file = fd_table_[newfd];
    
    if (!file_to_dup) {
        return E_BADF;
    }

    if (open_file) {
        close_fd(newfd, guard);
    }

    {
        spinlock_guard ref_count_guard(file_to_dup->ref_count_lock_);
        file_to_dup->ref_count_++;
        fd_table_[newfd] = file_to_dup;
    }
    return newfd;
}

int proc::get_open_fd(spinlock_guard& guard) {
    for (int i = 0; i < N_FILE_DESCRIPTORS; i++) {
        if (fd_table_[i] == nullptr) {
            return i;
        }
    }
    return -1;
}

int proc::assign_to_open_fd(file* f) {
    spinlock_guard guard(fd_table_lock_);
    return assign_to_open_fd(f, guard);
}

int proc::assign_to_open_fd(file* f, spinlock_guard& guard) {
    int open_fd = get_open_fd(guard);
    if (open_fd < 0) {
        return -1;
    }
    fd_table_[open_fd] = f;
    return open_fd;
}

uint64_t proc::syscall_pipe(regstate* regs) {
    int errno;
    int read_fd = -1;
    int write_fd = -1;
    int read_file_id = -1;
    int write_file_id = -1;

    pipe* new_pipe = knew<pipe>();
    pipe_vnode* pipe_read_vnode = knew<pipe_vnode>(new_pipe, true);
    file* pipe_read_file = knew<file>(pipe_read_vnode, VFS_FILE_READ);
    pipe_vnode* pipe_write_vnode = knew<pipe_vnode>(new_pipe, false);
    file* pipe_write_file = knew<file>(pipe_write_vnode, VFS_FILE_WRITE);


    if (!new_pipe || !pipe_read_vnode || !pipe_read_file || !pipe_write_vnode || !pipe_write_file) {
        errno = E_NOMEM;
        goto pipe_fail_free_objects;
    }
    {
        spinlock_guard fd_table_guard(fd_table_lock_);
        read_fd = assign_to_open_fd(pipe_read_file, fd_table_guard);
        write_fd = assign_to_open_fd(pipe_write_file, fd_table_guard);
        if (write_fd < 0 || read_fd < 0) {
            errno = E_NFILE;
            goto pipe_fail_free_fd_table;
        }
    }

    {
        spinlock_guard open_file_table_guard(open_file_table_lock);
        read_file_id = add_to_open_file_table(pipe_read_file, open_file_table_guard);
        write_file_id = add_to_open_file_table(pipe_write_file, open_file_table_guard);
        if (write_fd < 0 || read_fd < 0) {
            errno = E_NFILE;
            goto pipe_fail_free_open_table;
        }
    }

    return ((uint64_t) read_fd) | (((uint64_t) write_fd) << 32);

    pipe_fail_free_open_table: {
        spinlock_guard open_file_table_guard(open_file_table_lock);
        if (read_file_id >= 0) open_file_table[read_file_id] = nullptr;
        if (write_file_id >= 0) open_file_table[write_file_id] = nullptr;
    }

    pipe_fail_free_fd_table: {
        spinlock_guard fd_table_guard(fd_table_lock_);
        if (read_fd >= 0) fd_table_[read_fd] = nullptr;
        if (write_fd >= 0) fd_table_[write_fd] = nullptr;
    }

    pipe_fail_free_objects: {
        if (new_pipe) kfree(new_pipe);
        if (pipe_read_vnode) kfree(pipe_read_vnode);
        if (pipe_read_file) kfree(pipe_read_file);
        if (pipe_write_vnode) kfree(pipe_write_vnode);
        if (pipe_write_file) kfree(pipe_write_file);
    }
    return errno;
}

bool proc::is_valid_argument(uintptr_t argv, int argc) {
    if (argv == 0 || argc == 0) {
        log_printf("is_valid_argument fails part 1\n");
        return false;
    }

    if (!vmiter(this, argv).range_perm(sizeof(uintptr_t) * (argc + 1), PTE_P | PTE_U)) {
        log_printf("is_valid_argument fails part 2\n");
        return false;
    }
    
    char** args = reinterpret_cast<char**>(argv);
    for (int i = 0; i < argc; i++) {
        if (!is_valid_string(args[i], 64)) {
            log_printf("is_valid_argument fails part 2.9\n");
            return false;
        }
        if (args[i] == nullptr) {
            log_printf("is_valid_argument fails part 3\n");
            return false;
        }
    }
    if (args[argc] != nullptr) {
        log_printf("is_valid_argument fails part 4\n");
        return false;
    }

    return true;
}

ssize_t proc::copy_argument_to_stack_end(uintptr_t stack_end, uintptr_t stack_end_va, uintptr_t argv_val, int argc) {
    char* argv_copy[argc + 1];
    argv_copy[argc] = nullptr;
    char** argv = reinterpret_cast<char**>(argv_val);
    size_t written = 0;

    for (int i = argc - 1; i >= 0; i--) {
        size_t str_size = strlen(argv[i]) + 1;
        uintptr_t dest = stack_end - written - str_size;
        uintptr_t dest_va = stack_end_va - written - str_size;
        written += str_size;
        if (written > PAGESIZE) {
            return -1;
        }
        memcpy(reinterpret_cast<void*>(dest), argv[i], str_size);
        argv_copy[i] = reinterpret_cast<char*>(dest_va);
    }

    size_t argv_size = sizeof(char*) * (argc + 1);
    uintptr_t argv_dest = stack_end - written - argv_size;
    written += argv_size;
    if (written > PAGESIZE) {
        return -1;
    }
    memcpy(reinterpret_cast<void*>(argv_dest), argv_copy, argv_size);

    return written;
}

// proc::syscall_execv(regs)
//    Handle execv system call.

int proc::syscall_execv(regstate* regs) {
    uintptr_t pathname_ptr = regs->reg_rdi;
    uintptr_t argv = regs->reg_rsi;
    int argc = regs->reg_rdx;
    size_t written = 0;

    int error_code = 0;
    char* pathname;
    int memfile_id;

    chkfsstate::inode* ino = nullptr;

    x86_64_pagetable* old_pagetable = pagetable_;
    x86_64_pagetable* new_pagetable;
    void* new_stack_page;
    uint64_t entry_rip;

    if (!is_valid_pathname(pathname_ptr)) {
        error_code = E_FAULT;
        goto bad_execv_return;
    }

    if (!is_valid_argument(argv, argc)) {
        error_code = E_FAULT;
        goto bad_execv_return;
    }

    pathname = reinterpret_cast<char*>(pathname_ptr);

    ino = chkfsstate::get().lookup_inode(pathname);
    if (!ino) {
        error_code = E_NOENT;
        goto bad_execv_return;
    }

    new_pagetable = kalloc_pagetable();
    if (!new_pagetable) {
        error_code = E_NOMEM;
        goto bad_execv_return;
    }
    
    {
        inode_loader ld(ino, new_pagetable);
        assert(ld.inode_ && ld.pagetable_);
        int r = proc::load(ld);

        if (r < 0) {
            error_code = r;
            goto bad_execv_free_page_table;
        }
        entry_rip = ld.entry_rip_;
    }

    {
        new_stack_page = kalloc(PAGESIZE);
        if (vmiter(new_pagetable, MEMSIZE_VIRTUAL - PAGESIZE).try_map(new_stack_page, PTE_PWU) < 0) {
            error_code = E_NOMEM;
            goto bad_execv_free_stack;
        }

        if (
          vmiter(new_pagetable, CONSOLE_ADDR).try_map(CONSOLE_ADDR, PTE_PWU) < 0) {
            error_code = E_NOMEM;
            goto bad_execv_free_stack;
        }
    }

    init_user(id_, ppid_, new_pagetable);

    written = copy_argument_to_stack_end(reinterpret_cast<uintptr_t>(new_stack_page) + PAGESIZE, MEMSIZE_VIRTUAL, argv, argc);
    if (written < 0) {
        // written < 0 if size of argument is larger than stack
        goto bad_execv_free_stack;
    }
    
    regs_->reg_rdi = argc;
    regs_->reg_rsi = MEMSIZE_VIRTUAL - written;

    regs_->reg_rsp = MEMSIZE_VIRTUAL - written;
    regs_->reg_rip = entry_rip;

    set_pagetable(new_pagetable);

    kfree_all_user_mappings(old_pagetable);
    kfree_pagetable(old_pagetable);

    yield_noreturn();

    bad_execv_free_stack: {
        kfree(new_stack_page);
    }

    bad_execv_free_page_table: {
        kfree_pagetable(new_pagetable);
    }

    bad_execv_return: {

    }
    return error_code;
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
                // TODO: IF THIS FAILS ALSO FREE PAGE TABLE AND LEAVE
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
    child->init_fd_table();

    {
        spinlock_guard guard(process_hierarchy_lock);
        children_list_.push_back(child);
    }

    // copy over file descriptor table from parent
    child->copy_fd_table_from_proc(this);

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
    exit_status_ = (int) regs->reg_rdi;

    proc* parent = nullptr;
    // Remove current process from process table
    {
        auto irqs = ptable_lock.lock();
        // ptable[id_] = nullptr;
        parent = ptable[ppid_];
        ptable_lock.unlock(irqs);
        spinlock_guard guard(process_hierarchy_lock);

        log_printf("exiting process %d\n", id_);

        proc* child = children_list_.pop_front();
        while (child) {
            log_printf("iter start %d\n", child->id_);
            child->ppid_ = 1;
            ptable[1]->children_list_.push_back(child);

            log_printf("proc[%d] reassigned %d to parent\n", id_, child->id_);
            child = children_list_.pop_front();
        }

        {
            spinlock_guard fd_table_guard(fd_table_lock_);
            for (int i = 0; i < N_FILE_DESCRIPTORS; i++) {
                if (fd_table_[i]) {
                    close_fd(i, fd_table_guard);
                }
            }
        }        

        x86_64_pagetable* original_pagetable = pagetable_;
        kfree_all_user_mappings(original_pagetable);
        set_pagetable(early_pagetable);
        kfree_pagetable(original_pagetable);
        pagetable_ = early_pagetable;
        pstate_ = ps_exited;
        parent->wq_.wake_all();
        {
            spinlock_guard timer_guard(timer_lock);
            parent->interrupt_sleep_ = true;
            timer_queue.wake_all();
        }
    }

    yield_noreturn();
}


// proc::syscall_read(regs), proc::syscall_write(regs),
// proc::syscall_readdiskfile(regs)
//    Handle read and write system calls.

uintptr_t proc::syscall_read(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    int fd = regs->reg_rdi;
    uintptr_t addr = regs->reg_rsi;
    size_t sz = regs->reg_rdx;

    // Your code here!
    // * Read from open file `fd` (reg_rdi), rather than `keyboardstate`.
    // * Validate the read buffer.

    if (sz == 0) {
        return 0;
    }

    vmiter it(this, addr);
    if (!it.range_perm(sz, PTE_P | PTE_U | PTE_W)) {
        return E_FAULT;
    }

    file* file = nullptr;
    {
        spinlock_guard fd_table_guard(fd_table_lock_);
        file = fd_table_[fd];
    }
    if (!file) {
        return E_BADF;
    }
    return file->vfs_read(reinterpret_cast<char*>(addr), sz);
}

uintptr_t proc::syscall_write(regstate* regs) {
    // This is a slow system call, so allow interrupts by default
    sti();

    int fd = regs->reg_rdi;
    uintptr_t addr = regs->reg_rsi;
    size_t sz = regs->reg_rdx;

    log_printf("syscall_write %d [%zu]\n", fd, sz);

    // Your code here!
    // * Write to open file `fd` (reg_rdi), rather than `consolestate`.
    // * Validate the write buffer.

    if (fd < 0 || fd >= N_FILE_DESCRIPTORS) {
        return E_BADF;
    }

    if (sz == 0) {
        return 0;
    }

    vmiter it(this, addr);
    if (!it.range_perm(sz, PTE_P | PTE_U)) {
        return E_FAULT;
    }

    file* file = nullptr;
    {
        spinlock_guard fd_table_guard(fd_table_lock_);
        file = fd_table_[fd];
    }

    // No need to keep holding fd_table_guard because the file will not get deleted while you're reading it (ref count will never be 0)
    if (!file) {
        return E_BADF;
    }
    return file->vfs_write(reinterpret_cast<char*>(addr), sz);
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
    spinlock_guard hierarchy_guard(process_hierarchy_lock);

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
    {
        spinlock_guard guard(timer_lock);
        ++ticks;
        timer_queue.wake_for_time(ticks.load());
    }

    // Update display
    if (consoletype == CONSOLE_MEMVIEWER) {
        memshow();
    }
}
