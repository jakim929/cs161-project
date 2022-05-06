#include "kernel.hh"
#include "k-ahci.hh"
#include "k-apic.hh"
#include "k-chkfs.hh"
#include "k-chkfsiter.hh"
#include "k-devices.hh"
#include "k-vmiter.hh"
#include "k-vfs.hh"
#include "obj/k-firstprocess.h"
#include "k-futex.hh"

// kernel.cc
//
//    This is the kernel.

// # timer interrupts so far on CPU 0
std::atomic<unsigned long> ticks;
spinlock timer_lock;
timingwheel timer_queue;

futex_store global_futex_store;
shm_store global_shm_store;

int total_resume_count = 0;

static void tick();
static void boot_process_start(pid_t tgid, pid_t pid, pid_t ppid, const char* program_name);
void init_process_start(pid_t tgid, pid_t pid, pid_t ppid);
void issue_prefetch_process_start(pid_t pid, pid_t ppid);
void handle_prefetch_result_process_start(pid_t pid, pid_t ppid);

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

    for (pid_t i = 0; i < NTHREADGROUP; i++) {
        tgtable[i] = nullptr;
    }

    for (int i = 0; i < N_GLOBAL_OPEN_FILES; i++) {
        open_file_table[i] = nullptr;
    }

    // start initial kernel process
    init_process_start(1, 1, 1);

    // kernel process to handle prefetching
    // issue_prefetch_process_start(3, 1);

    // start first user process
    boot_process_start(2, 2, 1, CHICKADEE_FIRST_PROCESS);

    // start running processes
    cpus[0].schedule(nullptr);
}

void init_process_fn() {
    proc* p = ptable[1];
    int stat;
    while(true) {       
        int result = p->waitpid(0, &stat, 0);
        if (result < 0) {
            if (result == E_CHILD) {
                process_halt();
            }
            p->yield();
        }
    }
}

void issue_prefetch_process_fn() {
    auto& bc = bufcache::get();
    while(true) {
        spinlock_guard guard(bc.prefetch_queue_lock_);
        waiter().block_until(bc.prefetch_wait_queue_, [&] () {
            bool has_new = false;
            for (int i = 0; i < 32; i++) {
                if (bc.prefetch_queue_[(i + bc.prefetch_queue_head_) % 32].bn_ >= 0) {
                    has_new = true;
                    break;
                }
            }
            return has_new;
        }, guard);

        int block_to_get = -1;
        for (int i = 0; i < 32; i++) {
            int id = i + bc.prefetch_queue_head_;

            if (bc.prefetch_queue_[id % 32].bn_ >= 0) {
                block_to_get = bc.prefetch_queue_[id % 32].bn_;
                bc.prefetch_queue_[id % 32].bn_ = -1;
                bc.prefetch_queue_head_ = (bc.prefetch_queue_head_ + 1) % 32;
                break;
            }

        }
        
        if (block_to_get >= 0) {
            guard.unlock();
            bcentry* b = bc.get_disk_entry_for_prefetch(block_to_get);
            log_printf("prefetched %d\n", block_to_get);
            b->put();
            guard.lock();
        }
    }
}

void init_process_start(pid_t tgid, pid_t pid, pid_t ppid) {
    threadgroup* tg = knew<threadgroup>();
    tg->init(tgid, ppid, early_pagetable);

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

    tg->fd_table_[0] = kbc_file;
    tg->fd_table_[1] = kbc_file;
    tg->fd_table_[2] = kbc_file;


    proc* p = knew<proc>();
    p->init_kernel(pid, tg, &init_process_fn);
    {
        spinlock_guard guard(ptable_lock);
        assert(!ptable[pid]);
        ptable[pid] = p;
    }
    {
        spinlock_guard guard(tgtable_lock);
        assert(!tgtable[tgid]);
        tgtable[tgid] = tg;
    }
    tg->add_proc_to_thread_list(p);

    cpus[pid % ncpu].enqueue(p);
}

void issue_prefetch_process_start(pid_t tgid, pid_t pid, pid_t ppid) {
    threadgroup* tg = knew<threadgroup>();
    tg->init(tgid, ppid, early_pagetable);
    proc* p = knew<proc>();
    tg->add_proc_to_thread_list(p);
    p->init_kernel(pid, tg, &issue_prefetch_process_fn);
    {
        spinlock_guard guard(ptable_lock);
        assert(!ptable[pid]);
        ptable[pid] = p;
    }
    {
        spinlock_guard guard(tgtable_lock);
        assert(!tgtable[tgid]);
        tgtable[tgid] = tg;
    }

    cpus[pid % ncpu].enqueue(p);
}

// boot_process_start(pid, name)
//    Load application program `name` as process number `pid`.
//    This loads the application's code and data into memory, sets its
//    %rip and %rsp, gives it a stack page, and marks it as runnable.
//    Only called at initial boot time.

void boot_process_start(pid_t tgid, pid_t pid, pid_t ppid, const char* name) {
    // look up process image in initfs
    memfile_loader ld(memfile::initfs_lookup(name), kalloc_pagetable());
    assert(ld.memfile_ && ld.pagetable_);
    int r = proc::load(ld);
    assert(r >= 0);

    // allocate threadgroup
    threadgroup* tg = knew<threadgroup>();
    tg->init(tgid, ppid, ld.pagetable_);

    // not locking because init process MUST exist
    assert(tgtable[1]);
    tg->copy_fd_table_from_threadgroup(tgtable[1]);

    // allocate process, initialize memory
    proc* p = knew<proc>();
    
    p->init_user(pid, tg);
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
        spinlock_guard guard(tgtable_lock);
        assert(!tgtable[tgid]);
        tgtable[tgid] = tg;
    }
    tg->add_proc_to_thread_list(p);
    {
        spinlock_guard guard(process_hierarchy_lock);
        tgtable[1]->children_list_.push_back(tg);
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
        return tgid_;

    case SYSCALL_GETPPID: {
        spinlock_guard guard(process_hierarchy_lock);
        log_printf("SYSCALL_GETPPID for process %d => %d\n", id_, tg_->ppid_);
        return tg_->ppid_;
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

    case SYSCALL_TEXIT:
        syscall_texit(regs);
        // should never reach
        assert(false);
    
    case SYSCALL_CLONE:
        return syscall_clone(regs);

    case SYSCALL_FORK:
        // return 0;
        return syscall_fork(regs);

    case SYSCALL_OPEN:
        return syscall_open(regs);

    case SYSCALL_READ:
        return syscall_read(regs);

    case SYSCALL_WRITE:
        return syscall_write(regs);

    case SYSCALL_LSEEK:
        return syscall_lseek(regs);

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

    case SYSCALL_MKDIR:
        return syscall_mkdir(regs);

    case SYSCALL_RMDIR:
        return syscall_rmdir(regs);

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

    case SYSCALL_GETTID:
        return id_;

    case SYSCALL_MSLEEP:    
        return syscall_msleep(regs);

    case SYSCALL_WAITPID:    
        return syscall_waitpid(regs);

    case SYSCALL_FUTEX:
        return syscall_futex(regs);

    case SYSCALL_SHMGET:
        return syscall_shmget(regs);

    case SYSCALL_SHMAT:
        return syscall_shmat(regs);

    case SYSCALL_SHMDT:
        return syscall_shmdt(regs);

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
    return test[4];
}

int proc::syscall_testkalloc(uintptr_t heap_top, uintptr_t stack_bottom, int mode) {
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
    tg_->interrupt_sleep_ = false;
    waiter().block_until(*timer_queue.get_wq_for_time(end_time), [&] () {
        if (tg_->interrupt_sleep_) {
            log_printf("ABOUT TO INTERRUPT!\n");
        }
        return long(end_time - ticks.load()) <= 0 || tg_->interrupt_sleep_.load();
    }, guard);
    if (tg_->interrupt_sleep_) {
        return E_INTR;
    }

    return 0;
}

int proc::syscall_clone(regstate* regs) {
    uintptr_t stack_top = regs->reg_rdi;
    spinlock_guard guard(tg_->thread_list_lock_);
    proc* cloned_thread = nullptr;
    irqstate irqs;
    pid_t pid = -1;

    vmiter it(this, stack_top);
    if (!it.perm(PTE_P | PTE_U | PTE_W)) {
        return E_FAULT;
    }

    cloned_thread = knew<proc>();
    if (!cloned_thread) {
        return E_NOMEM;
    }
    tg_->thread_list_.push_back(cloned_thread);
    irqs = ptable_lock.lock();
    for (int i = 1; i < NPROC; i++) {
        if (ptable[i] == nullptr) {
            pid = i;
            break;
        }
    }
    if (pid >= 0) {
        ptable[pid] = cloned_thread;
    }
    ptable_lock.unlock(irqs);
    if (pid < 0) {
        cloned_thread->thread_links_.erase();
        kfree(cloned_thread);
        return E_AGAIN;
    }

    cloned_thread->init_user(pid, tg_);
    cloned_thread->regs_->reg_rip = regs->reg_rip;
    cloned_thread->regs_->reg_rsp = stack_top;

    log_printf("sys_clone pid[%d] tgid[%d] cloned to pid[%d] tgid[%d] with stack_page %p\n", id_, tgid_, cloned_thread->id_, cloned_thread->tgid_, stack_top);

    cloned_thread->regs_->reg_rax = 0;
    cpus[pid % ncpu].enqueue(cloned_thread);
    return pid;
}

void proc::texit(int status) {
    log_printf("syscall_texit[%d] for pid[%d] tgid[%d]\n", status, id_, tgid_);

    bool has_next_thread = false;
    bool has_prev_thread = false;
    bool is_last_thread = false;
    {

        // TODO: Move the ptable_lock outside so 
        spinlock_guard ptable_guard(ptable_lock);
        spinlock_guard thread_list_guard(tg_->thread_list_lock_);
        has_next_thread = tg_->thread_list_.next(this) != nullptr;
        has_prev_thread = tg_->thread_list_.prev(this) != nullptr;
        is_last_thread = !has_next_thread && !has_prev_thread;    
        thread_links_.erase();
        // cpustate::schedule will free proc with pstate_ = ps_blank
        pstate_ = ps_blank;
        ptable[id_] = nullptr;
    }

    if (is_last_thread) {
        log_printf("is_last_thread for pid[%d] tgid[%d]\n", id_, tgid_);
        tg_->exit_cleanup(status);
    }
    yield_noreturn();
}

void proc::syscall_texit(regstate* regs) {
    int status = regs->reg_rdi;
    texit(status);
}

int proc::waitpid(pid_t tgid, int* stat, int options) {
    return tg_->waitpid(tgid, stat, options);
}

int proc::syscall_waitpid(regstate* regs) {
    pid_t pid = regs->reg_rdi;
    int* stat = (int*) regs->reg_rsi;
    int options = (int) regs->reg_rdx;

    return waitpid(pid, stat, options);
}

int proc::syscall_futex(regstate* regs) {
    uintptr_t addr = regs->reg_rdi;
    int futex_op = regs->reg_rsi;
    int val = regs->reg_rdx;

    // TODO validate parameters, make sure user can acess

    if (futex_op == FUTEX_WAIT) {
        global_futex_store.wait(addr, val);
        return 0;
    } else if (futex_op == FUTEX_WAKE) {
        global_futex_store.wake_n(addr, val);
        return 1;
    }
    return 0;
}

int proc::syscall_shmget(regstate* regs) {
    void* shared_page = kalloc(4096);

    int global_shmid = -1;
    int shmid = -1;

    shm* shared_mem = knew<shm>();
    shared_mem->kptr_ = shared_page;
    {
        spinlock_guard guard(shared_mem->ref_count_lock_);
        shared_mem->ref_count_ = 1;
    }
    {
        spinlock_guard guard(global_shm_store.list_lock_);
        for (int i = 0; i < N_GLOBAL_SHM; i++) {
            if (global_shm_store.list_[i] == nullptr) {
                global_shmid = i;
                break;
            }
        }
        if (global_shmid >= 0) {
            global_shm_store.list_[global_shmid] = shared_mem;
            shared_mem->id_ = global_shmid;
            log_printf("shmget:: %d || %d\n", shared_mem->kptr_, shared_mem->id_);
        }
    }

    if (global_shmid < 0) {
        // HANDLE FAILURE
        assert(false);
    }

    log_printf("shared memory page created at %p\n", shared_page);

    shmid = assign_to_open_shmid(shared_mem);
    if (shmid < 0) {
        assert(false);
    }

    return shmid;
}

uintptr_t proc::syscall_shmat(regstate* regs) {
    int shmid = regs->reg_rdi;
    uintptr_t shmaddr = regs->reg_rsi;

    // TODO: validate shmaddr and shmid

    shm_mapping* shared_mem = nullptr;
    {
        spinlock_guard guard(tg_->shm_mapping_table_lock_);
        shared_mem = &tg_->shm_mapping_table_[shmid];
    }

    if (!shared_mem) {
        assert(false);
    }
    
    if (vmiter(this, shmaddr).try_map(ka2pa(shared_mem->shm_->kptr_), PTE_PWU) < 0) {
        assert(false);
    }

    shared_mem->va_ = shmaddr;
    return shmaddr;
}

int proc::syscall_shmdt(regstate* regs) {
    uintptr_t shmaddr = regs->reg_rdi;

    // TODO: validate shmaddr

    void* kptr = vmiter(this, shmaddr).kptr();
}


int proc::close_fd(int fd, spinlock_guard& guard) {
    file* open_file = tg_->fd_table_[fd];
    if (!open_file) {
        return E_BADF;
    }

    // log_printf("CLOSING fd %d\n", fd);

    tg_->fd_table_[fd] = nullptr;
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
    for (size_t i = 0; i < max_char; i++) {
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
    

    // create file
    if ((flag & OF_CREATE) && (flag & OF_WRITE)) {
        log_printf("creating file %s \n", pathname);
        
        path_elements path(pathname);
        chkfs::inode* dirino =  chkfsstate::get().lookup_containing_directory_inode(pathname);
        if (!dirino) {
            return E_NOENT;
        }
        dirino->lock_write();
        chkfs::inode* created_ino = chkfsstate::get().create_file_in_directory(dirino, path.last());
        dirino->unlock_write();
        dirino->put();
        created_ino->put();
    }

    chkfsstate::inode* ino = nullptr;

    ino = chkfsstate::get().lookup_file_inode(pathname);
    if (!ino) {
        return E_NOENT;
    }

    vnode* v;
    file* f;
    int open_file_id = -1;
    int fd = -1;
    uint64_t is_read = (flag & OF_READ) ? VFS_FILE_READ : 0;
    uint64_t is_write = (flag & OF_WRITE) ? VFS_FILE_WRITE : 0;

    // TODO: cleanup on failure
    v = knew<inode_vnode>(ino);
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
        errno = E_NFILE;
        goto open_fail_free_open_file_table_slot;
    }

    if ((flag & OF_TRUNC) && (flag & OF_WRITE)) {
        ((inode_vnode*) v)->truncate();
    }

    return fd;

    // open_fail_free_fd_table_slot: {
    //     spinlock_guard guard(tg_->fd_table_lock_);
    //     tg_->fd_table_[fd] = nullptr;
    // }

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
        ino->put();
        assert(ino);
    }

    return errno;
}

int proc::syscall_close(regstate* regs) {
    int fd = regs->reg_rdi;
    assert(fd >= 0 && fd < N_FILE_DESCRIPTORS);
    spinlock_guard guard(tg_->fd_table_lock_);
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

    spinlock_guard guard(tg_->fd_table_lock_);
    file* file_to_dup = tg_->fd_table_[oldfd];
    file* open_file = tg_->fd_table_[newfd];
    
    if (!file_to_dup) {
        return E_BADF;
    }

    if (open_file) {
        close_fd(newfd, guard);
    }

    {
        spinlock_guard ref_count_guard(file_to_dup->ref_count_lock_);
        file_to_dup->ref_count_++;
        tg_->fd_table_[newfd] = file_to_dup;
    }
    return newfd;
}


int proc::assign_to_open_shmid(shm* s) {
    spinlock_guard guard(tg_->fd_table_lock_);
    return assign_to_open_shmid(s, guard);
}

int proc::assign_to_open_shmid(shm* s, spinlock_guard& guard) {
    int open_shmid = get_open_fd(guard);
    if (open_shmid < 0) {
        return -1;
    }
    tg_->shm_mapping_table_[open_shmid].shm_ = s;


    return open_shmid;
}

int proc::get_open_shmid(spinlock_guard& guard) {
    for (int i = 0; i < N_PER_PROC_SHMS; i++) {
        if (tg_->shm_mapping_table_[i].shm_ == nullptr) {
            return i;
        }
    }
    return -1;
}

int proc::get_open_fd(spinlock_guard& guard) {
    for (int i = 0; i < N_FILE_DESCRIPTORS; i++) {
        if (tg_->fd_table_[i] == nullptr) {
            return i;
        }
    }
    return -1;
}

int proc::assign_to_open_fd(file* f) {
    spinlock_guard guard(tg_->fd_table_lock_);
    return assign_to_open_fd(f, guard);
}

int proc::assign_to_open_fd(file* f, spinlock_guard& guard) {
    int open_fd = get_open_fd(guard);
    if (open_fd < 0) {
        return -1;
    }
    tg_->fd_table_[open_fd] = f;
    return open_fd;
}

int proc::syscall_mkdir(regstate* regs) {
    uintptr_t pathname_ptr = regs->reg_rdi;
    // uint64_t flag = regs->reg_rsi;
    if (!is_valid_pathname(pathname_ptr)) {
        return E_FAULT;
    }

    const char* pathname = reinterpret_cast<const char*>(pathname_ptr);
    log_printf("mkrdir %s\n", pathname);


    path_elements path(pathname);
    chkfs::inode* dirino =  chkfsstate::get().lookup_containing_directory_inode(pathname);
  
    if (!dirino) {
        log_printf("failed, subdirectory in path missing\n");
        return E_NOENT;
    }

    chkfs::inode* existing_dirino = chkfsstate::get().lookup_relative_directory_inode(dirino, path.last());
    if (existing_dirino) {
        existing_dirino->put();
        log_printf("failed, directory already exists\n");
        return E_INVAL;
    }

    chkfs::inum_t directory_inum = chkfsstate::get().create_inode(chkfs::type_directory);
    dirino->lock_write();
    chkfsstate::get().create_dirent(dirino, path.last(), directory_inum);

    // sanity check: directory shouldn't be empty
    int test = chkfsstate::get().is_directory_empty(dirino);
    assert(test == 0);

    dirino->unlock_write();
    dirino->put();
    return 0;
}

int proc::syscall_rmdir(regstate* regs) {
    uintptr_t pathname_ptr = regs->reg_rdi;
    // uint64_t flag = regs->reg_rsi;
    if (!is_valid_pathname(pathname_ptr)) {
        return E_FAULT;
    }


    const char* pathname = reinterpret_cast<const char*>(pathname_ptr);
    path_elements path(pathname);

    log_printf("rmdir %s\n", pathname);


    chkfs::inode* dirino = chkfsstate::get().lookup_directory_inode(pathname);
    if (!dirino) {
        return E_NOENT;
    }

    // Check if directory is empty

    dirino->lock_read();
    int result = chkfsstate::get().is_directory_empty(dirino);
    dirino->unlock_read();

    // Error code
    if (result < 0) {
        dirino->put();
        return result;
    } else if (result == 0) {
        dirino->put();
        return E_INVAL;
    }

    // Deallocate extents for the directory inode
    chkfs_fileiter it(dirino);
    dirino->lock_write();

    // TODO: switch to just iterating over extents so it's faster
    for (size_t diroff = 0; !it.find(diroff).empty(); diroff += chkfs::blocksize) {
        chkfsstate::get().deallocate_extent(it.find(diroff).blocknum(), 1);
    }

    // Free up inode from inode block
    dirino->entry()->get_write();
    dirino->type = 0;
    dirino->size = 0;
    dirino->nlink = 0;
    for (size_t i = 0; i < chkfs::ndirect; i++) {
        dirino->direct[i].first = 0;
        dirino->direct[i].count = 0;
    }
    dirino->indirect.first = 0;
    dirino->indirect.count = 0;
    dirino->entry()->put_write();
    dirino->unlock_write();

    auto& bc = bufcache::get();
    auto superblock_entry = bc.get_disk_entry(0);
    assert(superblock_entry);
    auto& sb = *reinterpret_cast<chkfs::superblock*>
        (&superblock_entry->buf_[chkfs::superblock_offset]);
    superblock_entry->put();

    chkfs::inum_t inum = (dirino->entry()->bn_ - sb.inode_bn) * chkfs::inodesperblock + ((uintptr_t) dirino - (uintptr_t) dirino->entry()->buf_) / sizeof(chkfs::inode);
    dirino->put();

    chkfs::inode* containing_dirino = chkfsstate::get().lookup_containing_directory_inode(pathname);
    // Free up from dirent

    containing_dirino->lock_write();
    int remove_dirent_result = chkfsstate::get().remove_dirent(containing_dirino, path.last(), inum);
    assert(remove_dirent_result == 1);
    containing_dirino->unlock_write();

    containing_dirino->put();

    return 0;
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
        spinlock_guard fd_table_guard(tg_->fd_table_lock_);
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
        spinlock_guard fd_table_guard(tg_->fd_table_lock_);
        if (read_fd >= 0) tg_->fd_table_[read_fd] = nullptr;
        if (write_fd >= 0) tg_->fd_table_[write_fd] = nullptr;
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
    ssize_t written = 0;

    int error_code = 0;
    char* pathname;

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

    new_pagetable = kalloc_pagetable();
    if (!new_pagetable) {
        error_code = E_NOMEM;
        goto bad_execv_return;
    }

    ino = chkfsstate::get().lookup_file_inode(pathname);
    if (!ino) {
        error_code = E_NOENT;
        goto bad_execv_return;
    }

    {
        inode_loader ld(ino, new_pagetable);
        assert(ld.inode_ && ld.pagetable_);
        int r = proc::load(ld);
        ino->put();
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

    tg_->init(tg_->tgid_, tg_->ppid_, new_pagetable);
    tg_->copy_fd_table_from_threadgroup(tgtable[1]);
    init_user(id_, tg_);

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

    tg_->free_shm_table();
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
    log_printf("FAILING!!\n");
    return error_code;
}

// proc::syscall_fork(regs)
//    Handle fork system call.

int proc::syscall_fork(regstate* regs) {
    assert(tg_->tgid_ == tgid_);
    log_printf("Calling fork on %d in %d\n", id_, tg_->tgid_);
    int error_code = 0;
    threadgroup* child_tg = nullptr;
    proc* child;
    x86_64_pagetable* child_pagetable;
    pid_t tgid = -1;
    pid_t pid = -1;
    irqstate irqs;

    child_tg = knew<threadgroup>();
    if (child_tg == nullptr) {
        log_printf("fork_failed: child_tg == nullptr \n");
        error_code = E_NOMEM;
        goto bad_fork_return;
    }
    irqs = tgtable_lock.lock();
    for (int i = 1; i < NPROC; i++) {
        if (tgtable[i] == nullptr) {
            tgid = i;
            break;
        }
    }
    if (tgid >= 0) {
        tgtable[tgid] = child_tg;
    }
    tgtable_lock.unlock(irqs);

    if (tgid < 0) {
        log_printf("fork_failed: tgid < 0 \n");
        error_code = E_AGAIN;
        goto bad_fork_free_threadgroup;
    }

    child = knew<proc>();
    if (child == nullptr) {
        log_printf("fork_failed: child == nullptr \n");
        error_code = E_NOMEM;
        goto bad_fork_free_tgid;
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

    {
        spinlock_guard guard(process_hierarchy_lock);
        child_tg->init(tgid, tgid_, child_pagetable);
        child->init_user(pid, child_tg);
        tg_->children_list_.push_back(child_tg);
    }

    assert(tg_);


    child_tg->copy_shm_mapping_table_from_threadgroup(tg_);
    // If there are any shared pages, remove existing mapping and map to shared memory location
    {
        spinlock_guard guard(tg_->shm_mapping_table_lock_);
        for (int i = 0; i < N_PER_PROC_SHMS; i++) {
            if (tg_->shm_mapping_table_[i].va_ != 0 && tg_->shm_mapping_table_[i].shm_ != nullptr) {
                vmiter it(child_tg->pagetable_, tg_->shm_mapping_table_[i].va_);
                it.kfree_page();
            }
        }
    }
    {
        spinlock_guard guard(child_tg->shm_mapping_table_lock_);
        for (int i = 0; i < N_PER_PROC_SHMS; i++) {
            if (child_tg->shm_mapping_table_[i].va_ != 0 && child_tg->shm_mapping_table_[i].shm_ != nullptr) {
                vmiter it(child_tg->pagetable_, child_tg->shm_mapping_table_[i].va_);
                vmiter parent_it(tg_->pagetable_, child_tg->shm_mapping_table_[i].va_);
                log_printf("BEFORE %p\n", child_tg->shm_mapping_table_[i].shm_);
                log_printf("about to map %p => %p\n", child_tg->shm_mapping_table_[i].va_, child_tg->shm_mapping_table_[i].shm_->kptr_);
                if (it.try_map(child_tg->shm_mapping_table_[i].shm_->kptr_, parent_it.perm()) < 0) {
                    assert(false);
                }
            }

        }
    }

    // copy over file descriptor table from parent
    child_tg->copy_fd_table_from_threadgroup(tg_);

    child_tg->add_proc_to_thread_list(child);

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

    bad_fork_free_tgid: {
        assert(child_pagetable == nullptr);
        assert(tgid > 0);
        irqs = tgtable_lock.lock();
        tgtable[tgid] = nullptr;
        tgtable_lock.unlock(irqs);    
        tgid = -1;
    }

    bad_fork_free_threadgroup: {
        assert(child_tg != nullptr);
        kfree(child_tg);
        child_tg = nullptr; 
    }

    bad_fork_return: {
        assert(child == nullptr);
        assert(child_tg == nullptr);
    }
    
    return error_code;
}

void proc::syscall_exit(regstate* regs) {
    exit_status_ = (int) regs->reg_rdi;
    log_printf("EXITING syscall_exit status [%d] for tgid[%d] pid[%d]\n", regs->reg_rdi, tgid_, id_);
    tg_->should_exit_ = true;
    tg_->process_exit_status_ = exit_status_;
    {
        spinlock_guard guard(tg_->thread_list_lock_);
        for (proc* thread = tg_->thread_list_.front(); thread; thread = tg_->thread_list_.next(thread)) {
            if (thread != this) {
                thread->wake();
            }
        }

    }
    syscall_texit(regs);
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

    log_printf("syscall_read fd[%d] pid[%d] tgid[%d]\n", fd, id_, tgid_);

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
        spinlock_guard fd_table_guard(tg_->fd_table_lock_);
        file = tg_->fd_table_[fd];
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
        spinlock_guard fd_table_guard(tg_->fd_table_lock_);
        file = tg_->fd_table_[fd];
    }

    // No need to keep holding fd_table_guard because the file will not get deleted while you're reading it (ref count will never be 0)
    if (!file) {
        return E_BADF;
    }
    return file->vfs_write(reinterpret_cast<char*>(addr), sz);
}

ssize_t proc::syscall_lseek(regstate* regs) {
    int fd = regs->reg_rdi;
    size_t offset = regs->reg_rsi;
    uint64_t flag = regs->reg_rdx;

    if (
        flag != LSEEK_SET &&
        flag != LSEEK_CUR &&
        flag != LSEEK_END &&
        flag != LSEEK_SIZE
    ) {
        return E_INVAL;
    }

    if (fd < 0 || fd >= N_FILE_DESCRIPTORS) {
        return E_BADF;
    }
    
    file* file = nullptr;
    {
        spinlock_guard fd_table_guard(tg_->fd_table_lock_);
        file = tg_->fd_table_[fd];
    }

    // No need to keep holding fd_table_guard because the file will not get deleted while you're reading it (ref count will never be 0)
    if (!file) {
        return E_BADF;
    }

    return file->vfs_lseek(offset, flag);
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
    auto ino = chkfsstate::get().lookup_file_inode(filename);
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
