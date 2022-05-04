#ifndef CHICKADEE_KERNEL_HH
#define CHICKADEE_KERNEL_HH
#include "x86-64.h"
#include "lib.hh"
#include "k-list.hh"
#include "k-lock.hh"
#include "k-memrange.hh"
#include "k-waitstruct.hh"
#include "k-vfs.hh"
#include "k-futex.hh"
#if CHICKADEE_PROCESS
#error "kernel.hh should not be used by process code."
#endif
struct proc;
struct threadgroup;
struct yieldstate;
struct proc_loader;
struct elf_program;
struct buddyallocator;
struct timingwheel;
#define PROC_RUNNABLE 1
#define STACK_CANARY_VALUE 3482


// kernel.hh
//
//    Functions, constants, and definitions for the kernel.

#define N_GLOBAL_OPEN_FILES     32
extern file* open_file_table[N_GLOBAL_OPEN_FILES];
extern spinlock open_file_table_lock;

#define N_FILE_DESCRIPTORS 32
// Process descriptor type
struct __attribute__((aligned(4096))) proc {
    enum pstate_t {
        ps_blank = 0, ps_runnable = PROC_RUNNABLE, ps_faulted, ps_exited, ps_blocked
    };

    // These four members must come first:
    pid_t id_ = 0;                             // Process ID
    regstate* regs_ = nullptr;                 // Process's current registers
    yieldstate* yields_ = nullptr;             // Process's current yield state
    std::atomic<int> pstate_ = ps_blank;       // Process state

    x86_64_pagetable* pagetable_ = nullptr;    // Process's page table // TODO: should delete for multithreading
    uintptr_t recent_user_rip_ = 0;            // Most recent user-mode %rip
#if HAVE_SANITIZERS
    int sanitizer_status_ = 0;
#endif

    list_links runq_links_;

    list_links thread_links_;

    pid_t tgid_;
    threadgroup* tg_;

    int exit_status_;
    int resume_count_ = 0;
    int home_cpuindex_;
    wait_queue wq_;

    int stack_canary_ = STACK_CANARY_VALUE;

    proc();
    NO_COPY_OR_ASSIGN(proc);

    inline bool contains(uintptr_t addr) const;
    inline bool contains(void* ptr) const;

    void init_user(pid_t pid, threadgroup* tg);
    void init_kernel(pid_t pid, threadgroup* tg, void (*f)());

    // void init_user(pid_t pid, pid_t ppid, x86_64_pagetable* pt);
    // void init_kernel(pid_t pid, pid_t ppid, void (*f)());

    static int load(proc_loader& ld);

    void exception(regstate* reg);
    uintptr_t run_syscall(regstate* reg);
    uintptr_t syscall(regstate* reg);

    void yield();
    [[noreturn]] void yield_noreturn();
    [[noreturn]] void resume();
    [[noreturn]] void panic_nonrunnable();

    inline bool resumable() const;

    int syscall_nastyalloc(int n);
    int syscall_testkalloc(uintptr_t heap_top, uintptr_t stack_bottom, int mode);
    int syscall_testfree(uintptr_t heap_top, uintptr_t stack_bottom);
    
    int syscall_fork(regstate* regs);
    void syscall_exit(regstate* regs);

    void syscall_texit(regstate* regs);
    int syscall_clone(regstate* regs);

    int syscall_waitpid(regstate* regs);

    int syscall_msleep(regstate* regs);

    int syscall_futex(regstate* regs);

    int syscall_open(regstate* reg);

    uintptr_t syscall_read(regstate* reg);
    uintptr_t syscall_write(regstate* reg);
    uintptr_t syscall_readdiskfile(regstate* reg);
    ssize_t syscall_lseek(regstate* reg);

    int syscall_execv(regstate* reg);

    int syscall_dup2(regstate* reg);
    int syscall_close(regstate* reg);
    uint64_t syscall_pipe(regstate* reg);

    int syscall_mkdir(regstate* reg);
    int syscall_rmdir(regstate* reg);

    int get_open_fd(spinlock_guard& guard);
    int assign_to_open_fd(file* f);
    int assign_to_open_fd(file* f, spinlock_guard& guard);

    int get_available_open_file_table_id(spinlock_guard& guard);
    int add_to_open_file_table(file* f);
    int add_to_open_file_table(file* f, spinlock_guard& guard);

    int close_fd(int fd, spinlock_guard& guard);

    void copy_fd_table_from_proc(proc* source);

    bool is_valid_string(char* str, size_t max_char);
    bool is_valid_pathname(uintptr_t pathname);
    bool is_valid_argument(uintptr_t argv, int argc);
    bool is_valid_fd(int fd);

    ssize_t copy_argument_to_stack_end(uintptr_t stack_end, uintptr_t stack_end_va, uintptr_t argv_val, int argc);

    int waitpid(pid_t pid, int* stat, int options);
    void texit(int status);

    void wake();

    inline irqstate lock_pagetable_read();
    inline void unlock_pagetable_read(irqstate& irqs);

 private:
    static int load_segment(const elf_program& ph, proc_loader& ld);
};

struct __attribute__((aligned(4096))) threadgroup {
    pid_t tgid_;
    pid_t ppid_;
    x86_64_pagetable* pagetable_ = nullptr;    // Process's page table
    file* fd_table_[N_FILE_DESCRIPTORS];
    spinlock fd_table_lock_;
    list_links sibling_links_;
    list<threadgroup, &threadgroup::sibling_links_> children_list_;

    wait_queue process_wq_;

    int process_exit_status_;
    std::atomic<bool> is_exited_ = false;

    std::atomic<bool> interrupt_sleep_ = false;
    std::atomic<bool> should_exit_ = false;

    list<proc, &proc::thread_links_> thread_list_;
    spinlock thread_list_lock_;

    threadgroup();
    void init(pid_t tgid, pid_t ppid, x86_64_pagetable* pt);
    static pid_t assign_to_empty_tgid(spinlock_guard &guard, threadgroup* tg);
    void init_fd_table();
    void add_proc_to_thread_list(proc* p);
    void copy_fd_table_from_threadgroup(threadgroup* tg);

    threadgroup* get_child(pid_t tgid, spinlock_guard &process_hierarchy_lock);
    threadgroup* get_any_exited_child(spinlock_guard &process_hierarchy_lock);

    int waitpid(pid_t tgid, int* stat, int options);
    void exit(int status);
    void exit_cleanup(int status);
    
    bool is_exited(spinlock_guard &guard);

};

#define NTHREADGROUP 16
extern threadgroup* tgtable[NTHREADGROUP];
extern spinlock tgtable_lock;
extern spinlock process_hierarchy_lock;

#define NPROC 16
extern proc* ptable[NPROC];
extern spinlock ptable_lock;
#define PROCSTACK_SIZE 4096UL


struct proc_loader {
    x86_64_pagetable* pagetable_;
    uintptr_t entry_rip_ = 0;
    inline proc_loader(x86_64_pagetable* pt)
        : pagetable_(pt) {
    }
    virtual ssize_t get_page(uint8_t** pg, size_t off) = 0;
    virtual void put_page() = 0;
};



// CPU state type
struct __attribute__((aligned(4096))) cpustate {
    // These three members must come first:
    cpustate* self_;
    proc* current_ = nullptr;
    uint64_t syscall_scratch_;

    int cpuindex_;
    int lapic_id_;

    list<proc, &proc::runq_links_> runq_;
    spinlock runq_lock_;
    unsigned long nschedule_;
    proc* idle_task_;

    unsigned spinlock_depth_;

    uint64_t gdt_segments_[7];
    x86_64_taskstate taskstate_;


    inline cpustate()
        : self_(this) {
    }
    NO_COPY_OR_ASSIGN(cpustate);

    inline bool contains(uintptr_t addr) const;
    inline bool contains(void* ptr) const;

    void init();
    void init_ap();

    void exception(regstate* reg);

    void enqueue(proc* p);
    [[noreturn]] void schedule(proc* yielding_from);

    void enable_irq(int irqno);
    void disable_irq(int irqno);

 private:
    void init_cpu_hardware();
    void init_idle_task();
};

#define MAXCPU 16
extern cpustate cpus[MAXCPU];
extern int ncpu;
#define CPUSTACK_SIZE 4096UL
#define CPUALTSTACK_SIZE 3072UL

inline cpustate* this_cpu();


// yieldstate: callee-saved registers that must be preserved across
// proc::yield()

struct yieldstate {
    uintptr_t reg_rbp;
    uintptr_t reg_rbx;
    uintptr_t reg_r12;
    uintptr_t reg_r13;
    uintptr_t reg_r14;
    uintptr_t reg_r15;
    uintptr_t reg_rflags;
};


// timekeeping

// `HZ` defines the number of timer interrupts per second, or ticks.
// Real kernels typically use 100 or 1000; Chickadee typically uses 100.
// Exception: Sanitizers slow down the kernel so much that recursive timer
// interrupts can become a problem, so when sanitizers are on, we reduce the
// interrupt frequency to 10 per second.
#if HAVE_SANITIZERS
# define HZ 10
#else
# define HZ 100
#endif

extern std::atomic<unsigned long> ticks;        // number of ticks since boot


// Segment selectors
#define SEGSEL_BOOT_CODE        0x8             // boot code segment
#define SEGSEL_KERN_CODE        0x8             // kernel code segment
#define SEGSEL_KERN_DATA        0x10            // kernel data segment
#define SEGSEL_APP_CODE         0x18            // application code segment
#define SEGSEL_APP_DATA         0x20            // application data segment
#define SEGSEL_TASKSTATE        0x28            // task state segment


// Physical memory size
#define MEMSIZE_PHYSICAL        0x200000
// Virtual memory size
#define MEMSIZE_VIRTUAL         0x300000

enum memtype_t {
    mem_nonexistent = 0,
    mem_available = 1,
    mem_kernel = 2,
    mem_reserved = 3,
    mem_console = 4
};
extern memrangeset<16> physical_ranges;


// Hardware interrupt numbers
#define INT_IRQ                 32U
#define IRQ_TIMER               0
#define IRQ_KEYBOARD            1
#define IRQ_IDE                 14
#define IRQ_ERROR               19
#define IRQ_SPURIOUS            31

#define KTEXT_BASE              0xFFFFFFFF80000000UL
#define HIGHMEM_BASE            0xFFFF800000000000UL

inline uint64_t pa2ktext(uint64_t pa) {
    assert(pa < -KTEXT_BASE);
    return pa + KTEXT_BASE;
}

template <typename T>
inline T pa2ktext(uint64_t pa) {
    return reinterpret_cast<T>(pa2ktext(pa));
}

inline uint64_t ktext2pa(uint64_t ka) {
    assert(ka >= KTEXT_BASE);
    return ka - KTEXT_BASE;
}

template <typename T>
inline uint64_t ktext2pa(T* ptr) {
    return ktext2pa(reinterpret_cast<uint64_t>(ptr));
}


inline uint64_t pa2ka(uint64_t pa) {
    assert(pa < -HIGHMEM_BASE);
    return pa + HIGHMEM_BASE;
}

template <typename T>
inline T pa2kptr(uint64_t pa) {
    static_assert(std::is_pointer<T>::value, "T must be pointer");
    return reinterpret_cast<T>(pa2ka(pa));
}

inline uint64_t ka2pa(uint64_t ka) {
    assert(ka >= HIGHMEM_BASE && ka < KTEXT_BASE);
    return ka - HIGHMEM_BASE;
}

template <typename T>
inline uint64_t ka2pa(T* ptr) {
    return ka2pa(reinterpret_cast<uint64_t>(ptr));
}

inline uint64_t kptr2pa(uint64_t kptr) {
    assert(kptr >= HIGHMEM_BASE);
    return kptr - (kptr >= KTEXT_BASE ? KTEXT_BASE : HIGHMEM_BASE);
}

template <typename T>
inline uint64_t kptr2pa(T* ptr) {
    return kptr2pa(reinterpret_cast<uint64_t>(ptr));
}

template <typename T>
inline bool is_kptr(T* ptr) {
    uintptr_t va = reinterpret_cast<uint64_t>(ptr);
    return va >= HIGHMEM_BASE;
}

template <typename T>
inline bool is_ktext(T* ptr) {
    uintptr_t va = reinterpret_cast<uint64_t>(ptr);
    return va >= KTEXT_BASE;
}


template <typename T>
inline T read_unaligned(const uint8_t* x) {
    T a;
    memcpy(&a, x, sizeof(T));
    return a;
}
template <typename T>
inline T read_unaligned_pa(uint64_t pa) {
    return read_unaligned<T>(pa2kptr<const uint8_t*>(pa));
}
template <typename T, typename U>
inline T read_unaligned(const uint8_t* ptr, T (U::* member)) {
    alignas(U) char space[sizeof(U)] = {};
    U* dummy = (U*)(space);
    T a;
    memcpy(&a, ptr + (reinterpret_cast<uintptr_t>(&(dummy->*member)) - reinterpret_cast<uintptr_t>(dummy)), sizeof(T));
    return a;
}

extern timingwheel timer_queue;
extern spinlock timer_lock;

#define TIMING_WHEEL_QUEUE_COUNT 64

struct timingwheel {
    int n_ = TIMING_WHEEL_QUEUE_COUNT;
    wait_queue wqs_[TIMING_WHEEL_QUEUE_COUNT];

    wait_queue* get_wq_for_time(uint64_t time);
    void wake_for_time(uint64_t time);
    void wake_all();

    timingwheel();
};

#define BUDDY_ALLOCATOR_MIN_ORDER 12
#define BUDDY_ALLOCATOR_MAX_ORDER 21

extern buddyallocator allocator;

struct pagestatus {
    int order;
    bool is_free;
    list_links link_;
};

struct buddyallocator {
    const int min_order_ = BUDDY_ALLOCATOR_MIN_ORDER;
    const int max_order_ = BUDDY_ALLOCATOR_MAX_ORDER;
    pagestatus pages_[MEMSIZE_PHYSICAL / PAGESIZE];
    list<pagestatus, &pagestatus::link_> free_lists_[BUDDY_ALLOCATOR_MAX_ORDER - BUDDY_ALLOCATOR_MIN_ORDER + 1];

    buddyallocator();
    void init();
    uintptr_t allocate(size_t size);
    int free(uintptr_t addr);

 private:
    pagestatus* split_to_order(pagestatus* pg, int order);
    void merge(pagestatus* pg);
    pagestatus* merge_buddies(pagestatus* buddy1, pagestatus* buddy2);
    int find_buddy_id(int page_id);
    int find_buddy_id_for_order(int page_id, int order);
    bool is_index_aligned(int page_id, int order);
    int get_index_offset(int order);
    int pg2pi(pagestatus* pg);
    uintptr_t pg2pa(pagestatus* pg);
    int pa2pi(uintptr_t pa);
    pagestatus* pa2pg(uintptr_t pa);
    pagestatus* find_smallest_free(int order);
    int get_desired_order(size_t size);
    void init_range(uintptr_t start, uintptr_t end);
    void init_reserved_range(uintptr_t start, uintptr_t end);
    int max_order_allocable(uintptr_t start, uintptr_t end);

    bool is_pa_free(uintptr_t pa);
    bool is_allocated_block(uintptr_t pa);
};

// kalloc(sz)
//    Allocate and return a pointer to at least `sz` contiguous bytes
//    of memory. Returns `nullptr` if `sz == 0` or on failure.
//
//    If `sz` is a multiple of `PAGESIZE`, the returned pointer is guaranteed
//    to be page-aligned.
void* kalloc(size_t sz) __attribute__((malloc));

// kfree(ptr)
//    Free a pointer previously returned by `kalloc`. Does nothing if
//    `ptr == nullptr`.
void kfree(void* ptr);

void kfree_all_user_mappings(x86_64_pagetable* pt);
void kfree_pagetable(x86_64_pagetable* pt);

// operator new, operator delete
//    Expressions like `new (std::nothrow) T(...)` and `delete x` work,
//    and call kalloc/kfree.
void* operator new(size_t sz, const std::nothrow_t&) noexcept;
void* operator new(size_t sz, std::align_val_t al, const std::nothrow_t&) noexcept;
void* operator new[](size_t sz, const std::nothrow_t&) noexcept;
void* operator new[](size_t sz, std::align_val_t al, const std::nothrow_t&) noexcept;
void operator delete(void* ptr) noexcept;
void operator delete(void* ptr, size_t sz) noexcept;
void operator delete(void* ptr, std::align_val_t al) noexcept;
void operator delete(void* ptr, size_t sz, std::align_val_t al) noexcept;
void operator delete[](void* ptr) noexcept;
void operator delete[](void* ptr, size_t sz) noexcept;
void operator delete[](void* ptr, std::align_val_t al) noexcept;
void operator delete[](void* ptr, size_t sz, std::align_val_t al) noexcept;

// knew<T>(), knew<T>(args...)
//    Like `new (std::nothrow) T(args...)`.
template <typename T>
inline __attribute__((malloc)) T* knew() {
    return new (std::nothrow) T;
}
template <typename T, typename... Args>
inline __attribute__((malloc)) T* knew(Args&&... args) {
    return new (std::nothrow) T(std::forward<Args>(args)...);
}

// init_kalloc
//    Initialize stuff needed by `kalloc`. Called from `init_hardware`,
//    after `physical_ranges` is initialized.
void init_kalloc();


// Initialize hardware and CPUs
void init_hardware();

// Query machine configuration
unsigned machine_ncpu();
unsigned machine_pci_irq(int pci_addr, int intr_pin);

struct ahcistate;
extern ahcistate* sata_disk;


// Early page table (only kernel mappings)
extern x86_64_pagetable early_pagetable[3];

// Allocate and initialize a new, empty page table
x86_64_pagetable* kalloc_pagetable();

// Change current page table
void set_pagetable(x86_64_pagetable* pagetable);

// Print memory viewer
void console_memviewer(proc* p);


// Start the kernel
[[noreturn]] void kernel_start(const char* command);

// Turn off the virtual machine
[[noreturn]] void poweroff();

// Reboot the virtual machine
[[noreturn]] void reboot();

// Call after last process exits
[[noreturn]] void process_halt();


// log_printf, log_vprintf
//    Print debugging messages to the host's `log.txt` file. We run QEMU
//    so that messages written to the QEMU "parallel port" end up in `log.txt`.
__noinline void log_printf(const char* format, ...);
__noinline void log_vprintf(const char* format, va_list val);


// log_backtrace
//    Print a backtrace to the host's `log.txt` file, either for the current
//    stack or for a given stack range.
void log_backtrace(const char* prefix = "");
void log_backtrace(const char* prefix, uintptr_t rsp, uintptr_t rbp);


// lookup_symbol(addr, name, start)
//    Use the debugging symbol table to look up `addr`. Return the
//    corresponding symbol name (usually a function name) in `*name`
//    and the first address in that symbol in `*start`.
__no_asan
bool lookup_symbol(uintptr_t addr, const char** name, uintptr_t* start);


#if HAVE_SANITIZERS
// Sanitizer functions
void init_sanitizers();
void disable_asan();
void enable_asan();
void asan_mark_memory(unsigned long pa, size_t sz, bool poisoned);
#else
inline void disable_asan() {}
inline void enable_asan() {}
inline void asan_mark_memory(unsigned long pa, size_t sz, bool poisoned) {}
#endif


// `panicking == true` iff some CPU has panicked
extern std::atomic<bool> panicking;


// this_cpu
//    Return a pointer to the current CPU. Requires disabled interrupts.
inline cpustate* this_cpu() {
    assert(is_cli());
    cpustate* result;
    asm volatile ("movq %%gs:(0), %0" : "=r" (result));
    return result;
}

// current
//    Return a pointer to the current `struct proc`.
inline proc* current() {
    proc* result;
    asm volatile ("movq %%gs:(8), %0" : "=r" (result));
    return result;
}

// adjust_this_cpu_spinlock_depth(delta)
//    Adjust this CPU's spinlock_depth_ by `delta`. Does *not* require
//    disabled interrupts.
inline void adjust_this_cpu_spinlock_depth(int delta) {
    asm volatile ("addl %1, %%gs:%0"
                  : "+m" (*reinterpret_cast<int*>
                          (offsetof(cpustate, spinlock_depth_)))
                  : "er" (delta) : "cc", "memory");
}

// cpustate::contains(ptr)
//    Return true iff `ptr` lies within this cpustate's allocation.
inline bool cpustate::contains(void* ptr) const {
    return contains(reinterpret_cast<uintptr_t>(ptr));
}
inline bool cpustate::contains(uintptr_t addr) const {
    uintptr_t delta = addr - reinterpret_cast<uintptr_t>(this);
    return delta <= CPUSTACK_SIZE;
}

// proc::contains(ptr)
//    Return true iff `ptr` lies within this cpustate's allocation.
inline bool proc::contains(void* ptr) const {
    return contains(reinterpret_cast<uintptr_t>(ptr));
}
inline bool proc::contains(uintptr_t addr) const {
    uintptr_t delta = addr - reinterpret_cast<uintptr_t>(this);
    return delta <= PROCSTACK_SIZE;
}

// proc::resumable()
//    Return true iff this `proc` can be resumed (`regs_` or `yields_`
//    is set). Also checks some assertions about `regs_` and `yields_`.
inline bool proc::resumable() const {
    assert(!(regs_ && yields_));            // at most one at a time
    assert(!regs_ || contains(regs_));      // `regs_` points within this
    assert(!yields_ || contains(yields_));  // same for `yields_`
    return regs_ || yields_;
}

// proc::lock_pagetable_read()
//    Obtain a “read lock” on this process’s page table. While the “read
//    lock” is held, it is illegal to remove or change existing valid
//    mappings in that page table, or to free page table pages.
inline irqstate proc::lock_pagetable_read() {
    return irqstate();
}
inline void proc::unlock_pagetable_read(irqstate&) {
}

#endif
