#include "kernel.hh"
#include "k-lock.hh"
#include "k-vmiter.hh"

static spinlock page_lock;
// static uintptr_t next_free_pa;
buddyallocator allocator;

// init_kalloc
//    Initialize stuff needed by `kalloc`. Called from `init_hardware`,
//    after `physical_ranges` is initialized.
void init_kalloc() {
    // do nothing for now
    allocator.init();
}

// kalloc(sz)
//    Allocate and return a pointer to at least `sz` contiguous bytes of
//    memory. Returns `nullptr` if `sz == 0` or on failure.
//
//    The caller should initialize the returned memory before using it.
//    The handout allocator sets returned memory to 0xCC (this corresponds
//    to the x86 `int3` instruction and may help you debug).
//
//    If `sz` is a multiple of `PAGESIZE`, the returned pointer is guaranteed
//    to be page-aligned.
//
//    The handout code does not free memory and allocates memory in units
//    of pages.
void* kalloc(size_t sz) {
    if (sz == 0 || sz > (1 << BUDDY_ALLOCATOR_MAX_ORDER)) {
        return nullptr;
    }

    auto irqs = page_lock.lock();
    void* ptr = nullptr;

    uintptr_t pa = allocator.allocate(sz);
    ptr = pa == 0 ? nullptr: pa2kptr<void*>(pa);

    // skip over reserved and kernel memory
    // while (
    //     next_free_pa < physical_ranges.limit() &&
    //     physical_ranges.type(next_free_pa) != mem_available
    // ) {
    //     next_free_pa += PAGESIZE;
    // }
    // if (next_free_pa < physical_ranges.limit()) {
    //     ptr = pa2kptr<void*>(next_free_pa);

    //     next_free_pa += PAGESIZE;
    // }

    // auto range = physical_ranges.find(next_free_pa);
    // while (range != physical_ranges.end()) {
    //     log_printf("%p is in [%p, %p) of type %d\n",
    //        next_free_pa, range->first(), range->last(), range->type());

    //     if (range->type() == mem_available) {
    //         // use this page
    //         ptr = pa2kptr<void*>(next_free_pa);
    //         next_free_pa += PAGESIZE;
    //         break;
    //     } else {
    //         // move to next range
    //         next_free_pa = range->last();
    //         ++range;
    //     }
    // }

    page_lock.unlock(irqs);

    if (ptr) {
        // tell sanitizers the allocated page is accessible
        asan_mark_memory(ka2pa(ptr), sz, false);
        // initialize to `int3`
        memset(ptr, 0xCC, sz);
    }

    return ptr;
}


// kfree(ptr)
//    Free a pointer previously returned by `kalloc`. Does nothing if
//    `ptr == nullptr`.
void kfree(void* ptr) {
    if (ptr == nullptr) {
        return;
    }

    auto irqs = page_lock.lock();

    int order_freed = allocator.free(ka2pa(reinterpret_cast<uintptr_t>(ptr)));

    page_lock.unlock(irqs);
    // tell sanitizers the freed page is inaccessible
    asan_mark_memory(ka2pa(ptr), 1 << order_freed, true);
}

// kfree_all(x86)
//    Frees all user-accessible memory pointed to in pagetable
//    TODO: update to delete multiple page sizes.
//          currently only support PAGESIZE since
void kfree_all_user_mappings(x86_64_pagetable* pt) {
    for (vmiter it(pt, 0); it.low(); it.next()) {
        if (it.present() && !it.user()) {
            assert(false);
        }
        if (it.user()) {
            // Don't free page if mapped to console
            if (
                it.va() != (uintptr_t) console &&
                !(it.va() == 0xB8000 && it.pa() == 0xB8000)
            ) {
                it.kfree_page();
            }
        }
    }
}

void kfree_pagetable(x86_64_pagetable* pt) {
    for (ptiter it(pt); it.low(); it.next()) {
        it.kfree_ptp();
    }
    kfree(pt);
}

// operator new, operator delete
//    Expressions like `new (std::nothrow) T(...)` and `delete x` work,
//    and call kalloc/kfree.
void* operator new(size_t sz, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void* operator new(size_t sz, std::align_val_t, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void* operator new[](size_t sz, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void* operator new[](size_t sz, std::align_val_t, const std::nothrow_t&) noexcept {
    return kalloc(sz);
}
void operator delete(void* ptr) noexcept {
    kfree(ptr);
}
void operator delete(void* ptr, size_t) noexcept {
    kfree(ptr);
}
void operator delete(void* ptr, std::align_val_t) noexcept {
    kfree(ptr);
}
void operator delete(void* ptr, size_t, std::align_val_t) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr, size_t) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr, std::align_val_t) noexcept {
    kfree(ptr);
}
void operator delete[](void* ptr, size_t, std::align_val_t) noexcept {
    kfree(ptr);
}
