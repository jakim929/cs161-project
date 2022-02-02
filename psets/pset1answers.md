CS 161 Problem Set 1 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset1collab.md`.

Answers to written questions
----------------------------

A. Memory allocator
1. Currently, the max size is PAGESIZE, which is 4096 bytes.

2. 0xffff800000001000. In k-init.cc init_physical_ranges() function, the 0 page [0x0, 0x1000) of physical memory is reserved for the nullptr. Therefore, the first address returned is the physical address 0x1000, which is mapped to 0xffff800000001000 virtual memory by pa2kptr().

3. 0xffff8000001ff000

4. It returns high canonical (kernel virtual) addresses. This is done in the line that calls pa2kptr. In kernel.hh, we can see that pa2kptr calls pa2ka, which adds the base physical address to HIGHMEM_BASE, mapping it to the beginning of the high canonocal kernel virtual address (0xFFFF800000000000UL)

5. In init_physical_ranges() in k-init.cc, we can replace MEMSIZE_PHYSICAL with 0x300000 to make more memory available to the kernel. We can do this by setting [0, 0x300000] to mem_available.
ie) `physical_ranges.set(0, 0x300000, mem_available);`

6. 
```
    while (
        next_free_pa < physical_ranges.limit() &&
        physical_ranges.type(next_free_pa) != mem_available
    ) {
        next_free_pa += PAGESIZE;
    }
    if (next_free_pa < physical_ranges.limit()) {
        ptr = pa2kptr<void*>(next_free_pa);
        next_free_pa += PAGESIZE;
    }
```
7. The simplified loop above has to iterate through reserved ranges using PAGESIZE intervals. The old loop using find() was able to skip over the entire ranges of reserved sections. This was done by moving to the end of a range using `range->last()`.
Therefore, in the new version, skipping over kernel text and data takes size / PAGESIZE iterations rather than 1 iteration (in the initial implementation).


8. Concurrent processes calling kalloc() may be assigned the same address, due to a race condition happening on the global variable next_free_pa.
If process 1 iterates through physical_ranges to find the next available page, and process 2 attempts does the same before process 1 updates next_free_pa, both processes will assume that the same block is empty, and return the same address.

B. Memory viewer
1. Line 86 
`mark(pa, f_kernel);`

2. Line 96
`mark(ka2pa(p), f_kernel | f_process(pid));`

3.  The ptiter loop marks the physical addresses containing the actual pagetable pages as kernel-restricted. The vmiter loop iterates through the virtual address mappings pointed to by the process's pagetables, then marks the physical addresses pointed to as user-accessible. If the pages in ptiter loop were user-accessible, then it would be possible for user code to update the pagetable pages and rewrite the virtual => physical mappings to any arbitrary location in memory. In doing so, the user level code can access parts of physical memory that are should only be accessible by the kernel.

4. They are of type `mem_available`. All processes should only be able to kalloc parts of physical memory that has not been reserved or is being used for kernel text, hence they should be all of type `mem_available`.

5. They seem to operate the same way. The vmiter.next() function skips over holes in virtual memory space. Since we don't have any holes to skip over, next() iterates over the virtual memory space the same way as it+=PAGESIZE, and we can't see a difference in performance right now.

6. The first two of these pages are allocated in `cpustate::init_idle_task()`. The memory is allocated for the `proc* idle_task_` inside cpustate. The last of these pages is allocated in `memusage::refresh()` in order to initialize `v_`, the variable that stores the current `memusage` state to show in the memviewer.

7. I first marked the physical address pointed to by the virtual address in memusage.v_ as `f_kernel`. 

```
    mark(ka2pa(v_), f_kernel);
```
Then, iterating through the `cpustate` structs in `cpus`, I marked the `cpustate.idle_task_` pointer as `f_kernel`.

```
    for (int cpuid = 0; cpuid < ncpu; cpuid++) {
        cpustate* cpu = &cpus[cpuid];
        if (cpu->idle_task_) {
            mark(ka2pa(cpu->idle_task_), f_kernel);
        }
    }
```

Grading notes
-------------
