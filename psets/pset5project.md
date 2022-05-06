What was your goal?
My goal was to build a futex implementation. I only support FUTEX_WAIT and FUTEX_WAKE flags currently. As part of the testing, I also implemented a inter-process shared memory pages similar to linux's shmget and shmat.

What’s your design?

FUTEX

The kernel maintains a global set of futexes in global_futex_store. 

The futex object
Each futex object has a unique key (the addr_), a wait queue, and a spinlock. 

FUTEX_WAIT
The kernel looks for an existing waitqueue associated with the given address, then locks it, before checking if val == *futex_addr. It returns immediately if val != *futex_addr, but otherwise, adds it to the wait queue and begins blocking. There is no predicate to check before waking from the blocked state, and the thread simply sleeps until it is woken.

If it can't find a waitqueue associated with the given addr, it looks for an empty slot in the global_futex_store.list_ then stores it in there.

The synchronization is handled through the futex_store::list_lock_ and futex::lock_.

FUTEX_WAKE

The kernel looks for the futex and waitqueue associated with that address.

If the addr for the futex that the process requests to wake doesn't have any processes in the waitqueue, it is a no-op, and simply returns.


Memory management for futexes is quite simple. Whenever the waitqueue becomes empty, the futex slot addr_ becomes 0, and the futex slot can be claimed by another process to use.

SHARED MEMORY

The design is quite similar to the file descriptor table and open_file_table implementation.

There is a global list of shared memory pages. The shm object holds a refcount for how many processes have access to this shared memory page. When the ref_count reaches zero, the shm and the underlying kalloced page is freed. The refcount for a shm is decremented on a process' exit.

Each process holds a shm_mapping_table_, which has bookkeeping details on what virtual memory the underlying shared memory page was mapped to. Different processes can map the same underlying memory page to different virtual addresses if intended.

The shared memory are copied in fork, and the fork code makes sure that the virtual addresses pointing to shared memory pages point to the same physical memory upon fork. 

I currently support shmget (getting a shared page) and shmat (mapping the shared page to a user defined virtual address)

What code did you write (what files and functions)?

wrote k-futex.hh
wrote k-futex.cc
wrote k-shm.hh
changed some parts of k-wait.hh && k-waitstruct.hh
updated threadgroup.cc & kernel.cc to handle futex 
wrote tests p-testshm, p-testfutex, p-testfutexshm, p-testmutex

What challenges did you encounter?

There were some intricate race conditions related to checking whether *futex_addr == val. I used to check this condition in the syscall_futex function **before** locking the futex.lock_. This caused a race condition in testmutex where another thread calls FUTEX_WAKE before the FUTEX_WAIT could hold the lock, leading to missed wakeup.

How can we test your work?

p-testshm tests the basic memory sharing functionality

p-testfutex tests the basic futex functionality using threads

p-testfutex tests the basic futex functionality using processes and shared memory

p-testmutex tests an implementation of a mutex created using futexes. It takes ~20s to run. In the unsynchronized version, the four threads individually try to increment a shared sum value by 1, 100,000 times.
The expected value is 400,000, but the unsynchronized version will not reach 400,000. In the synchronized version, adding to the shared value is locked by a mutex. The first run is unsynchronized, the second run is synchronized. The test succeeds if the second run reaches 400,000 correctly.
