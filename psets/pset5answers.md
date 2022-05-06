CS 161 Problem Set 5 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset5collab.md`.

Answers to written questions
----------------------------

Synchronization plan for the multithreading

I added a new thread group table threadgroup* tgtable[]. This table is guarded by tgtable_lock, similar to the ptable_lock. I currently don't hold tgtable_lock and ptable_lock simultaneously. process_hierarchy lock is always grabbed first if used alongside tgtable_lock.

The threadgroup's pagetable, file descriptor table (fd_table_), and shared memory table (shm_mapping_table_), children & sibling list children_list_, thread_list_ (list of threads in a process).

1. pagetable
To synchronize access to the pagetable. Since adding new mappings to the pagetable are atomic, for most cases there is no special lock for adding a mapping to the pagetable. To synchronize between the memviewer and exit, the memviewer always holds process_hierarchy_lock alongside ptable_lock before analyzing the pagetable.

The only times the kernel unmaps entries from the page table are during fork (in the child process) and process exit (to free the pagetable and the shared memory table shm_mapping_table_). In this case, it's safe to unmap from the pagetable, since the thread that is doing the freeing is guaranteed to be the last thread in the process. In the case of the shared memory table, the thread doing the freeing is guaranteed to be the last thread in the last process with access to a shared memory table

The kernel holds the process_hierarchy lock while unmapping, which protects against race conditions with memviewer.

2. file descriptor table fd_table_
The file descriptor table is locked by the fd_table_lock_ before accessing. 

3. children_list_ & sibling_links
children_list_ is guarded by a global process_hierarchy_lock, same as before


Grading notes
-------------
