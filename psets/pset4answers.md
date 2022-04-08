CS 161 Problem Set 4 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset4collab.md`.

Answers to written questions
----------------------------

Eviction plan

I use a basic LRU cache to implement eviction. I keep a eviction_queue_, which contains all elements that are guaranteed to have a zero ref count, and can safely be evicted. Any time a block is loaded while it's on the eviction queue, I remove it from the eviction queue since it was recently accessed. New entries are added to the front, and the potential evictions are taken from the back of the queue.

Prefetching plan

I created a kernel task issue_prefetch_process_fn which runs on boot, and is never killed. The buffer cache has an associated prefetch_queue_ (which is implemented as a bounded buffer), and the kernel task waits on the prefetch_queue_ wait queue. Everytime new blocks to prefetch are added there, it wakes the kernel task, which pops an a task off of the queue and calls a blocking load. However, the user process calling read can call add prefetch items to the queue without blocking, allowing it to not have to wait for the kernel task to finish.

Syncing plan

the dirty_queue_ holds the cache entries that have been modified since the load or the last sync. An bcentry cannot be simultaneously in the eviction_queue_ and the dirty_queue_ (guarded by dirty_queue_lock_). When a block in the eviction queue is written to, it is moved to the dirty_queue_, so that isn't immediately evicted. I added some invariant checks to guarantee this.

Synchronization plan

I have a separate lock for the eviction_queue_ and dirty_queue_, and the locks are always acquired in this specific order to avoid deadlocks.

bufcache::lock => bcentry::lock

bufcache::lock => eviction_queue_lock

bcentry::lock => eviction_queue_lock

bcentry::lock => dirty_queue_lock

bcentry::lock => eviction_queue_lock => dirty_queue_lock


Extra credit:

I created subdirectories with mkdir and rmdir support. They enforce similar policies to unix, like not being able to rmdir until the directory is empty, and not being able to create a directory with mkdir until the previous subdirectories have been created.

Each sub-directory is a separate directory inode, and create a tree-like structure.

 You can test it with p-testdir.

Grading notes
-------------
