CS 161 Problem Set 2 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset2collab.md`.

Answers to written questions
----------------------------

C. Parent processes
In order to support O(C) reparenting, I added a linked list of child process as children_list_ inside the struct proc. I also added a pid_t ppid_ inside the struct proc to keep track of each process' parent.

Currently, I use a global process_hierarchy_lock to guard the children_list_ and ppid_. 

Any read or write access to any proc::children_list_ and proc::ppid_ requires holding the process_hierarchy_lock. Accessing the parent by looking at ptable[ppid_] then also requires the ptable_lock.

Only the parent process (when forking or exiting) or the initial creation function (init_user and init_kernel) can update the ppid_ of a child process.

Once initialized, the ppid_ can only be updated once, when the parent process exits and the child gets reassigned to the init process.

ppid_ and children_list_ must be kept in a consistent state using the process_hierarchy_lock. Specifically, if a proc A has ppid_ = x, ptable[x]->children_lists must contain proc A.

Using the process_hierarchy_lock is slightly better than using the ptable_lock to guard access the ppid_ and children_list_, as most of the logic in waitpid does not require access to the ptable_lock.

F. True blocking

For testmsleep, non-blocking code called resume about 339470 times, while the blocking code called resume about 38 times.

I tested for different sized timing-wheels. 
With 16 wait queues, the resume count was 109
With 32 wait queues, the resume count was 79
With 64 wait queues, the resume count was 59
With 128 wait queues, the resume count was 49

This is an expected result, as less waiting processes are woken up when there are more wait queues.

For testzombie, non-blocking code called resume about 1194 times, while the blocking code called resume about 487 times.

Grading notes
-------------
