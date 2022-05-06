CS 161 Problem Set 5 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset5collab.md`.

Answers to written questions
----------------------------

Synchronization plan for the multithreading

The threadgroup's pagetable, file descriptor table, and shared memory table, children_list_, and thread_list_ (list )

1. pagetable
To synchronize access to the pagetable. Since adding new mappings to the pagetable are atomic 

2. file descriptor table fd_table_
The file descriptor table is locked by the fd_table_lock_ before accessing.

3. children_list_ & sibling_links
children_list_ 

Grading notes
-------------
