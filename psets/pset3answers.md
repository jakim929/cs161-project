CS 161 Problem Set 3 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset3collab.md`.

Answers to written questions
----------------------------


I created a global initfs_lock_ that locks the initfs table. It is locked inside initfs_lookup before looking up a file / creating it. Because we don't have a way to "delete" initfs files, we just need to lock for the race condition where two processes are trying to write (create) to the same slot in the table.

Accessing the table through a table index (returned by initfs_lookup) should not require locking, since it's not possible yet to delete a memfile yet, and there aren't race conditions for read.

Grading notes
-------------
