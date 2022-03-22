CS 161 Problem Set 3 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset3collab.md`.

Answers to written questions
----------------------------

Part C.
In adding pipe, I removed all the init() functions that file and vnode had, and added constructors instead to clean up the code.

Also, I used to have a file::vfs_close_read() and file::vfs_close_write() separately, but I removed those in favor of a single file::vfs_close().


In the pipe implementation, the write end and read end are separate files with separate instance of the pipe_vnode. Both instances point to the same underlying pipe object. Then I use the file->perm to determine whether each file is the read end or write end. 

The underlying pipe object has pipe::close_read() and pipe::close_write() which are closed when the ref count of the read and write ends become zero.

This also helps enforce the design that a single vnode is only pointed to by one file in the open_file_table.

Part D.
I created a global initfs_lock_ that locks the initfs table. It is locked inside initfs_lookup before looking up a file / creating it. Because we don't have a way to "delete" initfs files, we just need to lock for the race condition where two processes are trying to write (create) to the same slot in the table.

Accessing the table through a table index (returned by initfs_lookup) should not require locking, since it's not possible yet to delete a memfile yet, and there aren't race conditions for read.

No significant changes were made to my VFS design.

Grading notes
-------------
