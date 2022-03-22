CS 161 Problem Set 3 VFS Design Document
========================================

```
class file {
  // TODO: add index inside open file table
 public:
  int id_; // index on global open file table
  int ref_count_;
  spinlock ref_count_lock_;
  vnode* vnode_; // Only public so the memviewer can access it and mark it
  file(vnode* node, int perm);
  ssize_t vfs_read(char* buf, size_t sz);
  ssize_t vfs_write(char* buf, size_t sz);
  void vfs_close();
 private:
  int perm_;
  size_t offset_;
};

class vnode {
 public:
  virtual ssize_t read(char* buf, size_t sz, size_t offset);
  virtual ssize_t write(char* buf, size_t sz, size_t offset);
  virtual void close();
};

```

Two main objects, `class vnode` and `class file`, make up my VFS layer. 

`file` is the high level abstraction for open files. It holds data agnostic to the underlying vnode_. Currently, a vnode only needs to expose three methods: read, write, close.

As a design decision, a vnode is only pointed to by one open file in the open file table. This makes it a bit easier to rely on the file ref_count_ to decide when to free the file.

The system-wide open file table is called `file* open_file_table[]`. I added a `spinlock open_file_table_lock` to guard the `file* open_file_table[]`. This lock is used every time code tries to index into the table (for read), and when the slots are being updated (new file is being added). It shouldn't require a lock when using vfs_write or vfs_read because the ref_count_.

Inside each struct proc, there is a file descriptor table file* fd_table_[], where each element is either a null pointer, or a file* pointer to an open file in the open_file_table.


On vnode & file creation
1. Kernel creates the appropriate vnode by using kalloc (knew<vnode>())
2. Kernel then creates a file object by using kalloc (knew<vnode>())
3. We pass the newly created vnode into knew<file>(vnode* node_), which initializes the file with refcount_ = 1;
4. We then add the file into open_file table, then add it to the process' file descriptor table if necessary

On freeing
1. when a process calls close on a fd
2. the process removes the file from the fd_table_
3. then file::ref_count is subtracted by 1
4. When the file::ref_count_ reaches 0
5. the file is removed from the open_file_table
6. the underlying file->vnode_->close() is called, and the vnode has can run whatever clean up code is necessary
7. then vnode_ is freed using kfree
8. then the file itself is freed

In terms of synchronization invariants, the ref_count_lock_ inside file protects the ref_count_ variable. When the decrementing the ref_count_ to 0 and freeing the file must happen atomically. Hence, the ref_count_lock_ is held when decrementing (and maybe also freeing) or incrementing the ref_count_.

In order to reduce deadlocks, I try to hold open_file_table_lock before holding ref_count_lock_ if both are needed.

However, there is no need for holding the ref_count_lock when calling vfs_read or vfs_write, since it is guaranteed that the ref_count_ will be at least 1, since the process calling vfs_read or vfs_write still has a reference to the file object.

There are no locks implemented at the vnode abstraction level either, although the child implementations of vnodes may contain a lock. For instance, pipe_vnode contains a struct pipe, which contains a lock inside.

vfs_write() and vfs_read() may block, but only if the underlying vnode implementation blocks. For instance, pipe_vnode blocks when there is nothing to read yet. However, the file object doesn't know the underlying implementation of the vnodes, so it doesn't know if it blocks or not.

vfs_write() and vfs_read() updates the offset_ at the file abstraction layer, then passes the current offset when calling the underlying vnode's read and write functions

Right now there is no multithreading for a single process, but if there were, we need to make sure that there are no race conditions when accessing a file inside the fd_table_. For instance, if two threads in a single process accesses the fd_table_[4] simultaneously, and thread 1 tries to close while thread 2 tries to write, the behavior is undefined. We need to add a lock to each of the file descriptors inside fd_table_ per process, that is locked while one thread is trying to use a file descriptor. ie) we can add `spinlock fd_locks_[N_FILE_DESCRIPTORS]` to the table.